/**
 * dsh-qoder-connect —— 把 Qoder CN（阿里 Qoder 国内版桌面 App）订阅里的模型接入
 * DeepSeek Harness。
 *
 * ## 它为什么长这样
 *
 * Qoder CN 的桌面 App **自己不实现 agent 循环**——它 spawn 一个内嵌的
 * Claude Code 式 worker（`@qoder-ai/qoder-cn-agent-sdk` 的
 * `qoder-worker-runtime.obf.mjs`，启动参数 `--print --output-format stream-json
 * --model qmodel_38max ...`）。App 只负责登录并把短期 `jobToken` 交给它。
 *
 * 所以「接模型」的正路不是去啃 App 的加密凭据（`auth.v1.dat` 是 Electron
 * safeStorage 密文，要弹钥匙串授权），而是走官方自建 **PAT**：
 *
 *   PAT(pt-…) ──exchange──▶ jobToken(jt-…, 短期) ──COSY 签名──▶ gateway.qoder.com.cn
 *
 * PAT 在 <https://qoder.com.cn/account/integrations> 自建，是官方支持的通道。
 *
 * ## 协议的三层坑（都已在 SDK 里核对过）
 *
 * 1. **鉴权不是 `Bearer <token>`**，是 Qoder 自研的 COSY 签名：
 *      aesKey     = 随机 16 字符
 *      info       = AES-128-CBC(JSON({uid,security_oauth_token,name,aid,email}), key=iv=aesKey) → base64
 *      cosyKey    = RSA_PKCS1(aesKey, 内置公钥) → base64
 *      payloadB64 = base64(JSON({version:"v1", requestId, info, cosyVersion, ideVersion:""}))
 *      sig        = md5(payloadB64 \n cosyKey \n 秒级时间戳 \n bodyBytes \n sigPath)
 *      Authorization: Bearer COSY.<payloadB64>.<sig>
 *    外加一整组 `Cosy-*` 头。**`sigPath` 是 pathname 去掉前导 `/algo`，且不含 query。**
 *
 * 2. **请求体多一层自定义编码**（URL 上的 `Encode=1`）：先标准 base64，再按 Qoder
 *    自定义字母表重映射（`=` → `$`），最后做三段块旋转 `[n-a,n) [a,n-a) [0,a)`，
 *    `a = floor(n/3)`。见 {@link qoderEncodeBody}。
 *
 * 3. **响应是双层 SSE**：外层 `data: {"statusCodeValue":200,"body":"<JSON 字符串>"}`，
 *    内层才是 OpenAI 形状的 `choices[0].delta`。控制哨兵还有 `[DONE]`、
 *    `[NOT_EXCEED_QUOTA]`、`[EXCEED_QUOTA]…`、`[NOTIFICATIONS]…`。
 *
 * ## 数据流
 *
 *   DSH ──OpenAI──▶ 本插件的回环 shim ──Qoder 双层 SSE──▶ gateway.qoder.com.cn
 *
 * shim 与 `dsh-workbuddy-connect` / `dsh-trae-connect` 同构：127.0.0.1 随机端口 +
 * 32 字节随机 bearer，只服务 `/healthz`、`/v1/models`、`/v1/chat/completions`。
 *
 * ## 两个平面的区别（别混）
 *
 *   · 推理平面  `gateway.qoder.com.cn/algo/**`   —— COSY 签名，`Encode=1` 请求体
 *   · OpenAPI 平面 `openapi.qoder.com.cn/**`     —— 普通 `Bearer <jobToken>` + `Cosy-ClientType`
 *
 * 额度与「签到活动」走的都是 OpenAPI 平面（App 自己就是这么打的），所以那边不需要
 * 签名，只需要一个有效 jobToken。
 *
 * ## 凭据
 *
 * 读宿主侧 `$DSH_HOME/qoder/pat`（0600；`~/.dsh` 已 bind mount 成容器里的 `/root/.dsh`），
 * 或环境变量 `QODERCN_PAT` / `QODERCN_PERSONAL_ACCESS_TOKEN` / `QODERCN_API_KEY`。
 * 插件只读明文 PAT，绝不碰 App 的目录。PAT 过期不会自动续——Qoder 官方明确
 * 「The SDK does not refresh PATs」，重新生成一个即可（jobToken 那层本插件自己刷）。
 *
 * @module dsh-qoder-connect
 */

import z from "@deepseek-ai/schemastery";
import { createCipheriv, createHash, publicEncrypt, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { createProvider } from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { PiAiAdapter } from "@deepseek-ai/dsh-llm-pi-ai";
import { resolveRetryPolicy } from "@deepseek-ai/dsh-llm";
import { resolveDshHome } from "@deepseek-ai/dsh-home-paths";
import { briefMessage, hostIsLoopback, loopbackRequest, originIsLoopback, writeJson } from "../../shared/http.js";

//#region 常量

/** Cordis 插件名。必须与 cordis.patch.yml 里的 `id` 一致。 */
export const name = "llm-qoder";
/** 注册 provider 之前必须先拿到模型注册表。 */
export const inject = ["llm"];

/** DSH 里对用户展示的 provider id，也是模型选择器上那一组的名字（= 渠道名）。 */
const QODER_PROVIDER = "qoder1";
const QODER_DISPLAY_NAME = "Qoder CN";

/** 推理平面（COSY 签名 + `Encode=1`）。 */
const DEFAULT_GATEWAY = "https://gateway.qoder.com.cn";
/** OpenAPI 平面（普通 Bearer）：userinfo / 额度 / 签到活动。 */
const DEFAULT_OPENAPI = "https://openapi.qoder.com.cn";

/** PAT → jobToken。**不需要签名**，也不带 Encode。 */
const PATH_EXCHANGE = "/api/v1/jobToken/exchange";
const PATH_USERINFO = "/api/v1/userinfo";
/** 额度：参考实现那条路（COSY 签名）。 */
const PATH_QUOTA_LEGACY = "/api/v2/quota/usage";
/** 额度：**App 自己**打的那条（OpenAPI 平面 + 普通 Bearer），字段更全。 */
const PATH_ACCOUNT_USAGE = "/sash/api/v2/me/usage";
/** 「签到活动」状态：App 的 CampaignMainService 就是打这个。 */
const PATH_CAMPAIGNS = "/sash/api/v1/me/campaigns";
/** 模型目录。`Encode=1` 只约束请求体，GET 的响应是明文 JSON。 */
/**
 * [dsh-connect 2026-09-24 修正] 网关的模型目录在 **`/algo` 前缀**下。
 *
 * 实测：`/algo/api/v2/model/list?Encode=1` → 200（70KB 完整目录）；
 * 而少了 `/algo` 的老路径会被 ALB 挡成 **HTTP 503 Service Temporarily Unavailable**
 * （不是鉴权问题，所以很容易误判成"token 不对"）。同网关的 chat 路径本来就带 `/algo`，
 * 这条是唯一漏了前缀的。
 */
const PATH_MODELS = "/algo/api/v2/model/list?Encode=1";
/** 对话。CN 渠道的 agent 入口（pathname 部分；签名只覆盖它，不含 query）。 */
const PATH_CHAT = "/algo/api/v2/service/pro/sse/agent_chat_generation";
/**
 * 对话的完整路径 + 查询串。
 *
 * `Encode=1` 必须有（插件的请求体是编码过的）；`FetchKeys` / `AgentId` 是从
 * 社区 MIT 实现 `pi-provider-qoder` 抄来的，SDK 里的常量只有裸 pathname
 * （查询串由它的 wasm `prepareRequest` 补）。保险起见整串可配置：万一哪天服务端
 * 不认这两个参数，改配置即可，不用改代码。多带的查询参数一般会被忽略，
 * 而漏掉 `Encode=1` 是致命的，所以默认按「全带上」。
 */
const DEFAULT_CHAT_PATH = `${PATH_CHAT}?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1`;
/** CN 客户端身份。SDK 里 `Ji ? "qoderclicn" : "qodercli"`，CN 走前者。 */
const DEFAULT_SESSION_TYPE = "qoderclicn";

//#endregion
//#region COSY 客户端身份常量

/**
 * COSY 内置 RSA 公钥（用来加密临时的 aesKey）。
 * 与 Qoder CLI 同一份；换 key 只会在服务端轮换时发生。
 */
const QODER_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`;

/**
 * 客户端身份版本号。
 *
 * ⚠️ 这是**硬编码契约**：`Cosy-Version` 落后于 Qoder CLI 当前版本时，服务端会
 * 返回被裁剪过的模型列表（本地实测：CLI 1.1.61 对应 1.1.38 可用）。
 * 随 CLI 升级要复核这里。
 */
const COSY_VERSION = "1.1.38";
/** OpenAPI 平面用的是另一条版本线。 */
const COSY_OPENAPI_VERSION = "1.0.1";
/** App 的 clientType（SDK 里的 `Mh.clientType`）。 */
const COSY_CLIENT_TYPE = "5";
const COSY_DATA_POLICY = "disagree";

//#endregion
//#region Encode=1（Qoder 自定义 base64）

/** 自定义字母表：第 i 个字符替代标准 base64 的第 i 个字符。 */
const CUSTOM_ALPHABET = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const ENC_TABLE = new Uint8Array(256);
const DEC_TABLE = new Uint8Array(256);
for (let i = 0; i < 256; i += 1) {
  ENC_TABLE[i] = i;
  DEC_TABLE[i] = i;
}
for (let i = 0; i < 64; i += 1) {
  ENC_TABLE[STD_ALPHABET.charCodeAt(i)] = CUSTOM_ALPHABET.charCodeAt(i);
  DEC_TABLE[CUSTOM_ALPHABET.charCodeAt(i)] = STD_ALPHABET.charCodeAt(i);
}
// Qoder 用 `$` 代替标准 base64 的 `=`。
ENC_TABLE["=".charCodeAt(0)] = "$".charCodeAt(0);
DEC_TABLE["$".charCodeAt(0)] = "=".charCodeAt(0);

/**
 * 请求体编码：标准 base64 → 字母表重映射 → 三段块旋转。
 *
 *   标准串 std[0,n)，a = floor(n/3)
 *   密文 = map(std[n-a, n)) + map(std[a, n-a)) + map(std[0, a))
 *
 * 返回 Buffer 直接当请求体用。
 */
export function qoderEncodeBody(plain) {
  const std = Buffer.isBuffer(plain) ? plain.toString("base64") : Buffer.from(plain, "utf8").toString("base64");
  const n = std.length;
  const a = Math.floor(n / 3);
  const out = Buffer.allocUnsafe(n);
  let dst = 0;
  for (let i = n - a; i < n; i += 1) out[dst++] = ENC_TABLE[std.charCodeAt(i)];
  for (let i = a; i < n - a; i += 1) out[dst++] = ENC_TABLE[std.charCodeAt(i)];
  for (let i = 0; i < a; i += 1) out[dst++] = ENC_TABLE[std.charCodeAt(i)];
  return out;
}

/** {@link qoderEncodeBody} 的逆。线上响应不需要解，只给自检用。 */
export function qoderDecodeBody(encoded) {
  const e = Buffer.isBuffer(encoded) ? encoded.toString("latin1") : String(encoded);
  const n = e.length;
  const a = Math.floor(n / 3);
  const m = n - 2 * a;
  const std = Buffer.allocUnsafe(n);
  const put = (chars, at) => {
    for (let i = 0; i < chars.length; i += 1) std[at + i] = DEC_TABLE[chars.charCodeAt(i)];
  };
  put(e.slice(0, a), n - a);
  put(e.slice(a, a + m), a);
  put(e.slice(a + m, n), 0);
  return Buffer.from(std.toString("latin1"), "base64");
}

//#endregion
//#region COSY 鉴权头

const md5 = (bytes) => createHash("md5").update(bytes).digest("hex");

/**
 * 签名只覆盖 pathname 去掉前导 `/algo`，**不含 query**。
 *
 * 例：`/algo/api/v2/model/list?Encode=1` → `/api/v2/model/list`。
 * 这一点错了会拿到 401 而不是 404，很容易误判成 token 失效。
 */
export function sigPathOf(url) {
  const p = new URL(url).pathname;
  return p.startsWith("/algo") ? p.slice("/algo".length) : p;
}

/** 机器码：优先用 Qoder 已落盘的那份，保证跨次稳定（否则服务端会当成新设备）。 */
export function resolveMachineId() {
  const candidates = [
    process.env.QODERCN_MACHINE_ID,
    join(homedir(), ".qoder-cn", ".auth", "machine_id"),
    join(homedir(), ".qoder", ".auth", "machine_id"),
  ].filter((p) => typeof p === "string" && p.length > 0);
  for (const path of candidates) {
    try {
      const value = readFileSync(path, "utf8").trim();
      if (value.length > 0) return value;
    } catch { /* 继续找下一个 */ }
  }
  const fallback = join(resolveDshHome(), "qoder", "machine-id");
  try {
    const value = readFileSync(fallback, "utf8").trim();
    if (value.length > 0) return value;
  } catch { /* 下面生成 */ }
  const generated = randomUUID();
  try {
    mkdirSync(dirname(fallback), { recursive: true });
    writeFileSync(fallback, `${generated}\n`, { mode: 0o600 });
  } catch { /* 只读环境就算了，本次进程内仍然一致 */ }
  return generated;
}

/** 平台串。SDK 会按 arch/os 拼，这里照抄。 */
function machineOs() {
  if (process.platform === "win32") return process.arch === "arm64" ? "aarch64_windows" : "x86_64_windows";
  if (process.platform === "darwin") return process.arch === "arm64" ? "aarch64_darwin" : "x86_64_darwin";
  return process.arch === "arm64" ? "aarch64_linux" : "x86_64_linux";
}

/**
 * 生成 `Authorization: Bearer COSY.<payloadB64>.<sig>` 及其配套 `Cosy-*` 头。
 *
 * `body` 必须是**最终要发出去的字节**（即已经过 {@link qoderEncodeBody} 的那份），
 * 因为签名和 `Cosy-Bodyhash` / `Cosy-Bodylength` 都覆盖它。
 */
export function buildCosyHeaders(body, requestUrl, creds) {
  if (typeof creds?.userID !== "string" || creds.userID.length === 0) throw new Error("cosy: userID 为空");
  /**
   * [dsh-connect 2026-09-24 修正] token 的字段名有两套：
   * token-manager 产出的凭据对象用 `jobToken`，而 userinfo 那一步是显式传 `authToken`。
   * 之前只认 `authToken` → 目录刷新每次都抛「cosy: authToken 为空」，
   * 表现成"已登录但模型永远只有兜底那一个"。两者都认即可。
   */
  const authToken = typeof creds?.authToken === "string" && creds.authToken !== "" ? creds.authToken : creds?.jobToken;
  if (typeof authToken !== "string" || authToken.length === 0) throw new Error("cosy: authToken 为空");

  const aesKey = randomUUID().replace(/-/g, "").slice(0, 16);
  const userInfo = {
    uid: creds.userID,
    security_oauth_token: authToken,
    name: creds.name ?? "",
    aid: "",
    email: creds.email ?? "",
  };
  const cipher = createCipheriv("aes-128-cbc", Buffer.from(aesKey), Buffer.from(aesKey));
  const infoB64 = cipher.update(JSON.stringify(userInfo), "utf8", "base64") + cipher.final("base64");
  const cosyKey = publicEncrypt(
    { key: QODER_RSA_PUBLIC_KEY, padding: 1 /* RSA_PKCS1_PADDING */ },
    Buffer.from(aesKey),
  ).toString("base64");

  const ts = String(Math.floor(Date.now() / 1000));
  const payloadB64 = Buffer.from(JSON.stringify({
    version: "v1",
    requestId: randomUUID(),
    info: infoB64,
    cosyVersion: COSY_VERSION,
    ideVersion: "",
  })).toString("base64");

  const bodyBytes = body === undefined || body === null
    ? Buffer.alloc(0)
    : (Buffer.isBuffer(body) ? body : Buffer.from(body));
  const sig = createHash("md5")
    .update(payloadB64).update("\n")
    .update(cosyKey).update("\n")
    .update(ts).update("\n")
    .update(bodyBytes).update("\n")
    .update(sigPathOf(requestUrl))
    .digest("hex");

  const machineId = creds.machineID ?? resolveMachineId();
  return {
    Authorization: `Bearer COSY.${payloadB64}.${sig}`,
    "Cosy-Key": cosyKey,
    "Cosy-User": creds.userID,
    "Cosy-Date": ts,
    "Cosy-Version": COSY_VERSION,
    "Cosy-Machineid": machineId,
    "Cosy-Machinetoken": machineId,
    "Cosy-Machinetype": "5",
    "Cosy-Machineos": machineOs(),
    "Cosy-Clienttype": COSY_CLIENT_TYPE,
    "Cosy-Clientip": "127.0.0.1",
    "Cosy-Bodyhash": md5(bodyBytes),
    "Cosy-Bodylength": String(bodyBytes.length),
    "Cosy-Sigpath": sigPathOf(requestUrl),
    "Cosy-Data-Policy": COSY_DATA_POLICY,
    "Cosy-Organization-Id": "",
    "Cosy-Organization-Tags": "",
    "Login-Version": "v2",
    "X-Request-Id": randomUUID(),
  };
}

//#endregion
//#region 配置

const PAT_FILE_FIELD = z.string().description("Qoder PAT 明文文件（默认 $DSH_HOME/qoder/pat）");
const GATEWAY_FIELD = z.string().description("Qoder 推理网关（默认 https://gateway.qoder.com.cn）");
const OPENAPI_FIELD = z.string().description("Qoder OpenAPI 网关（额度/签到；默认 https://openapi.qoder.com.cn）");
const CHAT_PATH_FIELD = z.string().description("对话路径与查询串（默认 /algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1）");
const SESSION_TYPE_FIELD = z.string().description("session_type 取值（CN 客户端是 qoderclicn；国际版 qodercli）");
const POLL_FIELD = z.number().description("凭据/目录巡检间隔（毫秒）");

export const Config = z.object({
  patFile: PAT_FILE_FIELD,
  gateway: GATEWAY_FIELD,
  openapiBase: OPENAPI_FIELD,
  chatPath: CHAT_PATH_FIELD,
  sessionType: SESSION_TYPE_FIELD,
  pollIntervalMs: POLL_FIELD,
});

/**
 * 解析路径默认值 —— 必须在 DSH_HOME 可用之后才能求值。
 *
 * [2026-09-25] 认证统一收进 `$DSH_HOME/connect-auth/`（见 trae 那边的同一条说明）：
 * PAT 与 App 会话都放这里，迁移只需搬一个目录。旧路径仍可用 `patFile` / `sessionFile`
 * 配置项指回。
 */
function defaultPatPath() {
  return join(resolveDshHome(), "connect-auth", "qoder.pat");
}

//#endregion
//#region 凭据（PAT）

/**
 * PAT 读取器。
 *
 * 每次 `resolve()` 都重新读盘 + 重新读环境变量，所以宿主侧换 PAT 之后**不用重启
 * DSH** 就能生效（与 WorkBuddy / Trae 两条路一致）。
 */
/**
 * [dsh-connect] App 会话凭据：读宿主导出的 Qoder CN 桌面 App 登录态。
 *
 * 为什么要它：官方 PAT 要在网页上手工自建，而 App 本来就已经登录好了。
 * 实测 App 的会话 token（`dt-` 前缀）在 **两个平面都是有效的 Bearer** ——
 * OpenAPI（userinfo/额度/签到）与推理（COSY 头里带的就是它），
 * 所以不需要 PAT 交换，uid 也直接来自会话（不必再问 userinfo）。
 *
 * 文件由宿主脚本 `scripts/qoder-vault.mjs --install-session` 写出（Electron safeStorage 解密）：
 *   $DSH_HOME/connect-auth/qoder-session.json   {token, refreshToken, expiresAt, uid, name, email}
 *
 * 读不到 / 过期 / 格式不对，一律返回 undefined，调用方回落到 PAT。
 */
export function createSessionStore(options) {
  const { config } = options;
  const explicitPath = () => {
    const value = config()?.sessionFile;
    return typeof value === "string" && value.length > 0 ? value : join(resolveDshHome(), "connect-auth", "qoder-session.json");
  };

  return {
    path: explicitPath,
    /** 当前可用的会话凭据；不可用时 undefined（不抛，因为 PAT 还能兜底）。 */
    async current() {
      const path = explicitPath();
      if (!existsSync(path)) return undefined;
      let doc;
      try {
        doc = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        return undefined;
      }
      const token = typeof doc?.token === "string" ? doc.token.trim() : "";
      const uid = typeof doc?.uid === "string" ? doc.uid.trim() : "";
      if (token === "" || uid === "") return undefined;
      // 过期就用不了（App 会自己续；续完重跑导出脚本即可）
      const expiresAt = resolveExpiry({ expires_at: doc?.expiresAt, expiresAt: doc?.expiresAt }) ?? 0;
      if (expiresAt !== 0 && expiresAt - JOB_TOKEN_SKEW_MS <= Date.now()) return undefined;
      return {
        token,
        uid,
        name: typeof doc?.name === "string" ? doc.name : "",
        email: typeof doc?.email === "string" ? doc.email : "",
        expiresAt: expiresAt === 0 ? Date.now() + ASSUMED_JOB_TOKEN_TTL_MS : expiresAt,
        source: path,
      };
    },
  };
}

export function createPatStore(options) {
  const { config } = options;
  const explicitPath = () => {
    const value = config()?.patFile;
    return typeof value === "string" && value.length > 0 ? value : defaultPatPath();
  };

  const fromEnv = () => {
    for (const key of ["QODERCN_PAT", "QODERCN_PERSONAL_ACCESS_TOKEN", "QODERCN_API_KEY"]) {
      const value = process.env[key];
      if (typeof value === "string" && value.trim().length > 0) return { pat: value.trim(), source: key };
    }
    return undefined;
  };

  const fromFile = () => {
    const path = explicitPath();
    if (!existsSync(path)) return undefined;
    try {
      const value = readFileSync(path, "utf8").trim();
      return value.length > 0 ? { pat: value, source: path } : undefined;
    } catch {
      return undefined;
    }
  };

  return {
    path: explicitPath,
    /**
     * 取 PAT。读不到就抛，由调用方降级成「未登录」。
     *
     * 环境变量优先于文件：便于临时用另一个账号跑一次而不动落盘的凭据。
     */
    async resolve() {
      const found = fromEnv() ?? fromFile();
      if (found === undefined) {
        throw new Error(`未配置 Qoder PAT：既没有 QODERCN_PAT/QODERCN_PERSONAL_ACCESS_TOKEN/QODERCN_API_KEY，也读不到 ${explicitPath()}。请到 https://qoder.com.cn/account/integrations 建一个 pt- 开头的 PAT。`);
      }
      if (!found.pat.startsWith("pt-")) {
        throw new Error(`${found.source} 里的令牌不是 pt- 前缀，Qoder 的 PAT 形如 pt-xxxxxxxx。`);
      }
      return found;
    },
    async current() {
      try {
        return await this.resolve();
      } catch {
        return undefined;
      }
    },
  };
}

//#endregion
//#region jobToken 管理

/** 换来的 jobToken 还剩不到这个时长就提前重换一次。 */
const JOB_TOKEN_SKEW_MS = 120000;

/**
 * `expires_at` 在 Qoder 的返回里可能是 ISO 串、秒级数字或毫秒级数字；
 * `expires_in` 可能是秒也可能是毫秒。全部宽容处理，读不出来就返回 undefined
 * （调用方按「保守 30 分钟」处理）。
 */
export function resolveExpiry(doc) {
  const at = doc?.expires_at;
  if (typeof at === "string") {
    const parsed = Date.parse(at);
    if (Number.isFinite(parsed)) return parsed;
  }
  if (typeof at === "number" && Number.isFinite(at)) return at < 1e12 ? at * 1000 : at;
  const inSecondsOrMs = doc?.expires_in;
  if (typeof inSecondsOrMs === "number" && Number.isFinite(inSecondsOrMs) && inSecondsOrMs > 0) {
    return Date.now() + (inSecondsOrMs < 1e6 ? inSecondsOrMs * 1000 : inSecondsOrMs);
  }
  return undefined;
}

/** 保守兜底：拿不到有效期时按 30 分钟算。 */
const ASSUMED_JOB_TOKEN_TTL_MS = 1800000;

/**
 * PAT → jobToken 的管理器。
 *
 * 一次成功的交换缓存起来；并发调用只会打一次上游（single-flight）。
 * jobToken 过期就重新用 PAT 换 —— PAT 本身不会过期（除非用户在网页上吊销）。
 */
export function createTokenManager(options) {
  const { pats, sessions, logger, config } = options;
  const openapiBase = () => String(config()?.openapiBase ?? DEFAULT_OPENAPI).replace(/\/+$/, "");

  /** @type {{ jobToken: string, expiresAt: number, userID: string, name: string, email: string, machineID: string, source: string }|undefined} */
  let cached;
  /** @type {Promise<unknown>|undefined} */
  let inflight;

  /** PAT 交换。不需要签名，也不带 Encode —— 这是唯一一条「裸」请求。 */
  async function exchange(pat) {
    const url = `${openapiBase()}${PATH_EXCHANGE}`;
    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "dsh-qoder-connect",
          "Cosy-Version": COSY_OPENAPI_VERSION,
          "Cosy-ClientType": COSY_CLIENT_TYPE,
        },
        body: JSON.stringify({ personal_token: pat }),
        signal: AbortSignal.timeout(20000),
      });
    } catch (error) {
      throw new Error(`连不上 Qoder OpenAPI（${openapiBase()}）：${error instanceof Error ? error.message : String(error)}`);
    }
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      const brief = text.replace(/\s+/g, " ").slice(0, 200);
      if (response.status === 401 || response.status === 403) {
        throw new Error(`PAT 被拒绝（HTTP ${response.status}）：可能已吊销或填错。${brief}`);
      }
      throw new Error(`PAT 交换失败（HTTP ${response.status}）：${brief}`);
    }
    let doc;
    try {
      doc = JSON.parse(text);
    } catch {
      throw new Error(`PAT 交换返回的不是 JSON：${text.slice(0, 200)}`);
    }
    const jobToken = typeof doc?.token === "string" ? doc.token.trim() : "";
    if (jobToken.length === 0) throw new Error(`PAT 交换没有返回 token：${text.slice(0, 200)}`);
    return {
      jobToken,
      refreshToken: typeof doc?.refresh_token === "string" ? doc.refresh_token : "",
      expiresAt: resolveExpiry(doc) ?? (Date.now() + ASSUMED_JOB_TOKEN_TTL_MS),
    };
  }

  /** userinfo：补上 COSY 签名需要的 uid/name/email。 */
  async function fetchUserInfo(creds) {
    const url = `${openapiBase()}${PATH_USERINFO}`;
    const response = await fetch(url, {
      headers: { ...buildCosyHeaders(null, url, creds), Accept: "application/json", "User-Agent": "dsh-qoder-connect" },
      signal: AbortSignal.timeout(20000),
    });
    if (!response.ok) {
      throw new Error(`userinfo 返回 HTTP ${response.status}：${(await response.text().catch(() => "")).slice(0, 200)}`);
    }
    const doc = await response.json().catch(() => undefined);
    return {
      userID: typeof doc?.id === "string" ? doc.id : "",
      email: typeof doc?.email === "string" ? doc.email : "",
      name: typeof doc?.name === "string" ? doc.name : (typeof doc?.username === "string" ? doc.username : ""),
    };
  }

  async function refresh() {
    const machineID = resolveMachineId();

    // —— 优先用 App 会话：不需要 PAT、不需要 userinfo 往返 ——
    // 实测 App 的会话 token 在两个平面都有效（OpenAPI 200；推理平面 COSY 头里用的就是它）。
    if (sessions !== undefined) {
      const session = await sessions.current().catch(() => undefined);
      if (session !== undefined) {
        cached = {
          jobToken: session.token,
          expiresAt: session.expiresAt,
          userID: session.uid,
          name: session.name,
          email: session.email,
          machineID,
          source: session.source,
        };
        logger?.debug?.(`dsh-qoder-connect: 使用 App 会话凭据（uid=${cached.userID}，有效期至 ${new Date(cached.expiresAt).toISOString()}）`);
        return cached;
      }
    }

    const { pat, source } = await pats.resolve();
    const exchanged = await exchange(pat);

    // userinfo 要 uid 才能签，而 uid 又要拿 jobToken 去问 —— 先要一次再补全。
    const identity = await fetchUserInfo({ userID: "", authToken: exchanged.jobToken, machineID }).catch(async (error) => {
      logger?.warn(`dsh-qoder-connect: userinfo 读取失败（额度与签到会缺账号名，推理不受影响）：${error instanceof Error ? error.message : String(error)}`);
      return { userID: "", email: "", name: "" };
    });
    if (identity.userID === "") {
      // uid 拿不到就签不出 COSY，等于不能用。
      throw new Error("Qoder userinfo 没有返回用户 id，无法生成 COSY 签名（PAT 可能已失效）。");
    }

    cached = {
      jobToken: exchanged.jobToken,
      expiresAt: exchanged.expiresAt,
      userID: identity.userID,
      name: identity.name,
      email: identity.email,
      machineID,
      source,
    };
    logger?.debug?.(`dsh-qoder-connect: jobToken 已刷新（uid=${cached.userID}，有效期至 ${new Date(cached.expiresAt).toISOString()}）`);
    return cached;
  }

  return {
    /** 拿一份当前可用的凭据；过期或缺失就重换。 */
    async get() {
      if (cached !== undefined && cached.expiresAt - JOB_TOKEN_SKEW_MS > Date.now()) return cached;
      if (inflight === undefined) {
        inflight = refresh().finally(() => { inflight = undefined; });
      }
      return inflight;
    },
    /** 只读快照，不触发刷新；状态路由用它避免每次打开面板都打上游。 */
    peek() {
      return cached;
    },
    /** 强制重换（PAT 在网页上被吊销后，用户改了 pat 文件等场景）。 */
    invalidate() {
      cached = undefined;
    },
  };
}

//#endregion
//#region 模型目录

/**
 * 拿不到目录时的兜底名单。
 *
 * **只放确认存在的 key。** 目录是懒加载的（要先有可用 jobToken），在第一次成功
 * 拉取之前模型组得有东西，否则 DSH 会按「模型组为空」把它整个隐藏掉。
 *
 * `qmodel_38max` 是从本机 Qoder CN 的运行清单里读到的真实 key
 * （`~/.qoder-cn/logs/runs/&lt;run_id&gt;/manifest.json` 的 `--model` 参数）；
 * 其余模型一律等网关目录返回，不猜名字。
 */
export const FALLBACK_QODER_MODELS = [
  { id: "qmodel_38max", name: "Qwen3.8-Max", contextWindow: 200000, maxTokens: 32000, supportsImages: false, isReasoning: false, isFree: false, rate: undefined },
];

/** 宽松取数：数字或数字串都认（SDK 的 `oci()` 就是这么写的）。 */
function toNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

/** 宽松取布尔（SDK 的 `aci()`）。 */
function toBoolean(value) {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === "1") return true;
  if (value === 0 || value === "0") return false;
  return undefined;
}

/** 目录最大可用的上下文窗口：优先 `context_config` 里最大的 token_count。 */
function contextWindowOf(entry) {
  const config = entry?.context_config;
  if (config !== null && typeof config === "object" && !Array.isArray(config)) {
    let best;
    for (const window of Object.values(config)) {
      const count = toNumber(window?.token_count);
      if (count !== undefined && (best === undefined || count > best)) best = count;
    }
    if (best !== undefined) return best;
  }
  const maxInput = toNumber(entry?.max_input_tokens ?? entry?.maxInputTokens);
  if (maxInput !== undefined && maxInput > 0) return maxInput;
  return undefined;
}

/**
 * 把网关的 `chat[]` 条目归一化成本插件内部形状。
 *
 * 字段名以 `@qoder-ai/qoder-cn-agent-sdk` 的 `sci()` 为准（那里是 camelCase 与
 * snake_case 都认）——**倍率就是 `price_factor`**，界面上按 `<n>×` 显示。
 */
export function normalizeCatalogEntry(raw) {
  const key = String(raw?.key ?? raw?.model_key ?? "").trim();
  if (key.length === 0) return undefined;
  const enabled = raw?.enable === undefined ? true : (toBoolean(raw.enable) ?? true);
  const rate = toNumber(raw?.price_factor ?? raw?.priceFactor);
  const free = toBoolean(raw?.is_free ?? raw?.isFree) ?? (rate === 0);
  return {
    id: key,
    name: String(raw?.display_name ?? raw?.name ?? key) || key,
    contextWindow: contextWindowOf(raw),
    maxTokens: toNumber(raw?.max_output_tokens) ?? 32000,
    supportsImages: toBoolean(raw?.is_vl) === true,
    isReasoning: toBoolean(raw?.is_reasoning) === true,
    isFree: free,
    rate,
    originalRate: toNumber(raw?.original_price_factor ?? raw?.originPriceFactor),
    promotion: raw?.promotion !== null && typeof raw?.promotion === "object" ? raw.promotion : undefined,
    source: typeof raw?.source === "string" ? raw.source : "system",
    outerProvider: typeof raw?.outer_provider === "string" ? raw.outer_provider : undefined,
    enabled,
  };
}

/**
 * 模型目录。
 *
 * 与 WorkBuddy / Trae 两条路不同，Qoder 的目录是**懒加载 + 快照兜底**：
 * 只有拿到可用 jobToken 才会去拉一次，拉到就缓存；失败保留上一次的结果（或者
 * 兜底名单），绝不让「目录暂时不可用」升级成「渠道消失」。
 */
export function createCatalog(options) {
  const { tokens, logger, config } = options;
  const gateway = () => String(config()?.gateway ?? DEFAULT_GATEWAY).replace(/\/+$/, "");

  let models = [...FALLBACK_QODER_MODELS];
  let source = "fallback";
  let fetchedAt = 0;
  let lastError;

  /** 打一次 `GET /api/v2/model/list?Encode=1`（COSY 签名，响应是明文 JSON）。 */
  async function fetchFromRemote(credential) {
    const url = `${gateway()}${PATH_MODELS}`;
    const response = await fetch(url, {
      headers: { ...buildCosyHeaders(null, url, credential), Accept: "application/json", "User-Agent": "dsh-qoder-connect" },
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) {
      throw new Error(`model/list 返回 HTTP ${response.status}：${(await response.text().catch(() => "")).slice(0, 300)}`);
    }
    const doc = await response.json().catch(() => undefined);
    const chat = Array.isArray(doc?.chat) ? doc.chat : [];
    const usable = chat.map((entry) => normalizeCatalogEntry(entry)).filter((entry) => entry !== undefined && entry.enabled);
    if (usable.length === 0) throw new Error(`model/list 没有返回任何可用模型（chat 长度 ${chat.length}）`);
    return usable;
  }

  /** 刷新目录。并发调用共享同一次上游请求。 */
  let inflight;
  async function reload() {
    if (inflight === undefined) {
      inflight = (async () => {
        const credential = await tokens.get();
        const list = await fetchFromRemote(credential);
        models = list;
        source = "remote";
        fetchedAt = Date.now();
        lastError = undefined;
        logger?.info?.(`dsh-qoder-connect: 目录已刷新，${list.length} 个模型可用`);
        return list;
      })().catch((error) => {
        lastError = error instanceof Error ? error.message : String(error);
        logger?.warn?.(`dsh-qoder-connect: 目录刷新失败，沿用${source === "remote" ? "上次快照" : "兜底名单"}：${lastError}`);
        throw error;
      }).finally(() => { inflight = undefined; });
    }
    return inflight;
  }

  return {
    reload,
    source: () => source,
    fetchedAt: () => fetchedAt,
    lastError: () => lastError,
    current: () => models,
    find: (id) => models.find((model) => model.id === id),
  };
}

//#endregion
//#region 上游对话客户端

/** 逐字节喂入的 SSE 读取器：`event:<name>\n` + `data:<payload>\n\n`。 */
export function createSseReader() {
  const decoder = new TextDecoder();
  let buffer = "";
  let eventName = "";
  const dataLines = [];
  const pending = [];

  const flush = () => {
    if (eventName === "" && dataLines.length === 0) return;
    const raw = dataLines.join("\n");
    pending.push({ event: eventName === "" ? "message" : eventName, raw });
    eventName = "";
    dataLines.length = 0;
  };

  return {
    push(bytes) {
      buffer += decoder.decode(bytes, { stream: true });
      let newline;
      while ((newline = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        if (line === "") { flush(); continue; }
        if (line.startsWith("event:")) { eventName = line.slice(6).trim(); continue; }
        if (line.startsWith("data:")) { dataLines.push(line.slice(5).replace(/^ /, "")); continue; }
      }
      const out = pending.slice();
      pending.length = 0;
      return out;
    },
    pending() {
      const out = pending.slice();
      pending.length = 0;
      return out;
    },
  };
}

/** Qoder 的 SSE 控制哨兵（见 SDK 的 `giA()`）。 */
function isControlSentinel(raw) {
  return raw === "[DONE]"
    || raw === "[NOT_EXCEED_QUOTA]"
    || raw.startsWith("[EXCEED_QUOTA]")
    || raw.startsWith("[NOTIFICATIONS]");
}

/**
 * 解开一层 Qoder 信封。
 *
 * Qoder 的 `data:` 有两层：
 *   data: {"statusCodeValue":200,"statusCode":200,"body":"{\"choices\":[...]}"}
 * 其中 `body` 是**字符串**，里面才是 OpenAI 形状的 chunk；也可能是 `"[DONE]"`。
 *
 * 返回：
 *   `{kind:"chunk", chunk}`   内层是普通 chunk
 *   `{kind:"done"}`           流结束
 *   `{kind:"error", message}` 上游业务错误
 *   `{kind:"ignore"}`         控制哨兵 / 空事件
 */
export function unwrapQoderEvent(raw) {
  const text = typeof raw === "string" ? raw.trim() : "";
  if (text === "") return { kind: "ignore" };
  if (text === "[DONE]") return { kind: "done" };
  if (text === "[NOT_EXCEED_QUOTA]") return { kind: "ignore" };
  if (text.startsWith("[EXCEED_QUOTA]")) return { kind: "error", message: "Qoder 额度已用尽（EXCEED_QUOTA）" };
  if (text.startsWith("[NOTIFICATIONS]")) return { kind: "ignore" };

  let envelope;
  try {
    envelope = JSON.parse(text);
  } catch {
    return { kind: "ignore" };
  }

  // 带信封的形状。
  if (envelope !== null && typeof envelope === "object" && envelope.statusCodeValue !== undefined && envelope.body !== undefined) {
    const code = toNumber(envelope.statusCodeValue);
    if (code !== undefined && code !== 200) {
      const detail = typeof envelope.body === "string" ? envelope.body : JSON.stringify(envelope.body);
      return { kind: "error", message: `Qoder 上游 ${code}：${detail.slice(0, 400)}` };
    }
    const body = envelope.body;
    if (typeof body !== "string") {
      // 有的实现直接把对象塞在 body 里。
      return body !== null && typeof body === "object" ? { kind: "chunk", chunk: body, envelope } : { kind: "ignore" };
    }
    const inner = body.trim();
    if (inner === "") return { kind: "ignore" };
    if (inner === "[DONE]") return { kind: "done" };
    if (isControlSentinel(inner)) return { kind: "ignore" };
    try {
      return { kind: "chunk", chunk: JSON.parse(inner), envelope };
    } catch {
      return { kind: "ignore" };
    }
  }

  // 裸 OpenAI chunk（防御性：万一服务端换了形状）。
  if (envelope !== null && typeof envelope === "object" && Array.isArray(envelope.choices)) {
    return { kind: "chunk", chunk: envelope };
  }
  return { kind: "ignore" };
}

/** 把 Qoder 的 delta 翻成 OpenAI 的 delta。 */
function deltaOf(chunk) {
  const choice = Array.isArray(chunk?.choices) ? chunk.choices[0] : undefined;
  const delta = choice?.delta;
  if (delta === null || typeof delta !== "object") return undefined;
  const out = {};
  if (typeof delta.content === "string" && delta.content.length > 0) out.content = delta.content;
  // Qoder 的思考链字段就叫 reasoning_content（与 DeepSeek 一致）。
  if (typeof delta.reasoning_content === "string" && delta.reasoning_content.length > 0) out.reasoning_content = delta.reasoning_content;
  if (Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0) out.tool_calls = delta.tool_calls;
  return Object.keys(out).length > 0 ? out : undefined;
}

/** 组装对话请求体（OpenAI 形状 + Qoder 专有字段）。 */
export function buildChatBody(options) {
  const { modelKey, messages, isReasoning, maxTokens, tools, toolChoice, temperature, sessionId, sessionType } = options;
  const requestId = randomUUID();
  const lastUser = [...(Array.isArray(messages) ? messages : [])].reverse().find((m) => m?.role === "user");
  const promptText = typeof lastUser?.content === "string"
    ? lastUser.content
    : Array.isArray(lastUser?.content)
      ? lastUser.content.filter((p) => p?.type === "text").map((p) => p.text).join("\n")
      : "";

  /** @type {Record<string, unknown>} */
  const parameters = { enable_thinking: isReasoning === true };
  if (Number.isFinite(maxTokens) && maxTokens > 0) parameters.max_tokens = Math.trunc(maxTokens);
  if (Number.isFinite(temperature)) parameters.temperature = temperature;
  if (isReasoning === true) parameters.reasoning_effort = "high";

  return {
    request_id: requestId,
    request_set_id: requestId,
    chat_record_id: requestId,
    session_id: typeof sessionId === "string" && sessionId.length > 0 ? sessionId : randomUUID(),
    stream: true,
    chat_task: "FREE_INPUT",
    is_reply: true,
    is_retry: false,
    source: 1,
    version: "3",
    agent_id: "agent_common",
    task_id: "common",
    session_type: typeof sessionType === "string" && sessionType.length > 0 ? sessionType : DEFAULT_SESSION_TYPE,
    code_language: "",
    chat_prompt: "",
    image_urls: null,
    aliyun_user_type: "",
    // 顶层 system 服务端会忽略，系统提示走 messages 里的 {role:"system"}。
    system: "",
    messages: Array.isArray(messages) ? messages : [],
    tools: Array.isArray(tools) ? tools : [],
    ...(toolChoice === undefined ? {} : { tool_choice: toolChoice }),
    parameters,
    chat_context: {
      chatPrompt: "",
      imageUrls: null,
      extra: {
        context: [],
        modelConfig: { key: modelKey, is_reasoning: isReasoning === true },
        originalContent: promptText,
      },
      features: [],
      text: promptText,
    },
    model_config: { key: modelKey, source: "system" },
    business: {
      product: "cli",
      version: "1.0.0",
      type: "agent",
      stage: "start",
      id: requestId,
      name: promptText.slice(0, 30),
      begin_at: Date.now(),
    },
  };
}

/**
 * 上游对话客户端。
 *
 * `chatStream` 发一次 `POST /algo/api/v2/service/pro/sse/agent_chat_generation`，
 * 返回一个**已经把 Qoder 双层 SSE 翻成 OpenAI SSE** 的 ReadableStream，
 * 这样 shim 只要 pipe 出去就行。
 */
export function createQoderClient(options) {
  const { tokens, logger, config } = options;
  const gateway = () => String(config()?.gateway ?? DEFAULT_GATEWAY).replace(/\/+$/, "");
  const chatPath = () => {
    const value = config()?.chatPath;
    return typeof value === "string" && value.length > 0 ? value : DEFAULT_CHAT_PATH;
  };
  const chatUrl = () => `${gateway()}${chatPath()}`;

  /**
   * 发一次流式请求。
   *
   * 返回 `{ok:true, response}` 或 `{ok:false, status, kind, message}`。
   * 因为上游**总是**回 HTTP 200 + SSE（业务错误藏在信封的 `statusCodeValue` 里），
   * 所以这里先读**首个有效事件**再决定成败，避免已经写出 200 才发现是错误。
   */
  async function chatStream(request, signal) {
    const credential = await tokens.get();
    const url = chatUrl();
    const body = buildChatBody({
      modelKey: request.model,
      messages: request.messages,
      isReasoning: request.isReasoning,
      maxTokens: request.maxTokens,
      tools: request.tools,
      toolChoice: request.toolChoice,
      temperature: request.temperature,
      sessionId: request.sessionId,
      sessionType: config()?.sessionType,
    });

    // 只有要发出去的字节才参与签名 —— 顺序不能反。
    const encoded = qoderEncodeBody(Buffer.from(JSON.stringify(body), "utf8"));
    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {
          ...buildCosyHeaders(encoded, url, credential),
          "Content-Type": "application/json",
          Accept: "text/event-stream",
          "Cache-Control": "no-cache",
          "Accept-Encoding": "identity",
          "X-Model-Key": request.model,
          "X-Model-Source": "system",
        },
        body: encoded,
        signal,
      });
    } catch (error) {
      if (signal?.aborted === true) return { ok: false, status: 0, kind: "aborted", message: "客户端已取消" };
      return { ok: false, status: 0, kind: "network", message: `连不上 Qoder 网关：${error instanceof Error ? error.message : String(error)}` };
    }
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      const auth = response.status === 401 || response.status === 403;
      if (auth) tokens.invalidate();
      return {
        ok: false,
        status: response.status,
        kind: auth ? "auth" : "upstream",
        message: auth
          ? `Qoder 拒绝了凭据（HTTP ${response.status}）：jobToken 可能已失效或 PAT 被吊销。${text.slice(0, 200)}`
          : text.replace(/\s+/g, " ").slice(0, 400),
      };
    }
    if (response.body === null) return { ok: false, status: response.status, kind: "upstream", message: "Qoder 返回了空响应体" };

    const reader = response.body.getReader();
    const parser = createSseReader();
    let first;
    while (first === undefined) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const event of parser.push(value)) {
        const parsed = unwrapQoderEvent(event.raw);
        if (parsed.kind === "ignore") continue;
        first = parsed;
        break;
      }
    }
    if (first === undefined) return { ok: false, status: 502, kind: "upstream", message: "Qoder 流提前结束，没有读到任何事件" };
    if (first.kind === "error") return { ok: false, status: 502, kind: "upstream", message: first.message };
    if (first.kind === "done") return { ok: false, status: 502, kind: "upstream", message: "Qoder 只回了一个结束标记，没有正文" };
    return { ok: true, response: translate(reader, parser.pending(), first, request, signal) };
  }

  /** 把已解析的 Qoder 事件流翻译成 OpenAI SSE 字节流。 */
  function translate(reader, leftoverEvents, firstChunk, request, signal) {
    const model = request.model;
    const id = `chatcmpl-qoder-${randomBytes(8).toString("hex")}`;
    const created = Math.floor(Date.now() / 1000);
    const encoder = new TextEncoder();
    const parser = createSseReader();
    let usage;
    let finished = false;

    const chunk = (delta, finishReason) => {
      const payload = {
        id,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [{ index: 0, delta, finish_reason: finishReason ?? null }],
      };
      if (finishReason !== undefined && finishReason !== null) {
        // openai-completions 的解析器只在最后一帧读 usage，所以并到收尾帧里。
        payload.usage = {
          prompt_tokens: usage?.prompt_tokens ?? 0,
          completion_tokens: usage?.completion_tokens ?? 0,
          total_tokens: usage?.total_tokens ?? 0,
        };
      }
      return encoder.encode(`data: ${JSON.stringify(payload)}\n\n`);
    };

    return new ReadableStream({
      start(controller) {
        // `finished` = 逻辑上收尾了；`closed` = 流真的关了。两者必须分开，
        // 否则 done 事件里 close() 之后 pump() 结尾再 close() 会抛 ERR_INVALID_STATE。
        let closed = false;
        const closeStream = () => {
          if (closed) return;
          closed = true;
          try { controller.close(); } catch { /* 下游已取消 */ }
        };
        const enqueue = (bytes) => {
          if (closed) return;
          try { controller.enqueue(bytes); } catch { closed = true; }
        };
        const emit = (parsed) => {
          if (finished || closed) return;
          if (parsed.kind === "ignore") return;
          if (parsed.kind === "error") {
            enqueue(chunk({ content: `\n\n[Qoder 错误] ${parsed.message}` }));
            return;
          }
          if (parsed.kind === "done") {
            finished = true;
            enqueue(chunk({}, "stop"));
            enqueue(encoder.encode("data: [DONE]\n\n"));
            closeStream();
            return;
          }
          const inner = parsed.chunk;
          if (inner?.usage !== undefined && inner.usage !== null) usage = inner.usage;
          const choice = Array.isArray(inner?.choices) ? inner.choices[0] : undefined;
          if (choice?.finish_reason !== undefined && choice.finish_reason !== null) {
            finished = true;
            const delta = deltaOf(inner) ?? {};
            enqueue(chunk(delta, choice.finish_reason));
            enqueue(encoder.encode("data: [DONE]\n\n"));
            closeStream();
            return;
          }
          const delta = deltaOf(inner);
          if (delta !== undefined) enqueue(chunk(delta));
        };

        const pump = async () => {
          try {
            // 首个 chunk 已经在 chatStream 里读出来了，这里补发。
            if (firstChunk !== undefined) emit(firstChunk);
            for (const raw of leftoverEvents) emit(unwrapQoderEvent(raw.raw));
            while (!finished && !closed) {
              const { done, value } = await reader.read();
              if (done) break;
              for (const event of parser.push(value)) emit(unwrapQoderEvent(event.raw));
            }
            if (!finished) {
              finished = true;
              enqueue(chunk({}, "stop"));
              enqueue(encoder.encode("data: [DONE]\n\n"));
            }
            closeStream();
          } catch (error) {
            logger?.warn?.(`dsh-qoder-connect: 上游流中断：${error instanceof Error ? error.message : String(error)}`);
            if (!finished) {
              finished = true;
              enqueue(chunk({}, "stop"));
              enqueue(encoder.encode("data: [DONE]\n\n"));
            }
            closeStream();
          }
        };

        if (signal?.aborted === true) { finished = true; closeStream(); return; }
        pump();
      },
      cancel() {
        finished = true;
        reader.cancel().catch(() => {});
      },
    });
  }

  return { chatStream };
}

//#endregion
//#region 账号侧客户端（额度 + 签到活动）

/** OpenAPI 平面：普通 `Bearer <jobToken>` + `Cosy-ClientType`，**不需要 COSY 签名**。 */
function openApiHeaders(jobToken) {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${jobToken}`,
    "Cosy-ClientType": COSY_CLIENT_TYPE,
    "User-Agent": "Qoder",
  };
}

/**
 * 额度与「签到」。
 *
 * 两条额度来源：
 *   1. `GET /sash/api/v2/me/usage`   —— **App 自己**用的那条（OpenAPI 平面），
 *      返回 `{displayMode, qoderUsage:{userType,userQuota:{used,total,percentage},…}}`。
 *   2. `GET /api/v2/quota/usage`     —— 社区参考实现那条（COSY 平面），
 *      返回 `{userQuota:{total,used,remaining,percentage,unit},…}`。
 *
 * 先打 1，失败回落到 2；两条都挂就抛，由状态文档降级成 `quotaError`。
 *
 * 签到：Qoder CN **确实**有每日活动（App 左下角用量面板里的礼物图标），状态就是
 * `GET /sash/api/v1/me/campaigns` → `{showCampaign, campaignUrl, claimable}`。
 * 但**领取动作在 App 内嵌的托管页面里**（`CampaignMainService` 给该 webContents
 * 注入 Authorization 后才放行），OpenAPI 平面上没有任何 claim 端点 —— 整个包里
 * 只有 8 个 `/sash` 路径，没有一个是「领取」。所以这里**只读** `claimable`，
 * 并把「要签到得回桌面 App」如实告诉用户，绝不假装点一下能领到。
 */
export function createQoderAccountClient(options) {
  const { tokens, config, logger } = options;
  const openapiBase = () => String(config()?.openapiBase ?? DEFAULT_OPENAPI).replace(/\/+$/, "");
  const TIMEOUT_MS = 20000;

  /** 打 OpenAPI 平面。失败一律抛，由调用方决定降级方式。 */
  async function getOpenApi(path, label, credential) {
    const url = `${openapiBase()}${path}`;
    let response;
    try {
      response = await fetch(url, {
        headers: openApiHeaders(credential.jobToken),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (error) {
      throw new Error(`${label} 连不上 ${openapiBase()}：${error instanceof Error ? error.message : String(error)}`);
    }
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) tokens.invalidate();
      throw new Error(`${label} 返回 HTTP ${response.status}：${text.replace(/\s+/g, " ").slice(0, 200)}`);
    }
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`${label} 返回的不是 JSON：${text.slice(0, 200)}`);
    }
  }

  /** 打 COSY 平面（备用额度来源）。 */
  async function getCosy(path, label, credential) {
    const url = `${openapiBase()}${path}`;
    const response = await fetch(url, {
      headers: { ...buildCosyHeaders(null, url, credential), Accept: "application/json", "User-Agent": "dsh-qoder-connect" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`${label} 返回 HTTP ${response.status}：${(await response.text().catch(() => "")).slice(0, 200)}`);
    }
    return response.json();
  }

  /** 「已用 / 总额 / 百分比」→ 统一形状。`total` 为 0 表示不限量。 */
  function shapeQuota(source, parts) {
    const used = toNumber(parts.used);
    const total = toNumber(parts.total);
    const remaining = toNumber(parts.remaining) ?? (total !== undefined && used !== undefined ? Math.max(0, total - used) : undefined);
    let percentage = toNumber(parts.percentage);
    // 有的实现给 0..1 的比例，有的给 0..100 的百分数 —— 统一成 0..1。
    if (percentage !== undefined && percentage > 1) percentage /= 100;
    if (percentage === undefined && total !== undefined && total > 0 && used !== undefined) percentage = used / total;
    return {
      source,
      used,
      total,
      remaining,
      percentage,
      unit: typeof parts.unit === "string" ? parts.unit : undefined,
      unlimited: total === 0,
    };
  }

  /** App 那条：`displayMode === "enterprise"` 时没有可用数字，只有外链。 */
  function shapeAccountUsage(doc) {
    if (doc?.displayMode === "enterprise") {
      const detail = doc?.enterpriseUsage;
      return {
        source: "account-usage",
        enterprise: true,
        detailUrl: typeof detail?.detailUrl === "string" ? detail.detailUrl : undefined,
        unlimited: false,
      };
    }
    const usage = doc?.qoderUsage;
    if (usage === null || typeof usage !== "object") throw new Error("额度接口没有返回 qoderUsage");
    const user = usage.userQuota ?? {};
    const addOn = usage.addOnQuota === null || usage.addOnQuota === undefined ? {} : usage.addOnQuota;
    const addOnTotal = toNumber(addOn.total);
    const addOnUsed = toNumber(addOn.used);
    const addOnRemaining = addOnTotal === undefined || addOnUsed === undefined ? undefined : Math.max(0, addOnTotal - addOnUsed);

    /**
     * [dsh-connect 2026-09-24 修正] 主额度要把**加油包**算进来。
     *
     * 实测 personal_standard 账号：`userQuota = {total:0, used:0}` 而
     * `addOnQuota = {total:100, used:0}` —— 只读 userQuota 会得到 0/0，
     * 而 `unlimited: total === 0` 就把它显示成"不限量"（用户一眼看出不对）。
     * 合并成"总可用 = 主额度 + 加油包"才是这个面板该显示的账。
     */
    const sum = (a, b) => {
      const left = toNumber(a);
      const right = toNumber(b);
      if (left === undefined) return right;
      if (right === undefined) return left;
      return left + right;
    };

    const shaped = shapeQuota("account-usage", {
      used: sum(user.used, addOnUsed),
      total: sum(user.total, addOnTotal),
      // 不传 percentage：合并后按 used/total 重算，避免"主额度占比"与合并后的账不一致。
      unit: typeof user.unit === "string" ? user.unit : addOn.unit,
    });
    return {
      ...shaped,
      enterprise: false,
      userType: typeof usage.userType === "string" ? usage.userType : undefined,
      /** 加油包剩余（单独留一份，便于 UI 细分）。 */
      addOnRemaining,
      addOnTotal,
      /** 组织资源包（有些账号有）。 */
      orgUsed: usage.orgResourcePackage === null || usage.orgResourcePackage === undefined
        ? undefined
        : toNumber(usage.orgResourcePackage.used),
    };
  }

  return {
    /** 额度。两条来源依次尝试，都失败才抛。 */
    async fetchQuota(credential) {
      const errors = [];
      try {
        return shapeAccountUsage(await getOpenApi(PATH_ACCOUNT_USAGE, "额度", credential));
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
      try {
        const doc = await getCosy(PATH_QUOTA_LEGACY, "额度(备用)", credential);
        const user = doc?.userQuota ?? {};
        if (user.total === undefined && user.used === undefined && user.remaining === undefined) {
          throw new Error("备用额度接口没有返回 userQuota");
        }
        return {
          ...shapeQuota("quota-usage", { used: user.used, total: user.total, remaining: user.remaining, percentage: user.percentage, unit: user.unit }),
          enterprise: false,
          isQuotaExceeded: doc?.isQuotaExceeded === true,
          expiresAt: typeof doc?.expiresAt === "string" ? doc.expiresAt : undefined,
        };
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
      throw new Error(errors.join(" ／ "));
    },

    /**
     * 「签到」状态。
     *
     * 只读：`claimable` 表示今天有奖可领。领取必须回桌面 App，这里如实标注。
     * 404 一律当成「当前账号没有活动」（而不是错误）—— 免费/企业账号本来就没有。
     */
    async fetchCampaign(credential) {
      let doc;
      try {
        doc = await getOpenApi(PATH_CAMPAIGNS, "签到活动", credential);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("HTTP 404")) {
          return { supported: false, showCampaign: false, claimable: false, reason: "当前账号没有签到活动" };
        }
        throw error;
      }
      const showCampaign = doc?.showCampaign === true;
      const claimable = doc?.claimable === true;
      const campaignUrl = typeof doc?.campaignUrl === "string" && doc.campaignUrl.trim().length > 0 ? doc.campaignUrl.trim() : undefined;
      if (!showCampaign && !claimable) {
        return { supported: true, showCampaign: false, claimable: false, reason: "当前账号没有进行中的签到活动" };
      }
      return {
        supported: true,
        showCampaign,
        claimable,
        campaignUrl,
        // 能不能由本插件代领：不能。见函数头注释。
        claimableHere: false,
        reason: claimable
          ? "Qoder CN 今日有可领取的奖励，但领取动作在桌面 App 内嵌的托管页面里，本插件没有可调用的接口 —— 请打开 Qoder CN 的用量面板（左下角礼物图标）领取。"
          : "今日签到已完成或暂不可领。",
      };
    },

    /**
     * 领取。**永远不假装成功** —— 直接把「去哪儿领」告诉调用方。
     * 保留成异步是为了让路由对 GET/POST 一视同仁。
     */
    async claimCampaign(credential) {
      let campaign;
      try {
        campaign = await this.fetchCampaign(credential);
      } catch (error) {
        return { state: "failed", message: error instanceof Error ? error.message : String(error) };
      }
      if (campaign.supported === false) return { state: "unsupported", message: campaign.reason ?? "当前账号没有签到活动" };
      if (campaign.claimable !== true) return { state: "already-claimed", campaign };
      return { state: "manual-required", campaign, message: campaign.reason, campaignUrl: campaign.campaignUrl };
    },
  };
}

//#endregion
//#region 回环 shim

function writeOpenAIError(res, status, code, message) {
  writeJson(res, status, { error: { message, type: code, code } });
}
async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/**
 * OpenAI → Qoder 的消息转换。
 *
 * Qoder 的请求是 OpenAI 形状，所以这里基本是透传 + 清洗：
 *   · `system` 保持独立角色（顶层 `system` 字段服务端会忽略）
 *   · 图片 `image_url` 原样保留
 *   · `assistant.tool_calls` 与 `role:"tool"` 原样保留
 */
export function toQoderMessages(messages) {
  const out = [];
  for (const message of Array.isArray(messages) ? messages : []) {
    if (message === null || typeof message !== "object") continue;
    const role = typeof message.role === "string" ? message.role : "user";
    /** @type {Record<string, unknown>} */
    const next = { role };
    if (typeof message.content === "string") {
      next.content = message.content;
    } else if (Array.isArray(message.content)) {
      next.content = message.content
        .map((part) => {
          if (part?.type === "text" && typeof part.text === "string") return { type: "text", text: part.text };
          if (part?.type === "image_url" && part.image_url?.url) return { type: "image_url", image_url: { url: part.image_url.url } };
          return undefined;
        })
        .filter((part) => part !== undefined);
    } else {
      next.content = "";
    }
    if (Array.isArray(message.tool_calls) && message.tool_calls.length > 0) next.tool_calls = message.tool_calls;
    if (typeof message.tool_call_id === "string") next.tool_call_id = message.tool_call_id;
    if (typeof message.name === "string") next.name = message.name;
    out.push(next);
  }
  if (out.length === 0) out.push({ role: "user", content: "" });
  return out;
}

/** 把 OpenAI 的 tools 原样透传（Qoder 的请求就是 OpenAI 形状）。 */
function toQoderTools(tools) {
  if (!Array.isArray(tools)) return [];
  return tools
    .filter((tool) => tool?.type === "function" && typeof tool.function?.name === "string")
    .map((tool) => ({
      type: "function",
      function: {
        name: tool.function.name,
        ...(typeof tool.function.description === "string" ? { description: tool.function.description } : {}),
        parameters: tool.function.parameters ?? { type: "object", properties: {} },
        ...(typeof tool.function.strict === "boolean" ? { strict: tool.function.strict } : {}),
      },
    }));
}

/** 解码模型 id 里可选的后缀：`<key>@think` 强制开思考、`@nothink` 强制关。 */
export function decodeModelId(raw, fallback) {
  const id = typeof raw === "string" ? raw : "";
  if (id.endsWith("@think")) return { model: id.slice(0, -"@think".length), thinking: true };
  if (id.endsWith("@nothink")) return { model: id.slice(0, -"@nothink".length), thinking: false };
  return { model: id, thinking: fallback };
}

/**
 * 回环 OpenAI shim。与另外两条渠道同构：随机端口 + 随机 bearer，
 * 只服务三个路由；上游换成 Qoder 客户端。
 */
export function createQoderShim(options) {
  const { client, catalog } = options;
  const logger = options.logger;
  /** 每次启动换一份共享密钥；只在 127.0.0.1 上用。 */
  const SHARED_SECRET = randomBytes(32).toString("base64url");

  function bearerOk(req) {
    const header = req.headers.authorization;
    if (typeof header !== "string") return false;
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    if (match === null) return false;
    const given = Buffer.from(match[1]);
    const expected = Buffer.from(SHARED_SECRET);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  const server = createServer((req, res) => { handle(req, res); });
  const ready = new Promise((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", reject);
  });
  server.listen(0, "127.0.0.1");
  const baseUrl = () => {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("dsh-qoder-connect: shim 没有监听地址");
    return `http://127.0.0.1:${address.port}`;
  };

  async function handle(req, res) {
    try {
      if (!hostIsLoopback(req.headers.host)) { writeOpenAIError(res, 403, "host_not_allowed", "Host 必须是回环地址"); return; }
      if (!originIsLoopback(req.headers.origin)) { writeOpenAIError(res, 403, "origin_not_allowed", "Origin 必须是回环地址"); return; }
      if (!bearerOk(req)) { writeOpenAIError(res, 401, "unauthorized", "Authorization bearer 缺失或不匹配"); return; }
      const url = req.url ?? "/";
      if (req.method === "GET" && (url === "/healthz" || url === "/healthz/")) { writeJson(res, 200, { ok: true }); return; }
      if (req.method === "GET" && (url === "/v1/models" || url === "/v1/models/")) {
        writeJson(res, 200, {
          object: "list",
          data: catalog.current().map((model) => ({ id: model.id, object: "model", created: 0, owned_by: QODER_PROVIDER })),
        });
        return;
      }
      if (req.method === "POST" && (url === "/v1/chat/completions" || url === "/v1/chat/completions/")) { await chatCompletions(req, res); return; }
      writeOpenAIError(res, 404, "not_found", `no such route: ${req.method} ${url}`);
    } catch (error) {
      if (!res.headersSent) writeOpenAIError(res, 500, "internal", String(error));
      else res.end();
    }
  }

  async function chatCompletions(req, res) {
    if (typeof req.headers["content-type"] !== "string" || !req.headers["content-type"].toLowerCase().includes("application/json")) {
      writeOpenAIError(res, 415, "unsupported_media_type", "Content-Type 必须是 application/json");
      return;
    }
    let request;
    try {
      request = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      writeOpenAIError(res, 400, "invalid_json", "请求体不是合法 JSON");
      return;
    }
    const decoded = decodeModelId(request.model, undefined);
    const entry = catalog.find(decoded.model);
    const isReasoning = decoded.thinking ?? entry?.isReasoning ?? false;

    const controller = new AbortController();
    req.on("close", () => controller.abort());

    let result;
    try {
      result = await client.chatStream({
        model: decoded.model,
        messages: toQoderMessages(request.messages),
        tools: toQoderTools(request.tools),
        toolChoice: request.tool_choice,
        isReasoning,
        maxTokens: request.max_tokens ?? request.max_completion_tokens,
        temperature: request.temperature,
      }, controller.signal);
    } catch (error) {
      writeOpenAIError(res, 401, "not_signed_in", error instanceof Error ? error.message : String(error));
      return;
    }

    if (!result.ok) {
      const status = result.kind === "auth" ? 401 : result.kind === "aborted" ? 499 : 502;
      writeOpenAIError(res, status, result.kind, `qoder upstream (http ${result.status}): ${result.message.slice(0, 500)}`);
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    });
    let sawDone = false;
    const body = Readable.fromWeb(result.response);
    body.on("data", (chunk) => { if (chunk.includes("[DONE]")) sawDone = true; });
    body.on("error", (error) => {
      logger?.warn?.(`dsh-qoder-connect: 上游流中断：${error instanceof Error ? error.message : String(error)}`);
      if (!sawDone && res.writable) res.end("data: [DONE]\n\n");
    });
    body.pipe(res);
  }

  return {
    ready,
    baseUrl,
    token: () => SHARED_SECRET,
    close: () => new Promise((resolve, reject) => {
      server.close(() => resolve());
      server.closeAllConnections();
      server.once("error", reject);
    }),
  };
}

//#endregion
//#region 适配器

/** pi-ai 的 auth 平面在本插件里必须惰性：认证只走 shim 的共享密钥。 */
const INERT_AUTH = {
  credentials: {
    async read() {},
    async list() { return []; },
    async modify() { throw new Error("dsh-qoder-connect: the qoder route has no pi-ai credential lifecycle"); },
    async delete() {},
  },
  authContext: {
    async env() {},
  },
};

/** pi-ai 模型描述里要显式写 0，否则计费面板会按未知价格处理。 */
const NO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
const REQUEST_IMAGE_BUDGETS = {
  maxRequestImageBytes: 20971520,
  requestImagePixelBudget: 4194304,
  requestImageMaxBytes: 1048576,
};
const QODER_STREAM_IDLE_TIMEOUT_MS = 300000;

/** 组装 pi-ai 的 provider + DSH 的 adapter。 */
/**
 * [dsh-connect] 面板下发的"禁用模型"钩子：`(providerId) => 要隐藏的模型 id[]`。
 *
 * provider 自己不知道面板的存在；lib/index.js 在启动时用 setExternalHidden 注入，
 * 未注入时视为"不隐藏"。每次构建模型列表时重新调用，所以用户在面板里改完立即生效。
 */
let externalHidden = () => [];
export function setExternalHidden(fn) {
  externalHidden = typeof fn === "function" ? fn : () => [];
}

export function createQoderAdapter(options) {
  const { shim, catalog } = options;
  const providerId = options.providerId ?? QODER_PROVIDER;
  const displayName = options.displayName ?? QODER_DISPLAY_NAME;
  /** [dsh-connect] 面板禁用的模型 id（每次构建列表时重读，改完立即生效）。 */
  const hidden = options.hidden ?? (() => []);

  const buildModels = () => {
    const baseUrl = `${shim.baseUrl()}/v1`;
    const hiddenIds = new Set(hidden());
    return catalog.current().filter((info) => !hiddenIds.has(info.id)).map((info) => ({
      id: info.id,
      // 倍率挂在名字上：模型下拉只渲染 `name`（理由见 withRateName）。
      name: withRateName(info),
      api: "openai-completions",
      provider: providerId,
      baseUrl,
      input: info.supportsImages === true ? ["text", "image"] : ["text"],
      // 思考链走 delta.reasoning_content 透传；这里保持 false，避免 pi-ai
      // 额外塞 Qoder 不认识的 reasoning 参数。
      reasoning: false,
      cost: NO_COST,
      contextWindow: info.contextWindow ?? 200000,
      maxTokens: info.maxTokens ?? 32000,
      compat: { maxTokensField: "max_tokens" },
    }));
  };

  const provider = {
    ...createProvider({
      id: providerId,
      name: displayName,
      auth: {
        apiKey: {
          name: "Qoder 回环凭据（由插件自己维护，无需填写）",
          async resolve({ credential }) {
            const apiKey = credential?.key;
            return apiKey === undefined || apiKey.length === 0 ? undefined : { auth: { apiKey }, source: "Qoder" };
          },
        },
      },
      models: buildModels(),
      api: openAICompletionsApi(),
    }),
    getModels: () => buildModels(),
  };

  const profile = {
    provider: providerId,
    displayName,
    streamIdleTimeoutMs: QODER_STREAM_IDLE_TIMEOUT_MS,
    retryPolicy: resolveRetryPolicy(undefined, "dsh-qoder-connect retryPolicy"),
    configuredMaxTokens: new Map(),
    modelErrors: new Map(),
    ...REQUEST_IMAGE_BUDGETS,
    piProvider: provider,
  };
  let profiles = new Map([[providerId, profile]]);
  return {
    adapter: new PiAiAdapter({
      profiles: () => profiles,
      auth: INERT_AUTH,
      resolveApiKey: async () => shim.token(),
    }),
    invalidate: () => { profiles = new Map([[providerId, profile]]); },
  };
}

//#endregion
//#region 状态路由（供浏览器侧读取）

/** 注册给浏览器侧的两个路由。与 client.js 里的字面量必须逐字一致。 */
export const QODER_STATUS_ROUTE = "/plugins/dsh-qoder-connect/status";
export const QODER_CHECKIN_ROUTE = "/plugins/dsh-qoder-connect/checkin";

/** 倍率展示：0.8 → "0.8×"，整数去掉小数，拿不到就是 undefined。 */
function formatRate(rate) {
  if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0) return undefined;
  return Number.isInteger(rate) ? `${rate}×` : `${Number(rate.toFixed(2))}×`;
}

/**
 * 把倍率挂到模型名上：`Qwen3.8-Max` → `Qwen3.8-Max · 0.5×`。
 *
 * DSH 0.1.5 的模型下拉（dsh-client-ui-model-selection）只渲染 `model.name`
 * （`modelLabel = currentChoice?.model.name`，列表项也是 `children: model.name`），
 * `description` 根本不读 —— 想让每个模型都看到倍率，只能挂在名字上。
 *
 * 拿不到倍率（上游没给 `price_factor`，例如 `Qwen3.8-Flash`）就原样返回，不硬凑。
 * 面板状态文档里另有独立的 `rate` 字段，所以那一边不必重复。
 */
function withRateName(info) {
  const rate = formatRate(info.rate);
  return rate === undefined ? info.name : `${info.name} · ${rate}`;
}

/**
 * 组装给浏览器侧的状态文档。
 *
 * 与另外两条渠道同一原则：**额度与签到都是「尽力而为」**——上游任何一段失败都降级
 * 成该字段的错误串，而不是让整份文档 500。否则网络抖一下，界面上连渠道名和签到
 * 按钮都会消失。
 *
 * 这里额外把**每个模型的倍率**带上（`models[].rate`），因为 dock 那一行要显示
 * 当前选中模型的倍率，而它只随目录变，不该为它单独打一次上游。
 */
export async function qoderWebStatus(deps) {
  const base = { provider: QODER_PROVIDER, channel: QODER_DISPLAY_NAME };
  // 凭据可以来自 App 会话（session.json）或官方 PAT —— 两者都没有才算未登录。
  // （会话由宿主脚本 scripts/qoder-vault.mjs --install-session 导出，token-manager 会优先用它。）
  const session = deps.sessions === undefined ? undefined : await deps.sessions.current().catch(() => undefined);
  const pat = await deps.pats.current();
  if (session === undefined && pat === undefined) {
    return {
      ...base,
      status: "signed-out",
      patPath: deps.pats.path(),
      ...deps.sessions === undefined ? {} : { sessionPath: deps.sessions.path() },
    };
  }

  let credential;
  try {
    credential = await deps.tokens.get();
  } catch (error) {
    return { ...base, status: "signed-out", patPath: deps.pats.path(), patSource: pat.source, reason: briefMessage(error) };
  }

  const models = deps.catalog.current();
  const doc = {
    ...base,
    status: "signed-in",
    userId: credential.userID,
    account: credential.name === "" ? credential.email : credential.name,
    email: credential.email,
    patSource: credential.source,
    expiresAt: new Date(credential.expiresAt).toISOString(),
    modelCount: models.length,
    catalogSource: deps.catalog.source(),
    catalogFetchedAt: deps.catalog.fetchedAt() === 0 ? undefined : new Date(deps.catalog.fetchedAt()).toISOString(),
    models: models.map((model) => ({
      id: model.id,
      name: model.name,
      rate: formatRate(model.rate),
      free: model.isFree === true,
      isReasoning: model.isReasoning === true,
      contextWindow: model.contextWindow,
    })),
  };

  try {
    doc.quota = await deps.account.fetchQuota(credential);
  } catch (error) {
    doc.quotaError = briefMessage(error);
  }
  try {
    doc.checkin = await deps.account.fetchCampaign(credential);
  } catch (error) {
    doc.checkinError = briefMessage(error);
  }
  return doc;
}

/** 签到路由：GET 读状态（只读），POST 尝试领取（会如实返回 manual-required）。 */
export async function qoderCheckinAction(deps, method) {
  const credential = await deps.tokens.get().catch(() => undefined);
  if (credential === undefined) return { state: "signed-out" };
  if (method === "GET") {
    try {
      return { state: "signed-in", checkin: await deps.account.fetchCampaign(credential) };
    } catch (error) {
      return { state: "failed", message: briefMessage(error) };
    }
  }
  try {
    return await deps.account.claimCampaign(credential);
  } catch (error) {
    return { state: "failed", message: briefMessage(error) };
  }
}

/**
 * 两个路由的共用外壳。
 *
 * 必须做 loopback 守卫：这两个端点挂在用户自己的 DSH 端口上，而 DSH 端口可能被
 * 反代 / 局域网暴露。Host **和** Origin 都要求是回环，缺一不可
 * （只有 Host 挡不住 DNS rebinding，只有 Origin 挡不住非浏览器客户端；
 * 这两个接口本身不写敏感数据，两者齐备即可）。
 */
function qoderRouteHandler(handle) {
  return async (req, res) => {
    if (req.method !== "GET" && req.method !== "POST") {
      writeJson(res, 405, { error: "method not allowed" });
      return;
    }
    if (!loopbackRequest(req)) {
      writeJson(res, 403, { error: "request-not-trusted" });
      return;
    }
    try {
      writeJson(res, 200, await handle(req.method));
    } catch (error) {
      writeJson(res, 500, { error: briefMessage(error) });
    }
  };
}

/** 注册 `/plugins/dsh-qoder-connect/{status,checkin}`；webServer 缺失时整段跳过。 */
export function registerQoderStatusRoutes(ctx, deps) {
  for (const [path, handle] of [
    [QODER_STATUS_ROUTE, () => qoderWebStatus(deps)],
    [QODER_CHECKIN_ROUTE, (method) => qoderCheckinAction(deps, method)],
  ]) {
    ctx.effect(() => {
      const dispose = ctx.webServer.register({ kind: "exact", path, handler: qoderRouteHandler(handle) });
      return () => { dispose(); };
    }, `dsh-qoder-connect: ${path}`);
  }
}

//#endregion
//#region 插件入口

const CREDENTIAL_POLL_MS = 30000;
const MIN_POLL_MS = 100;
const MAX_POLL_MS = 86400000;
function pollInterval(config) {
  const override = config?.pollIntervalMs;
  if (!Number.isFinite(override) || override < MIN_POLL_MS) return CREDENTIAL_POLL_MS;
  return Math.min(override, MAX_POLL_MS);
}

/**
 * 运行态落盘：`$DSH_HOME/.qoder-connect-state.json`。
 *
 * 与另外两条渠道同思路 —— DSH 的插件日志默认不进 web 日志文件，
 * 只看日志无法判断一个渠道到底有没有注册成功、当前是「未登录」还是「已就绪」。
 * 这份文件把结论固化下来，排查时直接看它。
 */
function writeState(patch) {
  try {
    const path = join(resolveDshHome(), ".qoder-connect-state.json");
    writeFileSync(path, `${JSON.stringify({ ...patch, at: new Date().toISOString() }, null, 2)}\n`, "utf8");
  } catch { /* 落盘失败不影响渠道本身 */ }
}

/**
 * 启动：起回环 shim → 注册 `qoder1` provider → 按凭据巡检刷新目录。
 *
 * 无论有没有 PAT 都先注册 provider —— DSH 用「模型组为空」来隐藏一个模型组，
 * 所以登录（放进 PAT）发生在 DSH 已经跑起来之后也能生效，不需要重新注册。
 */
export function apply(ctx, config) {
  let stopped = false;
  const current = () => config ?? {};

  const pats = createPatStore({ config: current });
  // [dsh-connect] App 会话优先：导出了 ~/.dsh/qoder/session.json 就用它，不碰 PAT。
  const sessions = createSessionStore({ config: current });
  const tokens = createTokenManager({ pats, sessions, config: current, logger: ctx.logger });
  const catalog = createCatalog({ tokens, config: current, logger: ctx.logger });
  const client = createQoderClient({ tokens, config: current, logger: ctx.logger });
  const account = createQoderAccountClient({ tokens, config: current, logger: ctx.logger });

  const shim = createQoderShim({ client, catalog, logger: ctx.logger });

  // 渠道状态行（渠道 / 倍率 / 额度 / 签到）走 DSH 自己的 webServer，不是回环 shim ——
  // 前者给浏览器同源读取，后者只给 pi-ai 发 OpenAI 请求。webServer 在非 web
  // profile 里不存在，所以用 ctx.inject 做可选依赖。
  ctx.inject(["webServer"], (webCtx) => {
    if (stopped) return;
    try {
      registerQoderStatusRoutes(webCtx, { pats, sessions, tokens, catalog, account });
    } catch (error) {
      ctx.logger?.warn?.("dsh-qoder-connect: 状态路由注册失败（渠道本身不受影响）", error);
    }
  });

  shim.ready.then(() => {
    if (stopped) return;
    const { adapter, invalidate } = createQoderAdapter({ shim, catalog, hidden: () => externalHidden(QODER_PROVIDER) });
    const release = ctx.llm.registerAdapter([QODER_PROVIDER], adapter);
    try {
      ctx.effect(() => () => { release(); shim.close(); });
    } catch {
      release();
      shim.close();
    }

    const refresh = () => {
      if (stopped) return;
      tokens.get().then(
        (credential) => catalog.reload().then(
          () => {
            if (stopped) return;
            invalidate();
            ctx.emit("llm/adapters-updated");
            const models = catalog.current();
            writeState({
              ready: true,
              provider: QODER_PROVIDER,
              shim: shim.baseUrl(),
              userId: credential.userID,
              patSource: credential.source,
              jobTokenExpiresAt: new Date(credential.expiresAt).toISOString(),
              catalogSource: catalog.source(),
              modelCount: models.length,
              models: models.map((model) => ({ id: model.id, rate: model.rate, free: model.isFree })),
            });
            ctx.logger.info(`dsh-qoder-connect: Qoder 已就绪（uid=${credential.userID}，${models.length} 个模型）`);
          },
          (error) => {
            if (stopped) return;
            const message = error instanceof Error ? error.message : String(error);
            // 目录挂了但凭据是好的：渠道仍然可用（只是沿用兜底名单）。
            invalidate();
            ctx.emit("llm/adapters-updated");
            writeState({
              ready: true,
              provider: QODER_PROVIDER,
              shim: shim.baseUrl(),
              userId: credential.userID,
              catalogSource: catalog.source(),
              modelCount: catalog.current().length,
              catalogError: message,
            });
            ctx.logger.warn(`dsh-qoder-connect: 目录刷新失败，渠道沿用兜底名单 — ${message}`);
          },
        ),
        (error) => {
          if (stopped) return;
          const message = error instanceof Error ? error.message : String(error);
          writeState({ ready: false, provider: QODER_PROVIDER, shim: shim.baseUrl(), patPath: pats.path(), error: message });
          ctx.logger.warn(`dsh-qoder-connect: 未就绪 — ${message}`);
        },
      );
    };

    refresh();
    const timer = setInterval(refresh, pollInterval(current()));
    timer.unref?.();
    ctx.effect(() => () => { clearInterval(timer); });
  }).catch((error) => {
    ctx.logger?.error?.("dsh-qoder-connect: 回环 shim 启动失败", error);
  });

  ctx.effect(() => () => { stopped = true; });
}

//#endregion
