// 在宿主机上执行：把 WorkBuddy 桌面主凭据从加密信封解出明文副本，供容器内插件读取。
//
// 背景：WorkBuddy 5.6+ 把 workbuddy-desktop.info 里的 accessToken/refreshToken 等
// 字段换成了 `{$wbEncrypted:1, envelope:<base64>}` 信封（AES-256-GCM，密钥由
// App 自己的 Electron 在运行时解出）。dsh-workbuddy-connect 在容器里解不开——它
// 需要 WorkBuddy 的 Electron 二进制，而容器里只有 macOS 那份（Mach-O 跑不了）。
// 所以由本脚本在宿主上用 App 自己的 Electron 拿到 at-rest 密钥，把整份文档解成
// 明文，写到 devbox/secrets/workbuddy-plain.info；容器经 WORKBUDDY_AUTH_FILE
// 改读该文件（见 docker-compose.yml 的 environment 段）。
//
// 为什么是"整份文档深拷贝解封"而不是"重新拼一个文档"：插件的
// parseWorkBuddyAuth 只认两种形状——桌面 App 实际的嵌套
// `{"auth":{...},"account":{...}}`，或扁平 `{"accessToken":...}`。信封散布在
// account / auth / accounts[] / allAccounts[] 多处，逐字段重建很容易写错形状
// （尤其 accessToken 读成空串时插件只会静默判"未登录"，不会报错，极难排查）。
// 深拷贝解封后落盘的文档与原文件同形，插件怎么读原文件就怎么读它。
//
// 为什么不用插件的 node_modules：~/.dsh/profiles/node_modules/@deepseek-ai/* 是
// 容器侧 pnpm 建的绝对路径软链，指向容器内的 /usr/local/lib/node_modules/...，
// 宿主 macOS 上并不存在，`import` 插件包在宿主必然 ERR_MODULE_NOT_FOUND。
// 因此本脚本只用 node 内置模块，自己复刻信封的 AAD 与解密（算法同步自
// dsh-workbuddy-connect 0.6.0 的 desktop-credential-protection，已在 5.6.x 实测）。
//
// 用法（需要 WorkBuddy 桌面 App 已安装，并已登录要导出的那个账号）：
//   node scripts/export-wb-plain.mjs              # 导出账号 1 → ~/.dsh/workbuddy/account1.info
//   node scripts/export-wb-plain.mjs --account 2  # 导出账号 2 → ~/.dsh/workbuddy/account2.info
//   node scripts/export-wb-plain.mjs --account 3  # 导出账号 3 → ~/.dsh/workbuddy/account3.info（企业版）
//   node scripts/export-wb-plain.mjs <输入.info> <输出.info>   # 显式指定路径
//
// 说明：App 同一时刻只保持一个登录，所以导账号 N 之前要先在 App 里切到账号 N。
//      企业版账号（--account 3）走的是同一个桌面文件 workbuddy-desktop.info，
//      凭据里多出 enterpriseId，插件据此自动切到企业版请求头与额度接口。
// 导入后**不需要重启**：插件是逐请求读快照文件的，凭据巡检（30 秒）会 adopt 新身份并重拉模型目录。
//
// 安全约定：本脚本只写入上面那一个输出文件（0600），
//          不删除、不修改任何其他文件，也绝不打印 token 内容。

import { createDecipheriv, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const project = resolve(here, '..');
const home = homedir();

// ── 路径解析 ────────────────────────────────────────────────────────────────
// 输出：默认写到宿主的 ~/.dsh/workbuddy/account<N>.info。该目录随 ~/.dsh 一起挂进容器
//       （→ /root/.dsh/workbuddy/），所以**不需要为凭据单独做目录映射**，也不会随容器
//       重建而丢失（塞进容器可写层的文件会在 recreate 时失效）。
//       --account 1（默认）/ 2 / 3 选择账号；也可用第 2 个位置参数显式指定输出路径。
// 输入：WorkBuddy 桌面 App 的凭据位置，与插件 darwin 分支的候选路径一致；
//       也接受 WORKBUDDY_AUTH_DIR（.env 里的同一个变量）指向的目录。
//       注意：App 同时只保持一个登录，所以「导出账号 N」需要在 App 里登录账号 N 之后跑。
const defaultIn = process.env.WORKBUDDY_AUTH_DIR
  ? join(process.env.WORKBUDDY_AUTH_DIR, 'workbuddy-desktop.info')
  : join(home, 'Library', 'Application Support', 'CodeBuddyExtension', 'Data', 'Public', 'auth', 'workbuddy-desktop.info');

const rawArgs = process.argv.slice(2);
const accountFlag = rawArgs.indexOf('--account');
let account = 1;
if (accountFlag !== -1) {
  const raw = rawArgs[accountFlag + 1];
  // 与插件变体表（workbuddy1 / workbuddy2 / workbuddy3）保持一一对应：
  // 加渠道时两边一起加，避免脚本能导出、插件却没有对应槽位。
  if (!/^[123]$/.test(raw ?? '')) {
    console.error(`--account 只接受 1、2 或 3（收到 ${JSON.stringify(raw)}）`);
    process.exit(2);
  }
  account = Number(raw);
  rawArgs.splice(accountFlag, 2);
}

const inPath = rawArgs[0] ?? defaultIn;
const defaultOut = join(home, '.dsh', 'workbuddy', `account${account}.info`);
const outPath = rawArgs[1] ?? defaultOut;

// WorkBuddy App 自带的 Electron。用真实 App 里的这份，才能取到与写文件时同一把
// at-rest 密钥；不要换成本机任意 electron。
const ELECTRON = process.env.WORKBUDDY_ELECTRON_BIN
  ?? '/Applications/WorkBuddy.app/Contents/MacOS/Electron';
// 在 App 的 Electron 里以纯 Node 身份跑：只有这里存在私有的 workbuddyStorage binding。
const HELPER =
  'process.stdout.write(String(process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()))';

if (process.platform !== 'darwin') {
  console.error('本脚本只能在 macOS 宿主上运行（需要 WorkBuddy App 自带的 Electron）。');
  process.exit(2);
}
if (!existsSync(ELECTRON)) {
  console.error(`找不到 WorkBuddy 的 Electron：${ELECTRON}`);
  console.error('请确认 WorkBuddy 桌面 App 已安装，或用 WORKBUDDY_ELECTRON_BIN 指定。');
  process.exit(2);
}
if (!existsSync(inPath)) {
  console.error(`找不到凭据文件：${inPath}`);
  console.error('请先在 WorkBuddy 桌面 App 里登录一次，或用参数指定输入路径。');
  process.exit(2);
}

// ── at-rest 密钥 ────────────────────────────────────────────────────────────
function atRestSecret() {
  let out;
  try {
    out = execFileSync(ELECTRON, ['-e', HELPER], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      encoding: 'utf8',
      maxBuffer: 1 << 20,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    console.error(`调用 WorkBuddy 的密钥助手失败（${ELECTRON}）：`, error.message);
    process.exit(1);
  }
  let payload;
  try {
    payload = JSON.parse(out.trim());
  } catch {
    console.error('密钥助手返回的不是 JSON，无法解析。');
    process.exit(1);
  }
  if (payload.version !== 1 || typeof payload.atRestSecretKey !== 'string') {
    console.error('密钥助手返回的字段不符合预期（version/atRestSecretKey）。');
    process.exit(1);
  }
  return payload.atRestSecretKey;
}

// ── 信封解密 ────────────────────────────────────────────────────────────────
// AAD 与密钥派生逐字节对齐 App 的 buildAuthenticatedContextAad：
//   "WB-AAD\0" | 0x01 | lp("WBEV1") | lp("sym-v1") | uint32BE(suite) | lp(keyId)
//   | 0x02 | 0x00 | 0x00
// 注意 AAD 只含 keyId 与 suite，**不含字段名**，所以可以无差别地解任意字段。
const lengthPrefixed = (value) => {
  const bytes = Buffer.from(value, 'utf8');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(bytes.length);
  return Buffer.concat([header, bytes]);
};

function aad(keyId, suite) {
  const suiteBytes = Buffer.allocUnsafe(4);
  suiteBytes.writeUInt32BE(suite);
  return Buffer.concat([
    Buffer.from('WB-AAD\0', 'ascii'),
    Buffer.from([1]),
    lengthPrefixed('WBEV1'),
    lengthPrefixed('sym-v1'),
    suiteBytes,
    lengthPrefixed(keyId),
    Buffer.from([2]),
    Buffer.from([0]),
    Buffer.from([0]),
  ]);
}

function openEnvelope(key, wrapped) {
  const envelope = JSON.parse(Buffer.from(wrapped.envelope, 'base64').toString('utf8'));
  if (envelope.suite !== 1) {
    throw new Error(`不支持的信封 suite=${envelope.suite}（只实现了凭据字段的 suite 1）`);
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'base64'), {
    authTagLength: 16,
  });
  decipher.setAAD(aad(envelope.keyId, envelope.suite));
  decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

const isEnvelope = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value) && value.$wbEncrypted === 1;

/** 深度遍历文档，把每个信封原位换成它的明文字符串。 */
function unseal(node, key, path = '', opened = []) {
  if (Array.isArray(node)) return node.map((value, index) => unseal(value, key, `${path}[${index}]`, opened));
  if (node !== null && typeof node === 'object') {
    if (isEnvelope(node)) {
      let text;
      try {
        text = openEnvelope(key, node);
      } catch (error) {
        throw new Error(`字段 ${path} 解封失败（keyId=${node.envelope?.keyId ?? '?'}）：${error.message}`);
      }
      opened.push(path);
      return text;
    }
    const out = {};
    for (const [field, value] of Object.entries(node)) {
      out[field] = unseal(value, key, path ? `${path}.${field}` : field, opened);
    }
    return out;
  }
  return node;
}

// ── 主流程 ──────────────────────────────────────────────────────────────────
const rawText = readFileSync(inPath, 'utf8');
let document;
try {
  document = JSON.parse(rawText);
} catch {
  console.error(`${inPath} 不是合法 JSON。`);
  process.exit(1);
}

const envelopeCount = (node) => {
  if (Array.isArray(node)) return node.reduce((sum, value) => sum + envelopeCount(value), 0);
  if (node !== null && typeof node === 'object') {
    if (isEnvelope(node)) return 1;
    return Object.values(node).reduce((sum, value) => sum + envelopeCount(value), 0);
  }
  return 0;
};

const total = envelopeCount(document);
const opened = [];
let plain;
if (total === 0) {
  // 已经在明文状态（旧版本 App，或上次已经解过一次）——直接透传，不退化为报错。
  console.log(`输入已是明文（0 个信封），直接复制。`);
  plain = document;
} else {
  console.log(`输入含 ${total} 个加密信封，使用 ${ELECTRON} 取 at-rest 密钥 …`);
  const key = createHash('sha256').update(atRestSecret(), 'utf8').digest();
  plain = unseal(document, key, '', opened);
  for (const path of opened) console.log(`  已解封 ${path}`);
  if (opened.length !== total) {
    console.error(`只解出 ${opened.length}/${total} 个信封，拒绝写出半成品。`);
    process.exit(1);
  }
}

// 落盘前自检：必须让插件的 parseWorkBuddyAuth 能取到 accessToken。
// 插件对"文件存在但读不到 token"是静默判未登录的，所以这里主动拦一道。
const auth = plain.auth ?? plain;
if (typeof auth.accessToken !== 'string' || auth.accessToken === '') {
  console.error('解封结果里 auth.accessToken 不是非空字符串——插件会把它当成未登录，拒绝写出。');
  process.exit(1);
}

writeFileSync(outPath, JSON.stringify(plain, null, 2) + '\n');
chmodSync(outPath, 0o600);

const ms = (value) => (typeof value === 'number' && value > 0 ? new Date(value).toISOString() : '-');
console.log(`已导出明文凭据 -> ${outPath}`);
console.log(`  形状  : ${plain.auth ? '{"auth":{...},"account":{...}}（嵌套）' : '{"accessToken":...}（扁平）'}`);
console.log(`  uid   : ${plain.account?.uid ?? auth.uid ?? '-'}`);
console.log(`  domain: ${auth.domain ?? '-'}`);
console.log(`  token : 长度 ${auth.accessToken.length}（不打印内容）`);
console.log(`  有效期: ${ms(auth.expiresAt)}`);
console.log(`  可续期至: ${ms(auth.refreshExpiresAt)}`);
console.log(`下一步：刷新 dsh 界面即可（插件逐请求读该文件，最多 30 秒生效，不用重启容器）。`);
