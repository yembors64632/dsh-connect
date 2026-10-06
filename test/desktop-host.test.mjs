import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

/**
 * 桌面宿主（`dsh web --port <n>`）下的三处回归。
 *
 * 三处都是**容器部署看不出、桌面部署必踩**的差异：
 *
 * 1. 扇出基址只认 `DSH_PORT`（compose 钉死 3079）→ 桌面宿主端口是启动参数，
 *    面板全部渠道齐刷刷 `fetch failed`（渠道本身健康）；
 * 2. `slotConfigured` 只看 `connect-auth/` → 扫码登录写的是插件自有副本
 *    `$DSH_HOME/.<id>-auth.json`，纯扫码进来的账号被当空闲槽位藏起来、还不参与一键签到；
 * 3. 单渠道签到路由按**启动快照**注册 → "先建槽位 → 重启 → 再扫码"的新槽位
 *    没有自己的 checkin 路由，行内「签到」按钮 405（一键签到却正常）。
 *
 * 测试进程里扇出必然连不上真实端口（没有真渠道在听），所以断言落在
 * **路由存在性** 与 **请求打向哪个端口** 上 —— 后者用 mock fetch 抓。
 */

const PORT = "19387";

function withTempHome(fn) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "dsh-connect-desktop-"));
    const previous = {
      DSH_HOME: process.env.DSH_HOME,
      DSH_PORT: process.env.DSH_PORT,
      DSH_WEB_URL: process.env.DSH_WEB_URL,
    };
    process.env.DSH_HOME = dir;
    // 桌面宿主的形状：**没有** DSH_PORT，只有 GUI 地址。
    delete process.env.DSH_PORT;
    process.env.DSH_WEB_URL = `http://127.0.0.1:${PORT}`;
    try {
      await fn(dir);
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

/** 最小 mock：路由表 + settings + logger（与 auth-routes.test.mjs 同形，另支持 prefix）。 */
function makeHarness() {
  const routes = new Map();
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    effect(fn) {
      fn();
    },
    webServer: {
      register({ kind = "exact", path, handler }) {
        routes.set(`${kind} ${path}`, handler);
        return () => routes.delete(`${kind} ${path}`);
      },
    },
  };
  const settingsApi = { async update() {}, async section() { return undefined; } };
  return { ctx, routes, settingsApi };
}

/**
 * 按 webServer 的真实语义取 handler：exact 优先，其次最长前缀命中。
 *
 * 之所以要模拟这一层：`/checkin/<id>` 现在是 prefix 路由，测试必须像宿主那样
 * 用完整 pathname 去匹配，否则测不到真实行为。
 */
function resolveRoute(routes, pathname) {
  const exact = routes.get(`exact ${pathname}`);
  if (exact !== undefined) return exact;
  let best;
  let bestLength = -1;
  for (const [key, handler] of routes) {
    if (!key.startsWith("prefix ")) continue;
    const prefix = key.slice("prefix ".length);
    if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
    if (prefix.length > bestLength) {
      best = handler;
      bestLength = prefix.length;
    }
  }
  return best;
}

/** 把 mock 请求打到某条路由上。 */
function call(routes, path, { method = "GET", host = `127.0.0.1:${PORT}`, body } = {}) {
  const handler = resolveRoute(routes, path);
  assert.ok(handler !== undefined, `路由未注册：${path}`);
  return new Promise((resolve, reject) => {
    const chunks = body === undefined ? [] : [Buffer.from(body)];
    const req = {
      method,
      url: path,
      headers: { host, origin: `http://${host}` },
      on(event, listener) {
        if (event === "data" && chunks.length > 0) listener(chunks.shift());
        if (event === "end") listener();
      },
      destroy() {},
    };
    const res = {
      statusCode: 0,
      writeHead(code) {
        this.statusCode = code;
      },
      end(text) {
        resolve({ status: this.statusCode, text: text ?? "" });
      },
    };
    Promise.resolve(handler(req, res)).catch(reject);
  });
}

const registry = await import("../lib/channel-registry.js");

test("扇出基址跟随请求 Host：桌面宿主没有 DSH_PORT 也要打对端口", withTempHome(async () => {
  const { loopbackBaseFrom } = await import("../lib/shared/http.js");

  // 桌面宿主的真实形状：进来的是 `127.0.0.1:19387`。
  assert.equal(loopbackBaseFrom(`127.0.0.1:${PORT}`), `http://127.0.0.1:${PORT}`);
  assert.equal(loopbackBaseFrom("[::1]:3088"), "http://127.0.0.1:3088");
  assert.equal(loopbackBaseFrom("localhost:3079"), "http://127.0.0.1:3079");

  // 非回环 / 畸形一概不给基址 —— 绝不能拿外部输入当扇出目标。
  assert.equal(loopbackBaseFrom("evil.example.com:443"), undefined);
  assert.equal(loopbackBaseFrom("127.0.0.1"), undefined);
  assert.equal(loopbackBaseFrom("127.0.0.1:abc"), undefined);
  assert.equal(loopbackBaseFrom("127.0.0.1:99999"), undefined);
  assert.equal(loopbackBaseFrom(undefined), undefined);
}));

test("没有 DSH_PORT、只有 DSH_WEB_URL 时，兜底基址取 GUI 端口", withTempHome(async (dir) => {
  const { registerHubRoutes, probeAll } = await import("../lib/panel.js");
  const { ctx, routes, settingsApi } = makeHarness();

  // 注册表里放一个**已配置**的渠道，扇出才有对象（hubChannels 会滤掉空槽位）。
  registry.writeRegistry([{ id: "trae", kind: "trae", displayName: "Trae" }]);
  mkdirSync(join(dir, "connect-auth"), { recursive: true });
  writeFileSync(join(dir, "connect-auth", "trae.json"), "{}");

  registerHubRoutes(ctx, {
    prefs: () => ({ autoCheckin: false, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    channels: () => registry.allChannels(),
    settingsApi: () => settingsApi,
  });

  // 记下扇出真正打向哪个端口。
  const realFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url) => {
    seen.push(String(url));
    throw new Error("connect ECONNREFUSED");
  };
  try {
    // 走「无请求上下文」的兜底路径（直接调 probeAll）。
    await probeAll([registry.allChannels()[0]]);
    assert.ok(seen.length > 0, "应当发生了一次扇出");
    assert.ok(
      seen.every((url) => url.startsWith(`http://127.0.0.1:${PORT}/`)),
      `扇出应打到 DSH_WEB_URL 的端口，实际：${seen.join(", ")}`,
    );
  } finally {
    globalThis.fetch = realFetch;
  }

  // 带请求的路由则用请求自身的 Host。
  const seen2 = [];
  globalThis.fetch = async (url) => {
    seen2.push(String(url));
    throw new Error("connect ECONNREFUSED");
  };
  try {
    const res = await call(routes, "/plugins/dsh-connect/status");
    assert.equal(res.status, 200);
    assert.ok(seen2.length > 0, "渠道页应当扇出到已配置渠道");
    assert.ok(
      seen2.every((url) => url.startsWith(`http://127.0.0.1:${PORT}/`)),
      `扇出应打请求 Host 的端口，实际：${seen2.join(", ")}`,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
}));

test("纯扫码槽位（凭据只在插件自有副本）算已配置：渠道页可见 + 参与一键签到", withTempHome(async (dir) => {
  const { registerHubRoutes, slotConfigured } = await import("../lib/panel.js");
  registry.writeRegistry([{ id: "workbuddy1", kind: "workbuddy", displayName: "扫码号" }]);

  // 扫码登录的产物：`$DSH_HOME/.workbuddy1-auth.json`（**不落** connect-auth/）。
  writeFileSync(join(dir, ".workbuddy1-auth.json"), JSON.stringify({ version: 1, credential: { accessToken: "at" } }));

  assert.equal(slotConfigured("workbuddy1"), true, "扫码来的账号必须算已配置");

  const { ctx, routes, settingsApi } = makeHarness();
  registerHubRoutes(ctx, {
    prefs: () => ({ autoCheckin: false, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    channels: () => registry.allChannels(),
    settingsApi: () => settingsApi,
  });

  // 渠道页（/status）的渠道清单应当包含它。
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("connect ECONNREFUSED");
  };
  try {
    const res = await call(routes, "/plugins/dsh-connect/status");
    assert.equal(res.status, 200);
    const ids = JSON.parse(res.text).channels.map((row) => row.id);
    assert.deepEqual(ids, ["workbuddy1"], "扫码号应出现在渠道页（原实现会被当空闲槽位藏掉）");
  } finally {
    globalThis.fetch = realFetch;
  }

  // 没凭据的槽位仍然不算已配置 —— 别把空闲槽位放进来。
  registry.writeRegistry([
    { id: "workbuddy1", kind: "workbuddy", displayName: "扫码号" },
    { id: "workbuddy2", kind: "workbuddy", displayName: "空槽位" },
  ]);
  assert.equal(slotConfigured("workbuddy2"), false);
}));

test("单渠道签到路由按注册表注册：有槽位但启动时还没扫码，行内签到也不能 405", withTempHome(async (dir) => {
  const { registerHubRoutes } = await import("../lib/panel.js");

  /**
   * 复现真实流程：**先建槽位 → 重启 → 才扫码**。
   *
   * 重启那一刻 workbuddy2 已在注册表里、但还没有任何凭据（扫码还没发生）。
   * 原实现按 `deps.channels()`（= 启动瞬间**已配置**的槽位）注册路由，
   * 于是 workbuddy2 永远拿不到自己的 `/checkin/workbuddy2` —— 等它扫码登录成功，
   * 面板那一行的「签到」按钮就一直是 405，而「一键签到」（每次现算）却正常。
   */
  registry.writeRegistry([
    { id: "workbuddy1", kind: "workbuddy", displayName: "一号" },
    { id: "workbuddy2", kind: "workbuddy", displayName: "二号" },
  ]);
  // 启动时两者都还没有凭据 —— 这正是流程的第二拍。
  const { ctx, routes, settingsApi } = makeHarness();
  const { hubChannels } = await import("../lib/panel.js");
  registerHubRoutes(ctx, {
    prefs: () => ({ autoCheckin: false, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    // 真实接线：`channels` 是**每次现算**的 hubChannels（index.js 就是这么传的）。
    channels: () => hubChannels({ includeHidden: true }),
    settingsApi: () => settingsApi,
  });

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("connect ECONNREFUSED");
  };
  try {
    // 两条路由都必须存在（原实现里两条都没有）。
    for (const id of ["workbuddy1", "workbuddy2"]) {
      const res = await call(routes, `/plugins/dsh-connect/checkin/${id}`, { method: "POST" });
      assert.equal(res.status, 200, `${id} 的行内签到路由必须存在（原实现 405）`);
      // 扇出连不上上游 → 如实降级成"这一条的结果"，绝不是 405。
      const row = JSON.parse(res.text);
      assert.equal(row.id, id);
      assert.ok(typeof row.state === "string" && row.state !== "", "应给出一个降级后的签到状态");
    }
    // 注册表里没有的 id 才回 404 —— 与"路由不存在"区分开。
    const ghost = await call(routes, "/plugins/dsh-connect/checkin/workbuddy404", { method: "POST" });
    assert.equal(ghost.status, 404);
  } finally {
    globalThis.fetch = realFetch;
  }

  // 扫码完成后（凭据落到插件自有副本），一键签到的渠道清单也要能带上它。
  writeFileSync(join(dir, ".workbuddy2-auth.json"), JSON.stringify({ version: 1, credential: { accessToken: "at2" } }));
  const seen = [];
  globalThis.fetch = async (url) => {
    seen.push(String(url));
    throw new Error("connect ECONNREFUSED");
  };
  try {
    const res = await call(routes, "/plugins/dsh-connect/checkin", { method: "POST" });
    assert.equal(res.status, 200);
    const ids = JSON.parse(res.text).results.map((row) => row.id);
    assert.ok(ids.includes("workbuddy2"), `扫码后的账号应参与一键签到，实际：${ids.join(", ")}`);
  } finally {
    globalThis.fetch = realFetch;
  }
}));
