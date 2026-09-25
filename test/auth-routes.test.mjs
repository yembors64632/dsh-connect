import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

/**
 * 路由层集成测试：mock 出 webServer/settings，直接调 registerHubRoutes，
 * 在内存里过一遍 /auth 的渠道 CRUD —— 不依赖容器、不打真实上游。
 *
 * probeAll 会扇出到 127.0.0.1:<port> 的渠道路由，测试进程里必然连不上；
 * 这正好落在「插件未响应 → unavailable」的降级分支上，不影响要断言的字段。
 */

const PORT = "39999";

function withTempHome(fn) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "dsh-connect-routes-"));
    const env = { ...process.env, DSH_HOME: dir, DSH_PORT: PORT };
    const previous = { DSH_HOME: process.env.DSH_HOME, DSH_PORT: process.env.DSH_PORT };
    process.env.DSH_HOME = dir;
    process.env.DSH_PORT = PORT;
    try {
      await fn(dir, env);
    } finally {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

const registry = await import("../lib/channel-registry.js");

/** 最小 mock：路由表 + settings 存储 + logger。 */
function makeHarness() {
  const routes = new Map();
  const store = { dshconnect: { autoCheckin: true, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] } };
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    effect(fn) {
      // Cordis 会立即执行 effect 来注册资源；测试桩也要这样做，dispose 留给进程退出。
      fn();
    },
    webServer: {
      register({ kind, path, handler }) {
        assert.equal(kind, "exact");
        routes.set(path, handler);
        return () => routes.delete(path);
      },
    },
  };
  const settingsApi = {
    async update(ns, patch) {
      store[ns] = { ...store[ns], ...patch };
    },
    async section(ns) {
      return store[ns];
    },
  };
  return { ctx, routes, settingsApi, store };
}

/** 把 Node 的 IncomingMessage/ServerResponse mock 到路由 handler 能用的程度。 */
function call(routes, path, { method = "GET", body, timeoutMs = 15000 } = {}) {
  const handler = routes.get(path);
  assert.ok(handler !== undefined, `路由未注册：${path}`);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`路由处理超时：${method} ${path}`)), timeoutMs);
    const finish = (result) => {
      clearTimeout(timer);
      resolve(result);
    };
    const chunks = body === undefined ? [] : [Buffer.from(body)];
    const headers = body === undefined
      ? { host: `127.0.0.1:${PORT}` }
      : { host: `127.0.0.1:${PORT}`, origin: `http://127.0.0.1:${PORT}`, "content-type": "application/json" };
    const req = {
      method,
      url: path,
      headers,
      on(event, listener) {
        if (event === "data" && chunks.length > 0) listener(chunks.shift());
        if (event === "end") listener();
      },
      destroy() {},
    };
    let payload = "";
    const res = {
      statusCode: 0,
      writeHead(code) {
        this.statusCode = code;
      },
      end(text) {
        payload = text ?? "";
        finish({ status: this.statusCode, json: safeJson(payload) });
      },
    };
    Promise.resolve(handler(req, res)).catch((error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

test("渠道 CRUD：create → GET 可见 → update 改名 → delete 连凭据一起删", withTempHome(async (dir) => {
  const { registerHubRoutes } = await import("../lib/panel.js");
  const { ctx, routes, settingsApi } = makeHarness();
  const deps = {
    prefs: () => ({ autoCheckin: true, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    channels: () => registry.allChannels(),
    settingsApi: () => settingsApi,
    onModelsChanged: () => {},
  };
  registerHubRoutes(ctx, deps);

  // —— create：新槽位进注册表，面板立即可见 ——
  const created = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "create", kind: "workbuddy", id: "workbuddy9", displayName: "九号账号" }),
  });
  assert.equal(created.status, 200);
  assert.equal(created.json.created.id, "workbuddy9");
  assert.equal(created.json.restartRequired, true);
  assert.deepEqual(
    JSON.parse(readFileSync(join(dir, "connect-channels.json"), "utf8")).channels.map((entry) => entry.id),
    ["workbuddy1", "workbuddy2", "workbuddy3", "trae", "qoder", "workbuddy9"],
  );

  const listed = await call(routes, "/plugins/dsh-connect/auth");
  const ids = listed.json.channels.map((channel) => channel.id);
  assert.ok(ids.includes("workbuddy9"), "新槽位应出现在 /auth 列表");
  assert.equal(listed.json.nextWorkbuddySlot, 4, "下一个空闲编号应跳过 9");
  assert.equal(listed.json.channels.find((channel) => channel.id === "workbuddy9").kind, "workbuddy");

  // —— create 防护：重复 id / 坏 id / 单例 kind 的错 id 都要被拒 ——
  const dup = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "create", kind: "workbuddy", id: "workbuddy9" }),
  });
  assert.equal(dup.status, 409);
  const badId = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "create", kind: "workbuddy", id: "MyChannel" }),
  });
  assert.equal(badId.status, 400);
  const singleton = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "create", kind: "qoder", id: "qoder2" }),
  });
  assert.equal(singleton.status, 400);

  // —— update：改名写注册表 ——
  const renamed = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "update", channel: "workbuddy9", displayName: "九号（改名）" }),
  });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.json.updated.displayName, "九号（改名）");

  // —— 凭据粘贴：给新槽位写一份合法 workbuddy 快照（原子写后文件存在）——
  const saved = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({
      channel: "workbuddy9",
      secret: JSON.stringify({ auth: { accessToken: "at-token-9" }, account: { uid: "u9", nickname: "九号" } }),
    }),
  });
  assert.equal(saved.status, 200);
  const credentialPath = join(dir, "connect-auth", "workbuddy9.json");
  assert.ok(existsSync(credentialPath), "凭据应落到 connect-auth/workbuddy9.json");

  // —— delete：凭据文件 + 注册表条目一起消失 ——
  const removed = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "delete", channel: "workbuddy9" }),
  });
  assert.equal(removed.status, 200);
  assert.ok(!existsSync(credentialPath), "凭据文件应被删除");
  const finalDoc = JSON.parse(readFileSync(join(dir, "connect-channels.json"), "utf8"));
  assert.ok(!finalDoc.channels.some((entry) => entry.id === "workbuddy9"), "注册表条目应被删除");
}));

test("回环守卫：非回环 Host 一律 403", withTempHome(async () => {
  const { registerHubRoutes } = await import("../lib/panel.js");
  const { ctx, routes, settingsApi } = makeHarness();
  registerHubRoutes(ctx, {
    prefs: () => ({ autoCheckin: true, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    channels: () => registry.allChannels(),
    settingsApi: () => settingsApi,
  });
  const handler = routes.get("/plugins/dsh-connect/auth");
  await new Promise((resolve) => {
    const res = { statusCode: 0, writeHead(code) { this.statusCode = code; }, end(text) { assert.equal(this.statusCode, 403); resolve(); } };
    void handler({ method: "GET", url: "/plugins/dsh-connect/auth", headers: { host: "evil.example.com" } }, res);
  });
}));

test("create 遇 connect-auth 同名残留凭据时 409 拒绝", withTempHome(async (dir) => {
  const { registerHubRoutes } = await import("../lib/panel.js");
  const { ctx, routes, settingsApi } = makeHarness();
  registerHubRoutes(ctx, {
    prefs: () => ({ autoCheckin: true, showDockButton: true, hiddenChannels: [], disabledChannels: [], disabledModels: [] }),
    channels: () => registry.allChannels(),
    settingsApi: () => settingsApi,
  });
  registry.writeRegistry(registry.DEFAULT_REGISTRY_CHANNELS);
  // 手工放置一个游离凭据（模拟旧文件残留）
  const { mkdirSync, writeFileSync: wf } = await import("node:fs");
  mkdirSync(join(dir, "connect-auth"), { recursive: true });
  wf(join(dir, "connect-auth", "workbuddy9.json"), "{}");
  const created = await call(routes, "/plugins/dsh-connect/auth", {
    method: "POST",
    body: JSON.stringify({ op: "create", kind: "workbuddy", id: "workbuddy9", displayName: "九号" }),
  });
  assert.equal(created.status, 409);
  assert.equal(created.json.error, "stray-credential");
  const finalDoc = JSON.parse(readFileSync(join(dir, "connect-channels.json"), "utf8"));
  assert.ok(!finalDoc.channels.some((entry) => entry.id === "workbuddy9"), "注册表不应写入被拒条目");
}));
