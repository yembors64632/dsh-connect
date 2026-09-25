import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

/** 每个用例独立 DSH_HOME，绝不碰真实 ~/.dsh/connect-channels.json。 */
function withTempHome(fn) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "dsh-connect-registry-"));
    const previous = process.env.DSH_HOME;
    process.env.DSH_HOME = dir;
    try {
      await fn(dir);
    } finally {
      if (previous === undefined) delete process.env.DSH_HOME;
      else process.env.DSH_HOME = previous;
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

const registry = await import("../lib/channel-registry.js");

test("注册表不存在时回落 5 条内置默认", withTempHome(() => {
  const doc = registry.readRegistry();
  assert.equal(doc.explicit, false);
  assert.deepEqual(doc.channels.map((entry) => entry.id), ["workbuddy1", "workbuddy2", "workbuddy3", "trae", "qoder"]);
}));

test("写注册表后按原顺序读回，空数组也被尊重", withTempHome((dir) => {
  const channels = [
    { id: "workbuddy1", kind: "workbuddy", displayName: "主账号" },
    { id: "workbuddy17", kind: "workbuddy", displayName: "第 17 个账号" },
  ];
  registry.writeRegistry(channels);
  const doc = registry.readRegistry();
  assert.equal(doc.explicit, true);
  assert.deepEqual(doc.channels, channels);
  assert.equal(JSON.parse(readFileSync(join(dir, "connect-channels.json"), "utf8")).version, 1);
  registry.writeRegistry([]);
  assert.deepEqual(registry.readRegistry(), { channels: [], explicit: true });
}));

test("坏条目与重复 id 被过滤，合法条目保留", withTempHome((dir) => {
  registry.writeRegistry([
    { id: "WorkBuddy1", kind: "workbuddy", displayName: "坏 id" },
    { id: "workbuddy8", kind: "workbuddy", displayName: "八号" },
    { id: "workbuddy8", kind: "workbuddy", displayName: "重复" },
    { id: "qoder", kind: "qoder", displayName: "Qoder CN" },
  ]);
  assert.deepEqual(registry.readRegistry().channels.map((entry) => entry.displayName), ["八号", "Qoder CN"]);
}));

test("workbuddy 条目正确派生 provider、路由与凭据提示", withTempHome(() => {
  registry.writeRegistry([{ id: "workbuddy42", kind: "workbuddy", displayName: "42 号" }]);
  const [channel] = registry.allChannels();
  assert.deepEqual(channel, {
    id: "workbuddy42",
    displayName: "42 号",
    provider: "workbuddy42",
    kind: "workbuddy",
    statusPath: "/plugins/dsh-workbuddy-connect/42/status",
    checkinPath: "/plugins/dsh-workbuddy-connect/42/checkin",
    credentialHint: "connect-auth/workbuddy42.json",
  });
}));

test("nextWorkbuddySlot 返回最小空闲编号", withTempHome(() => {
  registry.writeRegistry([
    { id: "workbuddy1", kind: "workbuddy", displayName: "一号" },
    { id: "workbuddy3", kind: "workbuddy", displayName: "三号" },
  ]);
  assert.equal(registry.nextWorkbuddySlot(), 2);
}));

test("version 不匹配或缺失的注册表整份回落默认+孤儿收纳", withTempHome((dir) => {
  const wf = writeFileSync;
  wf(join(dir, "connect-channels.json"), JSON.stringify({ version: 999, channels: [{ id: "workbuddy1", kind: "workbuddy", displayName: "未来版" }] }));
  const doc = registry.readRegistry();
  assert.equal(doc.explicit, false);
  assert.deepEqual(doc.channels.map((entry) => entry.id), ["workbuddy1", "workbuddy2", "workbuddy3", "trae", "qoder"]);
  wf(join(dir, "connect-channels.json"), JSON.stringify({ channels: [] })); // 无 version 字段
  const doc2 = registry.readRegistry();
  assert.equal(doc2.explicit, false);
  assert.equal(doc2.channels.length, 5);
}));

test("未知 kind / 单例错配 id / workbuddy 编号形状在读取侧即被过滤", withTempHome(() => {
  registry.writeRegistry([
    { id: "workbuddy1", kind: "claude", displayName: "未知 kind" },
    { id: "trae2", kind: "trae", displayName: "单例错配" },
    { id: "workbuddy01", kind: "workbuddy", displayName: "前导零" },
    { id: "workbuddy7", kind: "workbuddy", displayName: "合法" },
    { id: "qoder", kind: "qoder", displayName: "Qoder" },
  ]);
  const ids = registry.readRegistry().channels.map((entry) => entry.id);
  assert.deepEqual(ids, ["workbuddy7", "qoder"]);
}));
