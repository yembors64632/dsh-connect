import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function withTempHome(fn) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "dsh-connect-orphans-"));
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

test("无注册表时凭据孤儿槽位（旧版 4/5/6）自动收纳进默认表", withTempHome((dir) => {
  const authDir = join(dir, "connect-auth");
  mkdirSync(authDir, { recursive: true });
  // 旧版固定槽位 4 有凭据、5/6 没有 → 只应收纳 workbuddy4
  writeFileSync(join(authDir, "workbuddy4.json"), "{}");
  writeFileSync(join(authDir, "trae.json"), "{}");
  const doc = registry.readRegistry();
  assert.equal(doc.explicit, false);
  const ids = doc.channels.map((c) => c.id);
  assert.ok(ids.includes("workbuddy4"), "有凭据的孤儿槽位应被收纳");
  assert.ok(!ids.includes("workbuddy5"), "无凭据的空槽位不应出现");
  assert.equal(ids.filter((id) => id.startsWith("workbuddy")).length, 4);
  // 排序：workbuddy1..4 连续，后接 trae/qoder
  assert.deepEqual(ids, ["workbuddy1", "workbuddy2", "workbuddy3", "workbuddy4", "trae", "qoder"]);
}));

test("显式注册表存在时孤儿收纳不介入", withTempHome((dir) => {
  const authDir = join(dir, "connect-auth");
  mkdirSync(authDir, { recursive: true });
  writeFileSync(join(authDir, "workbuddy9.json"), "{}");
  registry.writeRegistry([{ id: "workbuddy1", kind: "workbuddy", displayName: "一号" }]);
  const doc = registry.readRegistry();
  assert.deepEqual(doc.channels.map((c) => c.id), ["workbuddy1"]);
}));
