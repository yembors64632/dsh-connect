import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function withTempHome(fn) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), "dsh-connect-empty-"));
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

test("显式空注册表 + 空 apply 兜底：不留 undefined 变体", withTempHome(async () => {
  registry.writeRegistry([]);
  const doc = registry.readRegistry();
  assert.equal(doc.explicit, true);
  assert.equal(doc.channels.length, 0);
  const variants = await import("../lib/providers/workbuddy/variants-CnrmSn0Q.js");
  assert.equal(variants.r.length, 0);
  assert.equal(variants.n, undefined);
  assert.equal(variants.t, undefined);
  assert.equal(variants.i("workbuddy1"), undefined);
}));
