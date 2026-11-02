import { test } from "node:test";
import assert from "node:assert/strict";
import { monitor } from "./directory-health.mjs";

test("directory outages alert once and recover once; notification failure remains retryable", async () => {
  const root = await Deno.makeTempDir(), messages = [];
  const args = { target: "test", url: "https://empty.example/config.json", state: root + "/state.json",
    notify: message => { messages.push(message); }, check: () => { throw Error("No signed guest entries"); } };
  try {
    await assert.rejects(monitor({ ...args, notify: () => { throw Error("Matrix unavailable"); } }), /Matrix unavailable/);
    await monitor(args); await monitor(args);
    assert.equal(messages.length, 1); assert.match(messages[0], /FAILED/);
    const healthy = { ...args, check: () => ({ nodes: 1, blockNumber: 42 }) };
    await monitor(healthy); await monitor(healthy);
    assert.equal(messages.length, 2); assert.match(messages[1], /RECOVERED/);
  } finally { await Deno.remove(root, { recursive: true }); }
});
