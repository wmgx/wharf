import assert from "node:assert/strict";
import test from "node:test";
import { hopBetween } from "../src/components/hop.ts";
import { parseUpstream } from "../src/pages/server/format.ts";

test("跨机链路显示实际直连或反向隧道", () => {
  const status = { servers: [{ name: "s2", private_addr: { network: "lan" } }] };
  assert.equal(hopBetween("s1", "s1", undefined, undefined, status).kind, "local");
  assert.deepEqual(hopBetween("s1", "s2", "auto", undefined, status), { kind: "direct", text: "直连 · 明文", plain: true });
  assert.equal(hopBetween("s1", "s2", "tunnel", undefined, status).kind, "tunnel");
  assert.equal(hopBetween("s1", "s2", "auto", undefined, status, { reach: [{ from: "s1", to: "s2", ok: false }] }).kind, "tunnel");
});

test("直连地址保留 IPv6 端口", () => {
  assert.deepEqual(parseUpstream("127.0.0.1:7700"), { host: "127.0.0.1", port: "7700" });
  assert.deepEqual(parseUpstream("http://[::1]:7700/health"), { host: "::1", port: "7700" });
});
