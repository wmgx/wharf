import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { createServer } from "vite";

test("环境变量只剥一层成对引号，Compose 和表单保留 UDP", async () => {
  const vite = await createServer({
    configFile: false,
    appType: "custom",
    resolve: { alias: { "@": resolve("src") } },
    server: { middlewareMode: true, hmr: false, watch: null },
  });
  try {
    const { parseEnv, portsFor } = await vite.ssrLoadModule("/src/components/fields.tsx");
    const { parseCompose, composePorts } = await vite.ssrLoadModule("/src/components/compose.tsx");
    assert.deepEqual(parseEnv('ARGS="--foo" "--bar"\nLIST="a","b"\nVALUE="abc"'), {
      ARGS: '"--foo" "--bar"', LIST: '"a","b"', VALUE: "abc",
    });
    const text = "services:\n  app:\n    ports:\n      - 11553:53/tcp\n      - 11553:53/udp";
    const ports = portsFor(composePorts(parseCompose(text)), true);
    assert.deepEqual(ports.map((p) => [p.host, p.udp]), [[11553, undefined], [11553, true]]);
    assert.notEqual(ports[0].name, ports[1].name);
  } finally {
    await vite.close();
  }
});
