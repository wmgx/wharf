import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
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

test("shared-only services hide backup settings", async () => {
  const vite = await createServer({
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
  });
  try {
    const { ServiceChecks } = await vite.ssrLoadModule("/src/pages/service/checks.tsx");
    const { ActionsProvider } = await vite.ssrLoadModule("/src/components/actions.tsx");
    const { StatusContext } = await vite.ssrLoadModule("/src/status.ts");
    const render = (volumes) => renderToStaticMarkup(
      h(MemoryRouter, null,
        h(StatusContext.Provider, { value: { status: { servers: [{ name: "s2", joined: true }] } } },
          h(ActionsProvider, null,
            h(ServiceChecks, { kind: "backup", svc: { name: "reader", spec: {
              server: "s1", source: { image: "nginx:1" }, volumes,
            } } }),
          ),
        ),
      ),
    );
    const shared = { name: "shared", target: "/shared", from_service: "photos:data" };
    assert.doesNotMatch(render([shared]), /id="service-backup"|这个服务没有数据卷/);
    assert.match(render([shared, { name: "data", target: "/data" }]), /id="service-backup"/);
  } finally {
    await vite.close();
  }
});
