// 只比较路径。请求方法常由通用组件、客户端封装或变量决定，静态扫描无法可靠识别。
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const allow = JSON.parse(readFileSync(new URL("api-parity-allow.json", import.meta.url), "utf8"));

function collect(dir, extensions, web) {
  const paths = new Set();
  for (const file of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!file.isFile() || !extensions.test(file.name)) continue;
    const source = readFileSync(join(file.parentPath, file.name), "utf8");
    const bindings = new Map();
    for (const line of source.split("\n")) {
      if (/^\s*(?:\/\/|\/\*|\*)/.test(line)) continue;
      const binding = line.match(/\b(?:const|let)\s+(\w+)\s*=\s*(?:format!\(\s*)?["'`]\/api\//)?.[1];
      // 也识别 `${base}/download` 和 format!("{base}/refresh") 这类路径后缀。
      const candidates = line.matchAll(/["'`]((?:\/api\/|\$?\{\w+\}\/)(?:\$\{[^{}]*\}|[^"'`?])*)(?=[?"'`])/g);
      for (const [, raw] of candidates) {
        const full = raw.replace(/^\$?\{(\w+)\}(?=\/)/, (match, name) => bindings.get(name) ?? match);
        const path = web
          ? full.replace(/\$\{[^{}]*\}/g, "{}")
          : full.replace(/\{[^{}]*\}/g, "{}");
        if (!/^\/api\/(?:[\w-]+|\{\})(?:\/(?:[\w-]+|\{\}))*$/.test(path)) continue;
        if (binding && raw.startsWith("/api/")) bindings.set(binding, path);
        paths.add(path);
      }
    }
  }
  return paths;
}

const web = collect(join(root, "web/src"), /\.tsx?$/, true);
const cli = collect(join(root, "crates/cli/src"), /\.rs$/, false);
const covered = [...web].filter((path) => cli.has(path));
const missing = [...web].filter((path) => !cli.has(path) && !Object.hasOwn(allow, path)).sort();
const stale = Object.keys(allow).filter((path) => cli.has(path) || !web.has(path)).sort();
for (const path of missing) console.error(`CLI 缺少接口：${path}`);
for (const path of stale) console.error(`白名单可以删掉：${path}`);
if (missing.length || stale.length) {
  process.exitCode = 1;
} else {
  console.log(`页面用到 ${web.size} 个接口，CLI 覆盖 ${covered.length} 个，白名单 ${Object.keys(allow).length} 个`);
}
