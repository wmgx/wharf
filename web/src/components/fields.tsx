import type { PortSpec } from "../types";

/** `KEY=VALUE` 一行一个，和 .env 一样写法。 */
export function parseEnv(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i <= 0) continue;
    env[line.slice(0, i).trim()] = line.slice(i + 1);
  }
  return env;
}

export function formatEnv(env?: Record<string, string>): string {
  return Object.entries(env ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
}

/** 名称规则和后端一致：小写字母、数字、减号。 */
export function toName(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

/** `ghcr.io/foo/bar-app:1.2` → `bar-app` */
export function nameFromImage(image: string): string {
  const last = image.split("@")[0].split("/").pop() ?? "";
  return toName(last.split(":")[0]);
}

export function PortsEditor({ ports, onChange }: { ports: PortSpec[]; onChange: (p: PortSpec[]) => void }) {
  const set = (i: number, patch: Partial<PortSpec>) => onChange(ports.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {ports.map((p, i) => (
        <div className="row" key={i}>
          <input type="text" placeholder="名称，例如 http" value={p.name} onChange={(e) => set(i, { name: toName(e.target.value) })} />
          <input
            type="number"
            placeholder="容器端口"
            value={p.port || ""}
            onChange={(e) => set(i, { port: Number(e.target.value) })}
          />
          <button type="button" className="btn small ghost fixed" onClick={() => onChange(ports.filter((_, j) => j !== i))}>
            移除
          </button>
        </div>
      ))}
      <div>
        <button type="button" className="btn small" onClick={() => onChange([...ports, { name: ports.length ? `p${ports.length + 1}` : "http", port: 0 }])}>
          ＋ 端口
        </button>
      </div>
    </div>
  );
}
