import { Link } from "react-router-dom";
import { useRef } from "react";
import type { ServerView } from "@/types";
import { cn } from "@/lib/utils";

export interface ComposePort {
  service: string;
  host: number;
  container: number;
}

export interface ComposeVolume {
  service: string;
  source: string;
  target: string;
}

export interface ComposeInfo {
  images: string[];
  ports: ComposePort[];
  volumes: ComposeVolume[];
}

const indentOf = (line: string) => line.length - line.trimStart().length;
const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");

/** `127.0.0.1:8080:80`、`8080:80/tcp`、`80` → 宿主机端口和容器端口；只有容器端口时没有宿主机端口。 */
function parsePort(text: string): { host?: number; container: number } | null {
  const parts = unquote(text).replace(/\/(tcp|udp)$/, "").split(":");
  const nums = parts.slice(-2).map(Number);
  if (nums.some((n) => !Number.isInteger(n) || n <= 0 || n > 65535)) return null;
  return parts.length === 1 ? { container: nums[0] } : { host: nums[0], container: nums[1] };
}

/**
 * 按行粗略读 compose：只认 services 下每个服务的 image、ports、volumes 短写法和 published/target 长写法。
 * 只用来给表单预填和提示，真正的校验在控制面。
 */
export function parseCompose(text: string): ComposeInfo {
  const info: ComposeInfo = { images: [], ports: [], volumes: [] };
  let svcIndent = -1;
  let service = "";
  let list: "ports" | "volumes" | null = null;
  let listIndent = -1;
  let pending: { published?: number; target?: number; source?: string; mount?: string } | null = null;
  const flush = () => {
    if (!pending) return;
    if (list === "ports" && pending.published && pending.target) info.ports.push({ service, host: pending.published, container: pending.target });
    if (list === "volumes" && pending.source && pending.mount) info.volumes.push({ service, source: pending.source, target: pending.mount });
    pending = null;
  };
  let inServices = false;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s+#.*$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const indent = indentOf(line);
    const t = line.trim();
    if (indent === 0) {
      flush();
      inServices = t === "services:";
      svcIndent = -1;
      service = "";
      list = null;
      continue;
    }
    if (!inServices) continue;
    if (svcIndent < 0) svcIndent = indent;
    if (indent === svcIndent) {
      flush();
      service = t.replace(/:$/, "");
      list = null;
      continue;
    }
    if (list && indent <= listIndent) {
      flush();
      list = null;
    }
    if (!list) {
      const m = /^(image|ports|volumes):\s*(.*)$/.exec(t);
      if (!m) continue;
      if (m[1] === "image" && m[2]) info.images.push(unquote(m[2]));
      if (m[1] !== "image") {
        list = m[1] as "ports" | "volumes";
        listIndent = indent;
      }
      continue;
    }
    const item = t.startsWith("- ") ? t.slice(2).trim() : null;
    if (item !== null) flush();
    const kv = /^([a-z_]+):\s*(.*)$/.exec(item ?? t);
    if (kv) {
      pending ??= {};
      const v = unquote(kv[2]);
      if (kv[1] === "published") pending.published = Number(v);
      if (kv[1] === "target") (list === "ports" ? (pending.target = Number(v)) : (pending.mount = v));
      if (kv[1] === "source") pending.source = v;
      continue;
    }
    if (item === null) continue;
    if (list === "ports") {
      const p = parsePort(item);
      if (p?.host) info.ports.push({ service, host: p.host, container: p.container });
    } else {
      const parts = unquote(item).split(":");
      if (parts.length >= 2) info.volumes.push({ service, source: parts[0], target: parts[1] });
    }
  }
  flush();
  return info;
}

/** 同 agent 的 split_image：第一段带点、冒号或是 localhost 时是仓库地址，否则是 docker.io。 */
export function registryOf(image: string): string {
  const first = image.trim().split("/")[0] ?? "";
  return image.includes("/") && (first.includes(".") || first.includes(":") || first === "localhost") ? first : "docker.io";
}

/** 告诉用户这台服务器拉这些镜像会走哪些镜像源，没配就给设置入口。 */
export function MirrorHint({ server, images }: { server?: ServerView; images: string[] }) {
  if (!server) return null;
  const registries = [...new Set(images.filter((i) => i.trim()).map(registryOf))];
  if (!registries.length) return null;
  const settings = server.settings as { registry_mirrors?: Record<string, string[]>; mirrors_only?: boolean };
  const mirrors = settings.registry_mirrors ?? {};
  return (
    <div className="grid gap-0.5 text-xs text-muted-foreground">
      {registries.map((r) => {
        const list = mirrors[r] ?? [];
        const order = [...list, ...(list.length && settings.mirrors_only ? [] : [`${r}（原地址）`])];
        return (
          <div key={r}>
            {server.name} 拉取 {r} 的镜像：{list.length ? order.join(" → ") : `没有配置镜像源，直接从 ${r} 拉`}
          </div>
        );
      })}
      <Link to={`/servers/${server.name}?tab=settings`} target="_blank" className="w-fit underline underline-offset-2">
        修改 {server.name} 的镜像源
      </Link>
    </div>
  );
}

const TOKEN =
  /(#.*$)|^(\s*-?\s*)([\w.-]+)(:)(?=\s|$)|("[^"]*"|'[^']*')|(\b\d+(?:\.\d+)?(?::\d+)*(?:\/(?:tcp|udp))?\b)/gm;

function highlight(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(TOKEN)) {
    const i = m.index ?? 0;
    if (i > last) out.push(text.slice(last, i));
    if (m[1]) out.push(<span key={k++} className="text-muted-foreground italic">{m[1]}</span>);
    else if (m[3]) {
      out.push(m[2]);
      const strong = ["ports", "volumes", "image"].includes(m[3]);
      out.push(<span key={k++} className={cn("text-sky-700 dark:text-sky-400", strong && "font-semibold")}>{m[3]}</span>, ":");
    } else if (m[5]) out.push(<span key={k++} className="text-emerald-700 dark:text-emerald-400">{m[5]}</span>);
    else out.push(<span key={k++} className="text-amber-700 dark:text-amber-400">{m[6]}</span>);
    last = i + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

/** 带 YAML 高亮的 compose 编辑框：透明 textarea 叠在高亮层上，滚动同步。 */
export function ComposeEditor({ id, value, onChange, placeholder }: { id?: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  const pre = useRef<HTMLPreElement>(null);
  const shared = "col-start-1 row-start-1 m-0 min-h-48 w-full whitespace-pre-wrap break-words rounded-md border px-3 py-2 font-mono text-xs leading-5";
  return (
    <div className="grid">
      <pre ref={pre} aria-hidden className={cn(shared, "pointer-events-none overflow-hidden border-transparent bg-transparent")}>
        {highlight(value)}
        {"\n"}
      </pre>
      <textarea
        id={id}
        spellCheck={false}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onScroll={(e) => {
          if (pre.current) pre.current.scrollTop = e.currentTarget.scrollTop;
        }}
        className={cn(shared, "resize-y border-input bg-transparent text-transparent caret-foreground outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring/50")}
      />
    </div>
  );
}
