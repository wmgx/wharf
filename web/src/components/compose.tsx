import { Link } from "react-router-dom";
import { CodeEditor } from "@/components/code-editor";
import type { PortSpec, ServerView } from "@/types";
import { toName } from "@/components/fields";

export interface ComposePort {
  service: string;
  host: number;
  container: number;
  udp?: boolean;
}

export interface ComposeVolume {
  service: string;
  source: string;
  target: string;
}

export interface ComposeInfo {
  /** compose 里的容器名，按出现顺序。 */
  services: string[];
  images: string[];
  ports: ComposePort[];
  volumes: ComposeVolume[];
}

const indentOf = (line: string) => line.length - line.trimStart().length;
const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");

/** `127.0.0.1:8080:80`、`8080:80/tcp`、`80` → 宿主机端口和容器端口；只有容器端口时没有宿主机端口。 */
function parsePort(text: string): Omit<ComposePort, "service" | "host"> & { host?: number } | null {
  const [address, protocol = "tcp", rest] = unquote(text).toLowerCase().split("/");
  if (rest !== undefined || (protocol !== "tcp" && protocol !== "udp")) return null;
  const parts = address.split(":");
  const nums = parts.slice(-2).map(Number);
  if (nums.some((n) => !Number.isInteger(n) || n <= 0 || n > 65535)) return null;
  return parts.length === 1 ? { container: nums[0] } : { host: nums[0], container: nums[1], ...(protocol === "udp" ? { udp: true } : {}) };
}

/**
 * 按行粗略读 compose：只认 services 下每个服务的 image、ports、volumes 短写法和 published/target 长写法。
 * 只用来给表单预填和提示，真正的校验在控制面。
 */
export function parseCompose(text: string): ComposeInfo {
  const info: ComposeInfo = { services: [], images: [], ports: [], volumes: [] };
  let svcIndent = -1;
  let service = "";
  let list: "ports" | "volumes" | null = null;
  let listIndent = -1;
  let pending: { published?: number; target?: number; protocol?: string; source?: string; mount?: string } | null = null;
  const flush = () => {
    if (!pending) return;
    const protocol = pending.protocol ?? "tcp";
    if (list === "ports" && pending.published && pending.target && ["tcp", "udp"].includes(protocol)) {
      info.ports.push({ service, host: pending.published, container: pending.target, ...(protocol === "udp" ? { udp: true } : {}) });
    }
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
      service = unquote(t.replace(/:$/, ""));
      info.services.push(service);
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
      if (kv[1] === "protocol") pending.protocol = v.toLowerCase();
      if (kv[1] === "published") pending.published = Number(v);
      if (kv[1] === "target") (list === "ports" ? (pending.target = Number(v)) : (pending.mount = v));
      if (kv[1] === "source") pending.source = v;
      continue;
    }
    if (item === null) continue;
    if (list === "ports") {
      const p = parsePort(item);
      if (p?.host) info.ports.push({ service, host: p.host, container: p.container, ...(p.udp ? { udp: true } : {}) });
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

/** compose 里写的端口转成表单端口：名称取服务名，同一服务多个端口时加容器端口区分。 */
export function composePorts(info: ComposeInfo): PortSpec[] {
  const count = new Map<string, number>();
  info.ports.forEach((p) => count.set(p.service, (count.get(p.service) ?? 0) + 1));
  const used = new Set<string>();
  const bindings = new Set<string>();
  return info.ports.flatMap((p) => {
    const binding = `${p.host}/${p.udp ? "udp" : "tcp"}`;
    if (bindings.has(binding)) return [];
    bindings.add(binding);
    const suffix = `${count.get(p.service)! > 1 ? `-${p.container}` : ""}${p.udp ? "-udp" : ""}`;
    const base = toName(p.service).slice(0, 48 - suffix.length) + suffix;
    let name = base || `p${p.host}`;
    for (let i = 2; used.has(name); i++) {
      const serial = `-${i}`;
      name = base.slice(0, 48 - serial.length) + serial;
    }
    used.add(name);
    return [{ name, host: p.host, ...(p.udp ? { udp: true } : {}) }];
  });
}

/** 新建和编辑共用：高亮编辑框 + 识别到的挂载。 */
export function ComposeField({ info, ...editor }: { id?: string; value: string; onChange: (v: string) => void; placeholder?: string; info: ComposeInfo }) {
  return (
    <>
      <CodeEditor lang="yaml" secrets className="min-h-48" {...editor} />
      {info.volumes.length > 0 && (
        <div className="grid gap-0.5 text-xs text-muted-foreground">
          <div>识别到的挂载：</div>
          {info.volumes.map((v, i) => (
            <div key={i} className="font-mono">
              {v.service}：{v.source} → {v.target}
            </div>
          ))}
        </div>
      )}
    </>
  );
}
