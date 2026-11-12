export function size(bytes?: number): string {
  if (bytes == null) return "-";
  const units = ["B", "K", "M", "G", "T"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)}${units[i]}`;
}

export function uptime(secs: number): string {
  const days = Math.floor(secs / 86400);
  if (days > 0) return `${days} 天`;
  const hours = Math.floor(secs / 3600);
  return hours > 0 ? `${hours} 小时` : `${Math.floor(secs / 60)} 分钟`;
}

export interface Traffic {
  since: string;
  rx: number;
  tx: number;
  quota?: number;
}

export function trafficText(t: Traffic | null): string | undefined {
  if (!t) return undefined;
  const used = t.rx + t.tx;
  const quota = t.quota
    ? ` · 额度 ${size(t.quota)}，已用 ${Math.round((used / t.quota) * 100)}%`
    : "";
  return `收 ${size(t.rx)} · 发 ${size(t.tx)}（${t.since.slice(5)} 起）${quota}`;
}

/** 私有网段 IPv4：10/8、172.16/12、192.168/16。公网地址不能绑，否则服务直接暴露。 */
export const isPrivate = (ip: string) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+(\.\d+)?$/.test(ip) &&
  ip.split(".").length === 4;

export const mirrorsText = (m?: Record<string, string[]>) =>
  Object.entries(m ?? {})
    .map(([k, v]) => `${k}=${v.join(",")}`)
    .join("\n");

export function parseMirrors(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf("=");
    if (i <= 0) continue;
    const list = line
      .slice(i + 1)
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    if (list.length) out[line.slice(0, i).trim()] = list;
  }
  return out;
}
