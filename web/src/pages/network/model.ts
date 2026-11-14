import type { Tone } from "@/components/common";
import type { NetworkView, RouteView, Status } from "@/types";

export interface LinkState { tone: Tone; text: string }
export interface Pair { a: string; b: string; ab: LinkState; ba: LinkState; tone: Tone; relay?: string }
export interface Affected { routes: RouteView[]; deps: [string, string][]; egress: [string, string][] }

export function linkState(from: string, to: string, net: NetworkView): LinkState {
  const reach = net.reach.find((r) => r.from === from && r.to === to);
  const link = net.links?.find((l) => l.from === from && l.to === to);
  if (reach && !reach.stale && !reach.ok) return { tone: "bad", text: "不通" };
  if (link && link.loss >= 20) return { tone: "bad", text: `丢包 ${link.loss.toFixed(0)}%` };
  if (link && link.loss > 0) return { tone: "warn", text: `丢包 ${link.loss.toFixed(0)}%` };
  if (link) return { tone: "ok", text: link.ms == null ? "正常" : `${link.ms.toFixed(0)} ms` };
  if (reach && !reach.stale && reach.ok) return { tone: "ok", text: "正常" };
  return { tone: "idle", text: reach?.stale ? "结果过期" : "没检查过" };
}

export function pairs(net: NetworkView): Pair[] {
  const names = net.servers.map((s) => s.name).sort();
  const order: Tone[] = ["bad", "warn", "idle", "ok"];
  const result: Pair[] = [];
  names.forEach((a, i) => names.slice(i + 1).forEach((b) => {
    const ab = linkState(a, b, net);
    const ba = linkState(b, a, net);
    const relay = net.relays?.find((r) => (r.from === a && r.to === b) || (r.from === b && r.to === a));
    result.push({ a, b, ab, ba, tone: order.indexOf(ab.tone) <= order.indexOf(ba.tone) ? ab.tone : ba.tone, relay: relay ? `${relay.from} → ${relay.to} 经 ${relay.via} 中转，丢包约 ${relay.via_loss.toFixed(0)}%` : undefined });
  }));
  return result;
}

export function affected(a: string, b: string, status: Status): Affected {
  const isPair = (x?: string, y?: string) => (x === a && y === b) || (x === b && y === a);
  const routes = status.routes.filter((r) => r.spec.service && isPair(status.gateways.find((g) => g.name === r.gateway)?.spec.server, status.services.find((s) => s.name === r.spec.service)?.spec.server));
  const deps: [string, string][] = status.services.flatMap((s) => (s.uses ?? []).filter((name) => isPair(s.spec.server, status.services.find((x) => x.name === name)?.spec.server)).map((name): [string, string] => [s.name, name]));
  const egress: [string, string][] = status.servers.filter((s) => isPair(s.name, s.settings.via)).map((s) => [s.name, s.settings.via!]);
  return { routes, deps, egress };
}
