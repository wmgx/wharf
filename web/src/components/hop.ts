import type { NetworkView, RouteView, Status } from "@/types";
import type { LinkMode } from "@/types.gen";

export type Hop =
  | { kind: "local"; text: "本机" }
  | { kind: "direct"; text: string; plain: boolean }
  | { kind: "tunnel"; text: "反向隧道" }
  | { kind: "redirect"; text: "跳转" }
  | { kind: "external"; text: "外部地址" }
  | { kind: "none"; text: "-" };

export function hopOf(route: RouteView, status: Status): Hop {
  if (route.spec.redirect) return { kind: "redirect", text: "跳转" };
  if (!route.spec.service) return { kind: "external", text: "外部地址" };
  const gateway = status.gateways.find((g) => g.name === route.gateway);
  const service = status.services.find((s) => s.name === route.spec.service);
  return hopBetween(gateway?.spec.server, service?.spec.server, route.spec.link, route.upstream, status);
}

export function hopBetween(
  gateway: string | undefined,
  service: string | undefined,
  link: LinkMode | undefined,
  upstream: string | null | undefined,
  status: Status,
  net?: NetworkView,
): Hop {
  if (!gateway || !service) return { kind: "none", text: "-" };
  if (gateway === service) return { kind: "local", text: "本机" };
  const network = status.servers.find((s) => s.name === service)?.private_addr?.network;
  const unreachable = net?.reach.some((r) => r.from === gateway && r.to === service && !r.stale && !r.ok);
  if (upstream?.startsWith("127.0.0.1:") || link === "tunnel" || !network || unreachable) {
    return { kind: "tunnel", text: "反向隧道" };
  }
  return { kind: "direct", text: network === "tailscale" ? "直连 · Tailscale" : network === "overlay" ? "直连 · 加密组网" : "直连 · 明文", plain: network === "lan" };
}
