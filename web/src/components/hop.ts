import type { RouteView, Status } from "@/types";

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
  if (!gateway || !service) return { kind: "none", text: "-" };
  if (gateway.spec.server === service.spec.server) return { kind: "local", text: "本机" };
  if (route.upstream?.startsWith("127.0.0.1:")) return { kind: "tunnel", text: "反向隧道" };
  const network = status.servers.find((s) => s.name === service.spec.server)?.private_addr?.network;
  if (!network) return { kind: "none", text: "-" };
  return { kind: "direct", text: network === "tailscale" ? "直连 · Tailscale" : network === "overlay" ? "直连 · 加密组网" : "直连 · 明文", plain: network === "lan" };
}
