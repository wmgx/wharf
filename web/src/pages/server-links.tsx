import { Facts } from "@/components/kit";
import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { SectionTitle } from "@/components/common";
import { useStatus } from "@/status";
import type { NetworkView } from "@/types";
import { ModeMenu, Quality } from "./Network";

/** 服务器"网络"标签上半部分：这台机器的地址、和其他机器的连通、端口、域名、出口。 */
export function ServerLinks({ server }: { server: string }) {
  const { data } = usePoll<NetworkView>("/api/network", 30000);
  const { status } = useStatus();
  const me = data?.servers.find((s) => s.name === server);
  const others = (data?.servers ?? []).map((s) => s.name).filter((n) => n !== server);
  const link = (from: string, to: string) => data?.links?.find((l) => l.from === from && l.to === to);
  const reach = (from: string, to: string) => data?.reach.find((r) => r.from === from && r.to === to);
  const relays = (data?.relays ?? []).filter((h) => h.from === server || h.to === server);
  const ports = (status?.services ?? [])
    .filter((s) => s.spec.server === server)
    .flatMap((s) => Object.entries(s.host_ports ?? {}).map(([name, port]) => ({ service: s.name, name, port })))
    .sort((a, b) => a.port - b.port);
  const gateways = (status?.gateways ?? []).filter((g) => g.spec.server === server).map((g) => g.name);
  const routes = (status?.routes ?? []).filter((r) => (r.gateway && gateways.includes(r.gateway)) || (r.spec.backup_gateway && gateways.includes(r.spec.backup_gateway)));
  const settings = status?.servers.find((s) => s.name === server)?.settings;
  const via = settings?.via as string | undefined;
  const exitFor = (status?.servers ?? []).filter((s) => s.settings.via === server).map((s) => s.name);

  const Cell = ({ from, to }: { from: string; to: string }) => {
    const r = reach(from, to);
    if (r && !r.ok) return <span className="text-xs text-destructive">不通</span>;
    return <Quality l={link(from, to)} />;
  };

  return (
    <div className="mb-8 grid gap-6">
      <Facts className="max-w-2xl" items={[
        ["接入方式", me ? <ModeMenu server={me} /> : "-"],
        ["内网地址", <span className="font-mono text-xs">{me?.private_ip ?? "-"}</span>],
        ["公网 IP", <span className="font-mono text-xs">{me?.public_ip ?? "-"}</span>],
        ["访问外网", <>{settings?.egress ? "给其他服务器当出口" : "不开出口"}{exitFor.length > 0 && `，${exitFor.join("、")} 经它访问外网`}{via && `；自己经 ${via} 访问外网`}</>],
      ]} />

      {others.length > 0 && (
        <div>
          <SectionTitle>和其他机器</SectionTitle>
          <div className="grid max-w-2xl grid-cols-[auto_1fr_1fr] gap-x-6 gap-y-1.5 text-sm">
            <span />
            <span className="text-xs text-muted-foreground">{server} → 它</span>
            <span className="text-xs text-muted-foreground">它 → {server}</span>
            {others.map((o) => (
              <div key={o} className="contents">
                <Link to={`/servers/${encodeURIComponent(o)}?tab=network`} className="hover:underline">
                  {o}
                </Link>
                <Cell from={server} to={o} />
                <Cell from={o} to={server} />
              </div>
            ))}
          </div>
          {relays.map((h) => (
            <p key={`${h.from}>${h.to}`} className="mt-2 text-xs text-warning">
              {h.from} → {h.to} 直连丢包 {h.direct_loss.toFixed(0)}%，经 {h.via} 中转约 {h.via_loss.toFixed(0)}%
            </p>
          ))}
        </div>
      )}

      <div>
        <SectionTitle count={ports.length}>占用的端口</SectionTitle>
        {ports.length === 0 ? (
          <p className="text-sm text-muted-foreground">没有</p>
        ) : (
          <div className="grid max-w-2xl grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
            {ports.map((p) => (
              <div key={`${p.service}.${p.name}`} className="contents">
                <span className="font-mono text-xs">{p.port}</span>
                <Link to={`/services/${p.service}`} className="hover:underline">
                  {p.service}
                  <span className="text-xs text-muted-foreground"> · {p.name}</span>
                </Link>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <SectionTitle count={routes.length}>从这里进来的域名</SectionTitle>
        {routes.length === 0 ? (
          <p className="text-sm text-muted-foreground">这台没有入口</p>
        ) : (
          <div className="grid max-w-2xl gap-1 text-sm">
            {routes.map((r) => (
              <div key={r.id} className="flex items-center gap-2">
                <a href={r.url} target="_blank" rel="noreferrer" className="font-mono text-xs hover:underline">
                  {r.spec.hostname}
                </a>
                <span className="text-xs text-muted-foreground">
                  → {r.spec.service ?? r.upstream ?? r.spec.upstream}
                  {r.spec.backup_gateway && gateways.includes(r.spec.backup_gateway) && "（备用入口）"}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
