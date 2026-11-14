import { Link, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { MODES, SectionTitle } from "@/components/common";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { useStatus } from "@/status";
import type { EgressPreset, NetworkView } from "@/types";
import { egressText } from "../network/egress";
import { LinkSheet } from "../network/link-sheet";
import { PairTable } from "../network/machines";
import { pairs } from "../network/model";

export function ServerLinks({ server }: { server: string }) {
  const { data: net } = usePoll<NetworkView>("/api/network", 30000);
  const { data: egress } = usePoll<{ presets: EgressPreset[] }>("/api/egress", 60000);
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const me = net?.servers.find((s) => s.name === server);
  const settings = status?.servers.find((s) => s.name === server)?.settings;
  const users = (status?.servers ?? []).filter((s) => s.settings.via === server).map((s) => s.name);
  const links = net ? pairs(net).filter((p) => p.a === server || p.b === server) : [];
  const gateways = (status?.gateways ?? []).filter((g) => g.spec.server === server).map((g) => g.name);
  const routes = (status?.routes ?? []).filter((r) => (r.gateway && gateways.includes(r.gateway)) || (r.spec.backup_gateway && gateways.includes(r.spec.backup_gateway)));
  const ports = (status?.services ?? []).filter((s) => s.spec.server === server).flatMap((s) => Object.entries(s.host_ports ?? []).map(([name, port]) => ({ service: s.name, name, port }))).sort((a, b) => a.port - b.port);
  const [a, b] = (params.get("link") ?? "").split("~");
  return <div className="mb-8">
    <Panel className="p-4">
      <Facts items={[
        ["接入方式", me ? <>
          {MODES[me.mode]} {!me.configured && <span className="text-xs text-muted-foreground">自动</span>}
        </> : "-"],
        ["内网地址", <span className="font-mono text-xs">
          {me?.private_ip ?? "-"}
        </span>],
        ["公网 IP", <span className="font-mono text-xs">
          {me?.public_ip ?? "-"}
        </span>],
        ["访问外网", settings?.via ? `经 ${settings.via}` : "直接访问"],
        ["作为出口", settings?.egress && `${egressText(settings.egress, egress?.presets ?? [])}${users.length ? `，${users.join("、")} 在用` : ""}`],
      ]} />
    </Panel>
    {links.length > 0 && <>
      <SectionTitle>和其他机器</SectionTitle>
      <PairTable items={links} server={server} />
    </>}
    <SectionTitle count={routes.length}>从这台进来的域名</SectionTitle>
    {routes.length ? <Rows>
      {routes.map((r) => <Row key={r.id} to={`/domains?open=${encodeURIComponent(r.spec.hostname)}`}>
        <span className="font-mono text-xs">
          {r.spec.hostname}
        </span>
        <span className="text-xs text-muted-foreground">→ {r.spec.service ?? r.upstream ?? r.spec.upstream}
        </span>
        {r.spec.backup_gateway && gateways.includes(r.spec.backup_gateway) && <Badge variant="outline">备用</Badge>}
      </Row>)}
    </Rows> : <p className="text-sm text-muted-foreground">这台没有入口</p>}
    {ports.length > 0 && <>
      <SectionTitle count={ports.length}>服务占用的端口</SectionTitle>
      <Rows>
        {ports.map((p) => <Row key={`${p.service}.${p.name}`}>
          <span className="font-mono text-xs">
            {p.port}
          </span>
          <Link to={`/services/${encodeURIComponent(p.service)}`} className="hover:underline">
            {p.service}
          </Link>
          <span className="text-xs text-muted-foreground">
            {p.name}
          </span>
        </Row>)}
      </Rows>
    </>}
    {a && b && net && status && <LinkSheet key={`${a}~${b}`} a={a} b={b} net={net} status={status} onClose={() => { const next = new URLSearchParams(params); next.delete("link"); setParams(next); }} />}
  </div>;
}
