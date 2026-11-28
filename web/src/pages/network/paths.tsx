import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, SectionTitle, StatusBadge } from "@/components/common";
import { Segmented } from "@/components/fields";
import { hopBetween } from "@/components/hop";
import { Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { NetworkView, Status } from "@/types";
import type { LinkMode } from "@/types.gen";
import { linkState } from "./model";

export function Paths({ status, net }: { status: Status; net: NetworkView }) {
  const [filter, setFilter] = useState<"all" | "cross">("all");
  const [params, setParams] = useSearchParams();
  const open = (a: string, b: string) => { const next = new URLSearchParams(params); next.set("link", [a, b].sort().join("~")); setParams(next); };
  const row = (label: string, serviceName: string, gateway?: string, host?: string, mode?: LinkMode, upstream?: string | null) => {
    const entry = status.gateways.find((g) => g.name === gateway);
    const service = status.services.find((s) => s.name === serviceName);
    const from = entry?.spec.server;
    const to = service?.spec.server;
    const cross = !!from && !!to && from !== to;
    const state = cross ? linkState(from, to, net) : undefined;
    const hop = hopBetween(from, to, mode, upstream, status, net);
    const invalidLayer4 = !host && hop.kind === "tunnel";
    return { label, host, entry, service, serviceName, cross, state, hop, invalidLayer4 };
  };
  const routes = [
    ...status.routes.flatMap((r) => {
      const host = r.spec.hostname;
      const primary = r.spec.service && !r.spec.upstream ? [row(host, r.spec.service, r.gateway ?? undefined, host, r.spec.link, r.upstream)] : [];
      return primary.concat((r.spec.paths ?? []).flatMap((p) =>
        p.service ? [row(host + p.path, p.service, r.gateway ?? undefined, host, r.spec.link)] : []));
    }),
    ...status.gateways.flatMap((g) => (g.spec.layer4 ?? []).flatMap((f) =>
      f.service ? [row(g.name + " :" + f.listen + "/" + (f.udp ? "udp" : "tcp"), f.service, g.name)] : [])),
  ].sort((a, b) => Number(b.state?.tone === "bad" || b.state?.tone === "warn") - Number(a.state?.tone === "bad" || a.state?.tone === "warn") || Number(b.cross) - Number(a.cross));
  const visible = routes.filter((r) => filter === "all" || r.cross);
  const deps = status.services.flatMap((s) => (s.uses ?? []).map((name) => ({ from: s, to: status.services.find((x) => x.name === name) })).filter((d) => !!d.to));
  return <>
    <SectionTitle count={routes.length} action={<Segmented value={filter} options={[["all", "全部"], ["cross", "跨机器"]]} onChange={setFilter} />}>域名</SectionTitle>
    {!visible.length ? <Empty>还没有指向服务的域名</Empty> : <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>域名</TableHead>
            <TableHead>入口</TableHead>
            <TableHead>走法</TableHead>
            <TableHead>服务</TableHead>
            <TableHead>链路</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map(({ label, host, entry, service, serviceName, state, hop, invalidLayer4 }) => {
            return <TableRow key={label}>
              <TableCell>
                {host ? <Link className="font-mono text-xs hover:underline" to={`/domains?open=${encodeURIComponent(host)}`}>
                  {label}
                </Link> : <span className="font-mono text-xs">{label}</span>}
              </TableCell>
              <TableCell>
                {entry?.name ?? "-"}<div className="text-xs text-muted-foreground">
                  {entry?.spec.server}
                </div>
              </TableCell>
              <TableCell>
                {invalidLayer4 ? <span className="text-warning">不可直连</span> : hop.kind === "direct" && hop.plain ? <Tip text="这段没有加密">
                  <span className="text-warning">
                    {hop.text}
                  </span>
                </Tip> : hop.text}
              </TableCell>
              <TableCell>
                <Link className="hover:underline" to={`/services/${encodeURIComponent(serviceName)}`}>
                  {serviceName}
                </Link>
                <div className="text-xs text-muted-foreground">
                  {service?.spec.server}
                </div>
              </TableCell>
              <TableCell>
                {state && entry && service ? <Button variant="ghost" size="xs" onClick={() => open(entry.spec.server, service.spec.server)}>
                  <StatusBadge tone={state.tone}>
                    {state.text}
                  </StatusBadge>
                </Button> : "-"}
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
    <SectionTitle count={deps.length}>服务之间</SectionTitle>
    {!deps.length ? <Empty>服务之间没有互相引用</Empty> : <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>调用方</TableHead>
            <TableHead>被调用方</TableHead>
            <TableHead>链路</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {deps.map(({ from, to }) => {
            const target = to!; const same = from.spec.server === target.spec.server; const state = same ? undefined : linkState(from.spec.server, target.spec.server, net); return <TableRow key={`${from.name}-${target.name}`}>
              <TableCell>
                <Link to={`/services/${encodeURIComponent(from.name)}`} className="hover:underline">
                  {from.name}
                </Link>
                <div className="text-xs text-muted-foreground">
                  {from.spec.server}
                </div>
              </TableCell>
              <TableCell>
                <Link to={`/services/${encodeURIComponent(target.name)}`} className="hover:underline">
                  {target.name}
                </Link>
                <div className="text-xs text-muted-foreground">
                  {target.spec.server}
                </div>
              </TableCell>
              <TableCell>
                {state ? <Button variant="ghost" size="xs" onClick={() => open(from.spec.server, target.spec.server)}>
                  <StatusBadge tone={state.tone}>
                    {state.text}
                  </StatusBadge>
                </Button> : "本机"}
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
  </>;
}
