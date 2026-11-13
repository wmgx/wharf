import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, SectionTitle, StatusBadge } from "@/components/common";
import { Segmented } from "@/components/fields";
import { hopOf } from "@/components/hop";
import { Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { NetworkView, Status } from "@/types";
import { linkState } from "./model";

export function Paths({ status, net }: { status: Status; net: NetworkView }) {
  const [filter, setFilter] = useState<"all" | "cross">("all");
  const [params, setParams] = useSearchParams();
  const open = (a: string, b: string) => { const next = new URLSearchParams(params); next.set("link", [a, b].sort().join("~")); setParams(next); };
  const routes = status.routes.filter((r) => !!r.spec.service).map((route) => {
    const entry = status.gateways.find((g) => g.name === route.gateway);
    const service = status.services.find((s) => s.name === route.spec.service);
    const cross = !!entry && !!service && entry.spec.server !== service.spec.server;
    const state = cross ? linkState(entry!.spec.server, service!.spec.server, net) : undefined;
    return { route, entry, service, cross, state };
  }).sort((a, b) => Number(b.state?.tone === "bad" || b.state?.tone === "warn") - Number(a.state?.tone === "bad" || a.state?.tone === "warn") || Number(b.cross) - Number(a.cross));
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
          {visible.map(({ route, entry, service, state }) => {
            const hop = hopOf(route, status);
            return <TableRow key={route.id}>
              <TableCell>
                <Link className="font-mono text-xs hover:underline" to={`/domains?open=${encodeURIComponent(route.spec.hostname)}`}>
                  {route.spec.hostname}
                </Link>
              </TableCell>
              <TableCell>
                {entry?.name ?? "-"}<div className="text-xs text-muted-foreground">
                  {entry?.spec.server}
                </div>
              </TableCell>
              <TableCell>
                {hop.kind === "direct" && hop.plain ? <Tip text="这段没有加密">
                  <span className="text-warning">
                    {hop.text}
                  </span>
                </Tip> : hop.text}
              </TableCell>
              <TableCell>
                <Link className="hover:underline" to={`/services/${encodeURIComponent(route.spec.service!)}`}>
                  {route.spec.service}
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
