import { CloudIcon, LockIcon, SearchIcon } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, OpenLink, useClickable } from "@/components/common";
import { Picker, Segmented } from "@/components/fields";
import { CertDays, Lamps, diagnosisOf, routeTone } from "@/components/health";
import { hopOf } from "@/components/hop";
import { Panel, Tip } from "@/components/kit";
import { OpMenu, routeOps } from "@/components/ops";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { RouteView, Status } from "@/types";

export function DomainList({ status, add }: { status: Status; add: React.ReactNode }) {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [problems, setProblems] = useState(false);
  const clickable = useClickable();
  const gateway = params.get("gateway") ?? "";
  const routes = status.routes.map((route) => ({ hostname: route.spec.hostname, route, edge: undefined as string | undefined }));
  const edge = (status.edge_apps ?? []).flatMap((app) => (app.spec.domains ?? []).map((hostname) => ({ hostname, route: undefined as RouteView | undefined, edge: app.name })));
  const rows: { hostname: string; route?: RouteView; edge?: string }[] = [...routes, ...edge].sort((a, b) => a.hostname.localeCompare(b.hostname));
  const bad = (r: RouteView) => ["bad", "warn"].includes(routeTone(diagnosisOf(status, r.spec.hostname)).tone);
  const problemCount = status.routes.filter(bad).length;
  const filtered = rows.filter((r) => (!gateway || (r.edge ? gateway === "cloudflare" : r.route?.gateway === gateway)) && [r.hostname, r.edge, r.route?.spec.service, r.route?.spec.upstream, r.route?.spec.redirect].some((v) => v?.toLowerCase().includes(query.toLowerCase())) && (!problems || !!r.route && bad(r.route)));
  const options = [{ value: "", label: "全部入口" }, ...status.gateways.map((g) => ({ value: g.name, label: g.name })), ...(edge.length ? [{ value: "cloudflare", label: "Cloudflare" }] : [])];
  const select = (value: string) => { const next = new URLSearchParams(params); if (value) next.set("gateway", value); else next.delete("gateway"); setParams(next); };
  if (!rows.length) return <Empty action={status.gateways.length ? add : <Button onClick={() => setParams({ tab: "entries", new: "1" })}>新建入口</Button>}>
    {status.gateways.length ? "还没有域名" : "还没有域名。先建一个入口"}
  </Empty>;
  return <>
    <div className="mb-4 flex flex-wrap items-center gap-2">
      {status.gateways.length <= 3 ? <div className="max-w-full overflow-x-auto">
        <Segmented value={gateway} options={options.map((o) => [o.value, o.label])} onChange={select} />
      </div> : <Picker value={gateway} options={options} onChange={select} />}
      <div className="relative w-48">
        <SearchIcon className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input className="pl-9" placeholder="搜索" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      {problemCount > 0 && <Button size="sm" variant={problems ? "secondary" : "outline"} onClick={() => setProblems(!problems)}>只看有问题的</Button>}
    </div>
    {!filtered.length ? <Empty>没有符合条件的域名</Empty> : <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>域名</TableHead>
            <TableHead>检查</TableHead>
            <TableHead>指向</TableHead>
            <TableHead>入口</TableHead>
            <TableHead>保护</TableHead>
            <TableHead>证书</TableHead>
            <TableHead>到期</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map(({ hostname, route, edge: app }) => {
            const d = diagnosisOf(status, hostname);
            const days = d?.domain_expires ? Math.floor((Date.parse(d.domain_expires) - Date.now()) / 86400000) : undefined;
            const hop = route && hopOf(route, status);
            return <TableRow key={`${hostname}-${app ?? "route"}`} className="cursor-pointer" {...clickable({ to: app ? `/edge/${encodeURIComponent(app)}` : `?open=${encodeURIComponent(hostname)}` })}>
              <TableCell className="font-mono text-xs">
                <OpenLink value={hostname} />
                {route?.on_backup && <Badge variant="destructive">正走备用</Badge>}
              </TableCell>
              <TableCell>
                {route ? <Lamps d={d} /> : "-"}
              </TableCell>
              <TableCell>
                {app ? <Link to={`/edge/${encodeURIComponent(app)}`} className="inline-flex items-center gap-1 hover:underline" onClick={(e) => e.stopPropagation()}>
                  <CloudIcon className="size-3.5" />
                  {app}
                </Link> : route?.spec.service ? <Link to={`/services/${encodeURIComponent(route.spec.service)}`} onClick={(e) => e.stopPropagation()} className="hover:underline">
                  {route.spec.service}
                </Link> : <span className="block max-w-40 truncate font-mono text-xs text-muted-foreground">
                  {route?.spec.redirect ? `→ ${route.spec.redirect}` : route?.spec.upstream}
                </span>}
              </TableCell>
              <TableCell>
                {app ? "Cloudflare" : <>
                  {route?.gateway ?? "-"}{hop && hop.kind !== "redirect" && hop.kind !== "none" && <div className={`text-xs ${hop.kind === "direct" && hop.plain ? "text-warning" : "text-muted-foreground"}`}>
                    {hop.text}
                  </div>}
                </>}
              </TableCell>
              <TableCell>
                {route?.spec.auth ? <Tip text="登录保护：账号密码">
                  <span>
                    <LockIcon className="size-4" />
                  </span>
                </Tip> : "-"}
              </TableCell>
              <TableCell>
                {d?.cert_expires ? <CertDays d={d} /> : "-"}
              </TableCell>
              <TableCell onClick={(e) => e.stopPropagation()}>
                {app ? "-" : days != null ? <Tip text={new Date(d!.domain_expires!).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" })}>
                  <span className={days < 3 ? "text-destructive" : days < 14 ? "text-warning" : "text-muted-foreground"}>{days < 0 ? "已到期" : `剩 ${days} 天`}</span>
                </Tip> : <span className="text-muted-foreground">未知</span>}
              </TableCell>
              <TableCell onClick={(e) => e.stopPropagation()}>
                {route && <OpMenu ops={routeOps} target={route} label={`${hostname} 的操作`} size="icon-sm" />}
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
  </>;
}
