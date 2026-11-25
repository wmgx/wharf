import { CloudIcon, SearchIcon } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, OpenLink, useClickable } from "@/components/common";
import { Picker, Segmented } from "@/components/fields";
import { CertDays, Lamps, diagnosisOf, routeTone } from "@/components/health";
import { hopOf } from "@/components/hop";
import { Panel, Tip } from "@/components/kit";
import { Probe } from "@/components/probe";
import { OpMenu, routeOps } from "@/components/ops";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useIsMobile } from "@/hooks/use-mobile";
import type { RouteView, Status } from "@/types";
import { ResourceNote } from "../service/note";

export function DomainList({ status, add }: { status: Status; add: React.ReactNode }) {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [problems, setProblems] = useState(false);
  const clickable = useClickable();
  const mobile = useIsMobile();
  const gateway = params.get("gateway") ?? "";
  const routes = status.routes.filter((r) => r.spec.expires_at == null).map((route) => ({ hostname: route.spec.hostname, route, edge: undefined as string | undefined }));
  const edge = (status.edge_apps ?? []).flatMap((app) => (app.spec.domains ?? []).map((hostname) => ({ hostname, route: undefined as RouteView | undefined, edge: app.name })));
  const rows: { hostname: string; route?: RouteView; edge?: string }[] = [...routes, ...edge].sort((a, b) => Number(!!b.route && ["bad", "warn"].includes(routeTone(diagnosisOf(status, b.hostname)).tone)) - Number(!!a.route && ["bad", "warn"].includes(routeTone(diagnosisOf(status, a.hostname)).tone)) || a.hostname.localeCompare(b.hostname));
  const bad = (r: RouteView) => ["bad", "warn"].includes(routeTone(diagnosisOf(status, r.spec.hostname)).tone);
  const problemCount = status.routes.filter((r) => r.spec.expires_at == null && bad(r)).length;
  const filtered = rows.filter((r) => (!gateway || (r.edge ? gateway === "cloudflare" : r.route?.gateway === gateway)) && [r.hostname, r.edge, r.route?.spec.service, r.route?.spec.upstream, r.route?.spec.redirect].some((v) => v?.toLowerCase().includes(query.toLowerCase())) && (!problems || !!r.route && bad(r.route)));
  const options = [{ value: "", label: "全部入口" }, ...status.gateways.map((g) => ({ value: g.name, label: g.name })), ...(edge.length ? [{ value: "cloudflare", label: "Cloudflare" }] : [])];
  const select = (value: string) => { const next = new URLSearchParams(params); if (value) next.set("gateway", value); else next.delete("gateway"); setParams(next); };
  if (!rows.length) return <Empty action={status.gateways.length ? add : <Button onClick={() => setParams({ tab: "entries", new: "1" })}>新建入口</Button>}>
    {status.gateways.length ? "还没有域名" : "还没有域名。先建一个入口"}
  </Empty>;
  const list = filtered.map(({ hostname, route, edge: app }) => {
    const d = diagnosisOf(status, hostname);
    const days = d?.domain_expires ? Math.floor((Date.parse(d.domain_expires) - Date.now()) / 86400000) : undefined;
    const hop = route && hopOf(route, status);
    const key = `${hostname}-${app ?? "route"}`;
    const link = clickable({ to: app ? `/edge/${encodeURIComponent(app)}` : `?open=${encodeURIComponent(hostname)}` });
    const checks = route?.probe ? <Probe probe={route.probe} /> : route ? <Lamps d={d} /> : "-";
    const operations = route && <OpMenu ops={routeOps} target={route} label={`${hostname} 的操作`} size="icon-sm" />;
    const note = route && <div className="font-sans" onClick={(e) => e.stopPropagation()}>
      <ResourceNote path={`/api/routes/${encodeURIComponent(hostname)}/note`} value={route.note} />
    </div>;
    const target = app ? <Link to={`/edge/${encodeURIComponent(app)}`} className="inline-flex items-center gap-1 hover:underline" onClick={(e) => e.stopPropagation()}>
      <CloudIcon className="size-3.5 max-md:shrink-0" />
      {app}
    </Link> : route?.spec.service ? <Link to={`/services/${encodeURIComponent(route.spec.service)}`} onClick={(e) => e.stopPropagation()} className="hover:underline">
      {route.spec.service}
    </Link> : <span className="block font-mono text-xs text-muted-foreground md:max-w-40 md:truncate">
      {route?.spec.redirect ? `→ ${route.spec.redirect}` : route?.spec.upstream}
    </span>;
    const backup = route?.on_backup && <Badge variant="destructive">正走备用</Badge>;
    if (mobile) return <div key={key} className="min-w-0 cursor-pointer" {...link}>
      <Panel className="grid gap-1.5 p-3">
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1 font-mono text-xs">
            <OpenLink value={hostname} className="max-w-full [&>a>span]:wrap-anywhere [&>a>span]:whitespace-normal" />
          </div>
          {operations}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs">{checks}{backup}</div>
        <div className="flex min-w-0 items-baseline gap-2 text-sm">
          <span className="shrink-0 text-xs text-muted-foreground">指向</span>
          <div className="min-w-0 wrap-anywhere">{target}</div>
        </div>
        {note}
      </Panel>
    </div>;
    return <TableRow key={key} className="cursor-pointer" {...link}>
      <TableCell className="font-mono text-xs">
        <OpenLink value={hostname} />
        {route?.spec.expires_at != null && <div className={`font-sans text-xs ${route.spec.expires_at <= Date.now() ? "text-warning" : "text-muted-foreground"}`}>{route.spec.expires_at <= Date.now() ? "已失效" : `临时分享，${new Date(route.spec.expires_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })} 到期`}</div>}
        {backup}
        {note}
      </TableCell>
      <TableCell>{checks}</TableCell>
      <TableCell>{target}</TableCell>
      <TableCell>
        {app ? "Cloudflare" : <>
          {route?.gateway ?? "-"}{hop && hop.kind !== "redirect" && hop.kind !== "none" && <div className={`text-xs ${hop.kind === "direct" && hop.plain ? "text-warning" : "text-muted-foreground"}`}>
            {hop.text}
          </div>}
        </>}
      </TableCell>
      <TableCell>
        {route ? <Button variant="outline" size="xs" onClick={(e) => { e.stopPropagation(); setParams({ protection: hostname }); }}>{route.spec.sso?.mode === "oidc" ? "OIDC" : route.spec.sso?.public ? "公开" : route.spec.sso ? "门禁" : route.spec.auth ? "账号密码" : "不保护"}</Button> : "-"}
      </TableCell>
      <TableCell>{d?.cert_expires ? <CertDays d={d} /> : "-"}</TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>
        {app ? "-" : days != null ? <Tip text={new Date(d!.domain_expires!).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" })}>
          <span className={days < 3 ? "text-destructive" : days < 14 ? "text-warning" : "text-muted-foreground"}>{days < 0 ? "已到期" : `剩 ${days} 天`}</span>
        </Tip> : <span className="text-muted-foreground">未知</span>}
      </TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>{operations}</TableCell>
    </TableRow>;
  });
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
    {!filtered.length ? <Empty>没有符合条件的域名</Empty> : mobile ? <div className="grid gap-2">{list}</div> : <Panel>
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
        <TableBody>{list}</TableBody>
      </Table>
    </Panel>}
  </>;
}
