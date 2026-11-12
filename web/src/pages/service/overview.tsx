import { ArrowRightIcon, ArrowUpRightIcon, LockIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api";
import { CopyButton, Dot, OpenLink, SectionTitle, ago } from "@/components/common";
import { diagnosisOf, routeTone, serviceTruth } from "@/components/health";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Probe } from "@/components/probe";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import type { RouteView, ServiceView, Timeline } from "@/types";
import { ServiceNote } from "./note";
import { dataSummary } from "./status-text";

const kinds: Record<string, string> = { deploy: "部署", backup: "备份", task: "任务", heal: "自动重启", alert: "告警", op: "操作" };

export function Overview({ svc, routes, onTab, onBackup }: { svc: ServiceView; routes: RouteView[]; onTab: (t: string) => void; onBackup: () => void }) {
  const { status } = useStatus();
  const [timeline, setTimeline] = useState<Timeline | null>(null);
  useEffect(() => { api.get<Timeline>(`/api/services/${encodeURIComponent(svc.name)}/timeline?limit=3`).then(setTimeline).catch(() => setTimeline(null)); }, [svc.name]);
  const { tone, text, detail } = serviceTruth(svc, status);
  const routeProblem = svc.status?.tone !== "bad" && svc.status?.tone !== "warn" && routes.some((r) => routeTone(diagnosisOf(status, r.spec.hostname)).tone === "bad");
  const via = status?.servers.find((s) => s.name === svc.spec.server)?.settings.via as string | undefined;
  const hints: { text: string; action: string; go: () => void }[] = [];
  if (!routes.length) hints.push({ text: "还没有域名，现在只能从内网访问。", action: "加域名", go: () => onTab("domains") });
  if (svc.data?.some((m) => m.kind === "managed") && !svc.spec.backup) hints.push({ text: "有数据，但还没开备份。", action: "开备份", go: onBackup });
  return <>
    <Panel className="p-4">
      <div className="flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-base font-medium">
            <Dot tone={tone} className="size-2.5" />
            {text}
          </div>
          <div className="text-sm text-muted-foreground">
            {detail || (routes.length ? `${routes.length} 个域名都能打开` : "只在内网访问")}
          </div>
        </div>
        {(tone === "bad" || tone === "warn") && <Button variant="outline" size="sm" onClick={() => onTab(routeProblem ? "domains" : "logs")}>
          {routeProblem ? "看域名" : "看日志"}
        </Button>}
      </div>
    </Panel>
    {hints.map((h) => <div key={h.action} className="mt-3 flex items-center gap-3 rounded-xl border border-dashed px-4 py-2.5 text-sm">
      <span className="flex-1 text-muted-foreground">
        {h.text}
      </span>
      <Button size="xs" variant="outline" onClick={h.go}>
        {h.action}<ArrowRightIcon />
      </Button>
    </div>)}
    <div className="mt-8 grid gap-3 md:grid-cols-[1.4fr_1fr]">
      <div>
        <SectionTitle>访问</SectionTitle>
        <Panel className="p-4">
          <Facts items={[
            ["域名", routes.length ? <div className="grid min-w-0 gap-1">
              {routes.map((r) => <div key={r.id} className="flex min-w-0 items-center gap-0.5">
                <a className="inline-flex min-w-0 items-center gap-1 font-mono text-xs text-primary hover:underline" href={r.url} target="_blank" rel="noreferrer">
                  {r.spec.auth && <LockIcon className="size-3.5 shrink-0 text-muted-foreground" />}<span className="truncate">
                    {r.url}
                  </span>
                  <ArrowUpRightIcon className="size-3.5 shrink-0" />
                </a>
                <CopyButton text={r.url} />
                <Probe probe={r.probe} />
              </div>)}
            </div> : "还没有域名"],
            ["内网地址", <div className="font-mono text-xs">
              {Object.entries(svc.addresses).map(([p, a]) => <div key={p} className="flex flex-wrap items-center gap-x-3 gap-y-0.5">
                <span className="text-muted-foreground">
                  {p}
                </span>
                <OpenLink value={a} />
                {(svc.lan_addresses?.[p] ?? []).map((l) => <span key={l} className="inline-flex items-center gap-1">
                  <span className="font-sans text-xs text-muted-foreground">局域网</span>
                  <OpenLink value={l} />
                </span>)}
              </div>)}{Object.keys(svc.addresses).length === 0 && "-"}
            </div>],
            ["依赖", !!(svc.uses?.length || svc.used_by?.length) && <div>
              {[["引用", svc.uses], ["被引用", svc.used_by]].map(([label, names]) => Array.isArray(names) && names.length > 0 && <div key={label as string} className="flex flex-wrap gap-x-2">
                <span className="text-xs text-muted-foreground">
                  {label}
                </span>
                {names.map((n) => <Link key={n} to={`/services/${encodeURIComponent(n)}`} className="hover:underline">
                  {n}
                </Link>)}
              </div>)}
            </div>],
            ["访问外网", via ? <>经 <Link to={`/servers/${encodeURIComponent(svc.spec.server)}?tab=settings`} className="hover:underline">
              {via}
            </Link>
            </> : "直接访问"],
            ["数据", <button type="button" className="text-left hover:underline" onClick={() => onTab("data")}>
              {dataSummary(svc)}
            </button>],
          ]} />
        </Panel>
      </div>
      <div>
        <SectionTitle>容器</SectionTitle>
        <Panel className="grid gap-2.5 p-4 text-sm">
          {svc.containers?.map((c) => <div key={c.name} className="flex items-center gap-3">
            <span className="w-24 truncate text-muted-foreground">
              {c.service}
            </span>
            <Dot tone={c.state === "running" ? "ok" : "bad"} />
            <span>
              {c.status || c.state}
            </span>
          </div>)}{!svc.containers?.length && <span className="text-muted-foreground">
            {svc.status?.error ?? "没有容器"}
          </span>}
        </Panel>
      </div>
    </div>
    <SectionTitle>备注</SectionTitle>
    <ServiceNote svc={svc} />
    {!!timeline?.items.length && <>
      <SectionTitle action={<Button variant="ghost" size="xs" onClick={() => onTab("history")}>全部</Button>}>最近</SectionTitle>
      <Rows>
        {timeline.items.map((item, i) => <Row key={`${item.at}-${i}`}>
          <span>
            {kinds[item.kind]}
          </span>
          <span className="min-w-0 flex-1">
            {item.title}
          </span>
          <span className="text-muted-foreground">
            {ago(new Date(item.at).toISOString())}
          </span>
        </Row>)}
      </Rows>
    </>}
  </>;
}
