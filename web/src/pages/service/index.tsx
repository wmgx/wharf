import { ArrowLeftIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { AddRoute } from "@/components/add-route";
import { Dot, Empty, ErrorNote, PageHeader, SectionTitle, ServerTag, StatusBadge, ago, sourceLabel } from "@/components/common";
import { serviceTruth } from "@/components/health";
import { Panel } from "@/components/kit";
import { LogStream } from "@/components/LogStream";
import { MetricsPanel } from "@/components/metrics";
import { OpBar, serviceOps } from "@/components/ops";
import { useTab } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useStatus } from "@/status";
import type { ServiceView } from "@/types";
import { DataTab } from "./data";
import { DomainsTab } from "./domains";
import { HistoryTab } from "./history";
import { Overview } from "./overview";
import { Repack } from "./repack";
import { Settings } from "./settings";
import { statusLayers } from "./status-text";
import { TerminalTab } from "./terminal";

const TABS = ["overview", "domains", "logs", "metrics", "history", "data", "terminal", "settings"] as const;
type Tab = typeof TABS[number];
const aliases: Record<string, Tab> = { network: "domains", config: "settings", timeline: "history", files: "data" };

export function ServiceDetail() {
  const { name = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useTab(TABS, "overview");
  const location = useLocation();
  const navigate = useNavigate();
  const { status } = useStatus();
  const { data: svc, error } = usePoll<ServiceView>(`/api/services/${encodeURIComponent(name)}`, 5000);
  const [addingRoute, setAddingRoute] = useState(false);
  const raw = params.get("tab");
  useEffect(() => { if (raw && aliases[raw]) { const next = new URLSearchParams(params); next.set("tab", aliases[raw]); navigate({ search: `?${next}`, hash: location.hash }, { replace: true }); } }, [raw, params, navigate, location.hash]);
  const settingsAt = (section: string) => navigate({ search: "?tab=settings", hash: `#${section}` });
  const back = <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground" to="/services">
    <ArrowLeftIcon className="size-3.5" />服务</Link>;
  if (error && !svc) return <>
    {back}<ErrorNote error={error} />
  </>;
  if (!svc) return <>
    {back}<Skeleton className="mb-6 h-12 w-64" />
    <div className="grid gap-3 md:grid-cols-[1.4fr_1fr]">
      <Skeleton className="h-44 rounded-xl" />
      <Skeleton className="h-44 rounded-xl" />
    </div>
  </>;
  const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];
  const { tone, text, detail } = serviceTruth(svc, status);
  const onTab = (value: string) => setTab(value as Tab);
  const monitor = svc.spec.monitor;
  const result = svc.monitor;
  return <>
    <PageHeader back={{ to: "/services", label: "服务" }} title={<>
      {svc.name}<Tooltip>
        <TooltipTrigger>
          <StatusBadge tone={tone}>
            {text}
          </StatusBadge>
        </TooltipTrigger>
        {svc.status && <TooltipContent className="grid gap-0.5">
          {detail && <div className="font-medium">
            {detail}
          </div>}{statusLayers(svc.status).map((line) => <div key={line}>
            {line}
          </div>)}
        </TooltipContent>}
      </Tooltip>
    </>} description={<span className="flex items-center gap-1.5">
      <span className="font-mono text-xs">
        {sourceLabel(svc.spec.source)}
      </span>· 在 <ServerTag name={svc.spec.server} />
    </span>} actions={<OpBar ops={serviceOps} target={svc} label={`${svc.name} 的操作`} />} />
    <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
      <div className="-mx-1 overflow-x-auto px-1">
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="domains">域名{routes.length > 0 && <span className="ml-1 text-muted-foreground">
            {routes.length}
          </span>}
          </TabsTrigger>
          <TabsTrigger value="logs">日志</TabsTrigger>
          <TabsTrigger value="metrics">监控</TabsTrigger>
          <TabsTrigger value="history">历史</TabsTrigger>
          <TabsTrigger value="data">数据</TabsTrigger>
          <TabsTrigger value="terminal">终端</TabsTrigger>
          <TabsTrigger value="settings">设置</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="overview" className="mt-4">
        <Overview svc={svc} routes={routes} onTab={onTab} onBackup={() => settingsAt("backup")} />
      </TabsContent>
      <TabsContent value="domains" className="mt-4">
        <DomainsTab routes={routes} onAdd={() => setAddingRoute(true)} />
      </TabsContent>
      <TabsContent value="logs" className="mt-4">
        <LogStream path={`/api/services/${encodeURIComponent(name)}/logs/stream`} />
      </TabsContent>
      <TabsContent value="metrics" className="mt-4">
        <MetricsPanel subject={name} kind="svc" title="" />
        <SectionTitle>健康检查</SectionTitle>
        {monitor ? <Panel className="flex flex-wrap items-center gap-2 p-4 text-sm">
          {result && <>
            <Dot tone={result.ok ? "ok" : result.fails >= 3 ? "bad" : "warn"} />
            <span>
              {result.detail}{!result.ok && result.fails > 1 ? `（连续 ${result.fails} 次）` : ""}
            </span>
            <span className="text-xs text-muted-foreground">
              {ago(new Date(result.at).toISOString())}检查</span>
          </>}<span className="ml-auto font-mono text-xs text-muted-foreground">
            {monitor.path}{monitor.expect ? ` → ${monitor.expect}` : ""}{monitor.keyword ? ` 含“${monitor.keyword}”` : ""}
          </span>
        </Panel> : <Empty action={<Button onClick={() => settingsAt("monitor")}>去设置</Button>}>没开健康检查</Empty>}
      </TabsContent>
      <TabsContent value="history" className="mt-4">
        <HistoryTab name={name} />
      </TabsContent>
      <TabsContent value="data" className="mt-4">
        <DataTab svc={svc} onSettings={() => settingsAt("backup")} />
      </TabsContent>
      <TabsContent value="terminal" className="mt-4">
        <TerminalTab svc={svc} />
      </TabsContent>
      <TabsContent value="settings" forceMount className="mt-4 data-[state=inactive]:hidden">
        <Settings svc={svc} active={tab === "settings"} />
      </TabsContent>
    </Tabs>
    {params.get("repack") === "1" && <Repack svc={svc} onClose={() => { const next = new URLSearchParams(params); next.delete("repack"); setParams(next, { replace: true }); }} />}
    <AddRoute service={name} open={addingRoute} onClose={() => setAddingRoute(false)} />
  </>;
}
