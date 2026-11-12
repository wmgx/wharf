import { ArrowLeftIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { Empty, ErrorNote, PageHeader, StatusBadge, ago, serverTone } from "@/components/common";
import { HostSessions } from "@/components/host-sessions";
import { MetricsPanel } from "@/components/metrics";
import { OpBar, serverOps } from "@/components/ops";
import { useTab } from "@/components/page-tabs";
import { ServiceUsage } from "@/components/usage";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useStatus } from "@/status";
import type { HostInfo } from "@/types";
import { type Traffic, uptime } from "./format";
import { ServerHostUnits } from "./host-units";
import { ServerLinks } from "./links";
import { Overview } from "./overview";
import { SettingsForm } from "./settings";
import { SystemInfo } from "./system";

function useHostInfo(name: string, online: boolean) {
  const [data, setData] = useState<HostInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(
        await api.get<HostInfo>(
          `/api/servers/${encodeURIComponent(name)}/host`,
        ),
      );
    } catch(e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [name]);
  useEffect(() => {
    setData(null);
    if (online) load();
  }, [load, online]);
  return { data, error, loading, load };
}

function useTraffic(name: string) {
  const [data, setData] = useState<Traffic | null>(null);
  useEffect(() => {
    setData(null);
    api
      .get<Traffic>(`/api/servers/${encodeURIComponent(name)}/traffic`)
      .then(setData)
      .catch(() => setData(null));
  }, [name]);
  return data;
}

const TABS = ["overview", "metrics", "network", "system", "host", "terminal", "settings"] as const;

export function ServerDetail() {
  const { name = "" } = useParams();
  const { status } = useStatus();
  const actions = useActions();
  const nav = useNavigate();
  const [tab, setTab] = useTab(TABS, "overview");
  const server = status?.servers.find((s) => s.name === name);
  const host = useHostInfo(name, !!server?.online);
  const traffic = useTraffic(name);
  const back = <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground md:hidden" to="/servers">
    <ArrowLeftIcon className="size-3.5" />服务器</Link>;
  if (!server || !status) return <>
    {back}{status ? <Empty>没有服务器 {name}
    </Empty> : <Skeleton className="h-44 rounded-xl" />}
  </>;
  const report = server.report;
  const info = host.data;
  const services = status.services.filter((s) => s.spec.server === name);
  const gateways = status.gateways.filter((g) => g.spec.server === name);
  const description = server.online ? [info?.os ?? report?.os, report?.arch, info && `已运行 ${uptime(info.uptime_secs)}`].filter(Boolean).join(" · ") : server.last_seen ? `最后在线 ${ago(server.last_seen)}` : undefined;
  const settingsAt = (part: string) => nav({ search: "?tab=settings", hash: `#${part}` });
  return <>
    {back}
    <PageHeader title={<>
      {name}<StatusBadge tone={serverTone(server)}>
        {!server.joined ? "等待加入" : server.online ? "在线" : "离线"}
      </StatusBadge>
    </>} description={description} actions={<OpBar ops={serverOps} target={server} label={`${server.name} 的操作`} />} />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList className="max-w-full justify-start overflow-x-auto">
        <TabsTrigger value="overview">概览</TabsTrigger>
        <TabsTrigger value="metrics">监控</TabsTrigger>
        <TabsTrigger value="network">网络</TabsTrigger>
        <TabsTrigger value="system">系统</TabsTrigger>
        <TabsTrigger value="host">宿主机程序</TabsTrigger>
        <TabsTrigger value="terminal">终端</TabsTrigger>
        <TabsTrigger value="settings">设置</TabsTrigger>
      </TabsList>
      <TabsContent value="overview" className="mt-4">
        <Overview server={server} status={status} info={info} traffic={traffic} loading={host.loading} />
      </TabsContent>
      <TabsContent value="metrics" className="mt-4">
        <MetricsPanel subject={name} kind="host" title="" />
        <ServiceUsage server={name} />
      </TabsContent>
      <TabsContent value="network" className="mt-4">
        <ServerLinks server={name} />
        <Button variant="outline" onClick={() => settingsAt("network")}>修改网络设置</Button>
      </TabsContent>
      <TabsContent value="system" className="mt-4">
        {!server.online ? <Empty>服务器离线，读不到系统信息</Empty> : !info ? <>
          <ErrorNote error={host.error} />
          <Skeleton className="h-40 rounded-xl" />
        </> : <SystemInfo info={info} server={server} onRefresh={host.load} loading={host.loading} />}
      </TabsContent>
      <TabsContent value="host" className="mt-4">
        {tab === "host" && <ServerHostUnits server={name} online={server.online} />}
      </TabsContent>
      <TabsContent value="terminal" className="mt-4">
        {!server.settings.host_terminal ? <Empty action={<Button onClick={() => settingsAt("access")}>去开启</Button>}>宿主机终端没有开启</Empty> : !server.online ? <Empty>服务器离线</Empty> : !server.host_shell ? <Empty action={<Button onClick={() => actions.upgradeAgent(name)}>升级 agent</Button>}>agent 版本太旧</Empty> : <HostSessions server={name} />}
      </TabsContent>
      <TabsContent value="settings" forceMount className="mt-4 data-[state=inactive]:hidden">
        <SettingsForm server={server} canRemove={services.length + gateways.length === 0} active={tab === "settings"} />
      </TabsContent>
    </Tabs>
  </>;
}
