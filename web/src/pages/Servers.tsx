import { ArrowUpCircleIcon, DatabaseIcon, NetworkIcon, PlusIcon, WaypointsIcon, WorkflowIcon } from "lucide-react";
import { lazy, Suspense, useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { AddServer } from "@/components/add-server";
import { Dot, Empty, PageHeader, serverTone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { Data } from "./Data";
import { GatewaysPanel } from "./Gateways";
import { NetworkPanel } from "./Network";
import { ServerDetail } from "./ServerDetail";

// 拓扑图依赖的 @xyflow/react 比较大，只在打开拓扑时加载。
const Topology = lazy(() => import("./Topology").then((m) => ({ default: m.Topology })));

/** 服务器下面除了每台机器，还有这些跨机器的页面。 */
const PANELS = [
  { tab: "entries", label: "入口", icon: WaypointsIcon, title: "入口", hint: undefined },
  { tab: "network", label: "组网", icon: NetworkIcon, title: "组网", hint: "机器之间怎么连：Tailscale、内网地址" },
  { tab: "topology", label: "拓扑", icon: WorkflowIcon, title: "拓扑", hint: "入口、服务器、服务之间的连接" },
  { tab: "data", label: "数据与备份", icon: DatabaseIcon, title: "数据与备份", hint: "每个服务的数据目录和备份" },
] as const;

type Panel = (typeof PANELS)[number]["tab"];

/** 服务器：左边是机器和跨机器的页面，右边是选中的那一项。 */
export function Servers() {
  const { name } = useParams();
  const { search } = useLocation();
  const { status } = useStatus();
  const tab = new URLSearchParams(search).get("tab") as Panel | null;
  const panel = PANELS.find((p) => p.tab === tab);

  // 没选任何一项：默认打开第一台服务器。
  if (!name && !panel && status?.servers.length) {
    return <Navigate to={`/servers/${encodeURIComponent(status.servers[0].name)}`} replace />;
  }

  return (
    <div className="flex flex-wrap items-start gap-6">
      <Side name={name} tab={panel?.tab} />
      <div className="min-w-0 flex-[999_1_560px]">
        {name ? (
          <ServerDetail key={name} />
        ) : panel ? (
          <>
            <PageHeader title={panel.title} description={panel.hint} />
            <PanelBody tab={panel.tab} />
          </>
        ) : !status ? (
          <Skeleton className="h-64 rounded-xl" />
        ) : (
          <Empty>还没有服务器。点左边"加服务器"，在那台机器上执行给出的一条命令，agent 连上后这里会出现。</Empty>
        )}
      </div>
    </div>
  );
}

function PanelBody({ tab }: { tab: Panel }) {
  switch (tab) {
    case "entries":
      return <GatewaysPanel />;
    case "network":
      return <NetworkPanel />;
    case "data":
      return <Data />;
    case "topology":
      return (
        <Suspense fallback={<Skeleton className="h-[480px] rounded-xl" />}>
          <Topology />
        </Suspense>
      );
  }
}

const item = "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors hover:bg-accent";

function Side({ name, tab }: { name?: string; tab?: Panel }) {
  const { status } = useStatus();
  const [adding, setAdding] = useState(false);

  return (
    <nav className="grid w-full gap-4 md:sticky md:top-4 md:w-60 md:flex-none">
      <div className="grid gap-0.5">
        <Heading>服务器</Heading>
        {!status
          ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-12 rounded-lg" />)
          : status.servers.map((s) => {
              const count = status.services.filter((v) => v.spec.server === s.name).length;
              return (
                <Entry key={s.name} to={`/servers/${encodeURIComponent(s.name)}`} on={s.name === name}>
                  <Dot tone={serverTone(s)} />
                  <span className="grid min-w-0 flex-1">
                    <span className="flex items-center gap-1.5 font-medium">
                      {s.name}
                      {s.agent_outdated && <ArrowUpCircleIcon className="size-3.5 text-warning" aria-label="agent 可升级" />}
                    </span>
                    <span className="truncate text-xs text-muted-foreground">
                      {s.online ? `${count} 个服务${s.rtt_ms != null ? ` · ${s.rtt_ms} ms` : ""}` : "离线"}
                    </span>
                  </span>
                </Entry>
              );
            })}
        <Button variant="ghost" size="sm" className="justify-start text-muted-foreground" onClick={() => setAdding(true)}>
          <PlusIcon />
          加服务器
        </Button>
      </div>
      <div className="grid gap-0.5">
        <Heading>全部机器</Heading>
        {PANELS.map((p) => (
          <Entry key={p.tab} to={`/servers?tab=${p.tab}`} on={p.tab === tab}>
            <p.icon className="size-4 text-muted-foreground" />
            {p.label}
          </Entry>
        ))}
      </div>
      <AddServer open={adding} onClose={() => setAdding(false)} />
    </nav>
  );
}

function Heading({ children }: { children: ReactNode }) {
  return <div className="px-2.5 pb-1 text-xs font-medium text-muted-foreground">{children}</div>;
}

function Entry({ to, on, children }: { to: string; on: boolean; children: ReactNode }) {
  return (
    <Link to={to} aria-current={on ? "page" : undefined} className={cn(item, on && "bg-accent font-medium")}>
      {children}
    </Link>
  );
}
