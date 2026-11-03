import { ArrowUpCircleIcon, PlusIcon, ServerIcon } from "lucide-react";
import { lazy, Suspense, useState } from "react";
import { AddServer } from "@/components/add-server";
import { CardsSkeleton, CopyButton, Dot, useClickable, Empty, PageHeader, StatusBadge, ago, diskText, serverText, serverTone } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useStatus } from "@/status";
import type { ServerView, Status } from "@/types";
import { NetworkPanel } from "./Network";

const TABS = ["list", "topology", "network"] as const;

// 拓扑图依赖的 @xyflow/react 比较大，只在打开拓扑标签时加载。
const Topology = lazy(() => import("./Topology").then((m) => ({ default: m.Topology })));

/** 服务器：每台一张卡片；组网是一个标签。 */
export function Servers() {
  const { status } = useStatus();
  const [tab, setTab] = useTab(TABS, "list");
  const [adding, setAdding] = useState(false);

  return (
    <>
      <PageHeader
        title="服务器"
        description={status ? `${status.servers.filter((s) => s.online).length} / ${status.servers.length} 台在线` : "载入中…"}
        actions={
          <Button onClick={() => setAdding(true)}>
            <PlusIcon />
            加服务器
          </Button>
        }
      />
      <Tabs value={tab} onValueChange={(v) => setTab(v as (typeof TABS)[number])}>
        <TabsList className="mb-4">
          <TabsTrigger value="list">服务器</TabsTrigger>
          <TabsTrigger value="topology">拓扑</TabsTrigger>
          <TabsTrigger value="network">组网</TabsTrigger>
        </TabsList>
        <TabsContent value="list">
          {!status ? (
            <CardsSkeleton count={3} />
          ) : status.servers.length === 0 ? (
            <Empty>
              还没有服务器。点右上角"加服务器"，在那台机器上执行给出的一条命令，agent 连上后这里会出现。
            </Empty>
          ) : (
            <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,300px),1fr))] gap-3">
              {status.servers.map((s) => (
                <ServerCard key={s.name} s={s} status={status} />
              ))}
            </div>
          )}
        </TabsContent>
        <TabsContent value="topology">
          {tab === "topology" && (
            <Suspense fallback={<Skeleton className="h-[480px] rounded-xl" />}>
              <Topology />
            </Suspense>
          )}
        </TabsContent>
        <TabsContent value="network">{tab === "network" && <NetworkPanel />}</TabsContent>
      </Tabs>
      <AddServer open={adding} onClose={() => setAdding(false)} />
    </>
  );
}

function ServerCard({ s, status }: { s: ServerView; status: Status }) {
  const services = status.services.filter((v) => v.spec.server === s.name);
  const gateways = status.gateways.filter((g) => g.spec.server === s.name);
  const disk = diskText(s);
  const tone = serverTone(s);
  const r = s.report;
  const clickable = useClickable();

  return (
    <div
      {...clickable({ to: `/servers/${encodeURIComponent(s.name)}` })}
      className="flex cursor-pointer flex-col gap-3 rounded-xl border bg-card p-4 shadow-xs transition-all hover:-translate-y-px hover:border-foreground/15 hover:shadow-md"
    >
      <div className="flex items-center gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg border bg-muted text-muted-foreground">
          <ServerIcon className="size-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 font-semibold">
            {s.name}
            {s.agent_outdated && (
              <Badge variant="outline" className="gap-1 border-warning/50 font-normal text-warning">
                <ArrowUpCircleIcon className="size-3" />
                可升级
              </Badge>
            )}
          </div>
          <div className="truncate text-xs text-muted-foreground">{r ? `${r.os} · ${r.arch}` : s.joined ? "等待上报" : "还没加入"}</div>
        </div>
        <StatusBadge tone={tone}>{serverText(s)}</StatusBadge>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">公网</dt>
        <dd className="flex min-w-0 items-center gap-0.5 font-mono">
          <span className="truncate">{s.public_ip ?? "-"}</span>
          {s.public_ip && <CopyButton text={s.public_ip} className="size-5" />}
        </dd>
        <dt className="text-muted-foreground">内网</dt>
        <dd className="flex min-w-0 items-center gap-0.5 font-mono">
          <span className="truncate">{s.private_addr?.ip ?? "-"}</span>
          {s.private_addr?.ip && <CopyButton text={s.private_addr.ip} className="size-5" />}
        </dd>
        <dt className="text-muted-foreground">磁盘剩余</dt>
        <dd className={disk?.low ? "text-warning" : undefined}>{disk?.text ?? "-"}</dd>
        {!s.online && s.last_seen && (
          <>
            <dt className="text-muted-foreground">最后在线</dt>
            <dd>{ago(s.last_seen)}</dd>
          </>
        )}
      </dl>
      <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
        {services.length + gateways.length === 0 && <span>上面还没有服务</span>}
        {services.map((v) => (
          <span key={v.name} className="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5">
            <Dot tone={v.status?.tone ?? "idle"} />
            {v.name}
          </span>
        ))}
        {gateways.map((g) => (
          <span key={g.name} className="inline-flex items-center gap-1 rounded-md border border-dashed px-1.5 py-0.5">
            入口 {g.name}
          </span>
        ))}
      </div>
    </div>
  );
}
