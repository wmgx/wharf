import { ArrowUpCircleIcon, PlusIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { AddServer } from "@/components/add-server";
import { Dot, Empty, ago, serverTone } from "@/components/common";
import { Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { ServerDetail } from "./detail";

/** 旧地址 `/servers?tab=x` 指向的页面，现在是独立页面。 */
const OLD_TABS: Record<string, string> = { entries: "/domains?tab=entries", network: "/network", topology: "/network", data: "/data" };

/** 服务器：左边一列机器，贴着侧边栏；右边是选中那台的详情。 */
export function Servers() {
  const { name } = useParams();
  const { search } = useLocation();
  const { status } = useStatus();
  const [adding, setAdding] = useState(false);
  const params = new URLSearchParams(search);
  // 只有不带机器名的 `/servers?tab=x` 才是旧地址；`/servers/home?tab=network` 是服务器自己的标签。
  const old = name ? undefined : OLD_TABS[params.get("tab") ?? ""];

  if (old) {
    params.delete("tab");
    if (old === "/domains?tab=entries" && params.has("open")) {
      params.set("entry", params.get("open")!);
      params.delete("open");
    }
    const q = params.toString();
    return <Navigate to={q ? `${old}${old.includes("?") ? "&" : "?"}${q}` : old} replace />;
  }
  // 没选机器：默认打开第一台。
  if (!name && status?.servers.length) {
    return <Navigate to={`/servers/${encodeURIComponent(status.servers[0].name)}`} replace />;
  }

  return (
    <div className="flex min-w-0 flex-1 flex-col md:flex-row">
      <Side name={name} onAdd={() => setAdding(true)} />
      <div className="min-w-0 flex-1 px-4 py-5 md:px-8 md:py-8">
        <div className="mx-auto max-w-5xl">
          {name ? (
            <ServerDetail key={name} />
          ) : !status ? (
            <Skeleton className="h-64 rounded-xl" />
          ) : (
            <Empty action={<Button onClick={() => setAdding(true)}>加服务器</Button>}>还没有服务器</Empty>
          )}
        </div>
      </div>
      <AddServer open={adding} onClose={() => setAdding(false)} />
    </div>
  );
}

const item = "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors hover:bg-accent";

function Side({ name, onAdd }: { name?: string; onAdd: () => void }) {
  const { status } = useStatus();
  const today = Date.parse(`${new Date().toLocaleDateString("sv-SE", { timeZone: "Asia/Shanghai" })}T00:00:00+08:00`);

  return (
    <nav className="sticky top-14 z-[5] flex gap-1 overflow-x-auto border-b bg-background p-2 md:flex md:flex-col md:gap-0.5 md:overflow-x-visible md:sticky md:top-14 md:h-[calc(100svh-3.5rem)] md:w-56 md:flex-none md:overflow-y-auto md:border-r md:border-b-0">
      {!status
        ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-12 rounded-lg" />)
        : status.servers.map((s) => {
            const count = status.services.filter((v) => v.spec.server === s.name).length;
            const days = s.settings.renew_at ? Math.round((Date.parse(`${s.settings.renew_at}T00:00:00+08:00`) - today) / 86400000) : undefined;
            return (
              <Entry key={s.name} to={`/servers/${encodeURIComponent(s.name)}`} on={s.name === name}>
                <Dot tone={serverTone(s)} />
                <span className="grid min-w-0 flex-1">
                  <span className="flex items-center gap-1.5 font-medium">
                    {s.name}
                    {s.agent_outdated && <Tip text="agent 可以升级"><span><ArrowUpCircleIcon className="size-3.5 text-warning" /></span></Tip>}
                  </span>
                  <span className="truncate text-xs text-muted-foreground">
                    {!s.joined ? "等待加入" : s.online ? `${count} 个服务` : `离线${s.last_seen ? ` · ${ago(s.last_seen)}` : ""}`}
                    {days != null && <span className={days < 14 ? "text-warning" : undefined}> · {days < 0 ? "续费日已过" : `续费 ${days} 天后`}</span>}
                  </span>
                </span>
              </Entry>
            );
          })}
      <Button variant="outline" size="sm" className="shrink-0 justify-start md:mt-auto md:shrink" onClick={onAdd}>
        <PlusIcon />
        <span className="hidden md:inline">加服务器</span>
      </Button>
    </nav>
  );
}

function Entry({ to, on, children }: { to: string; on: boolean; children: ReactNode }) {
  return (
    <Link to={to} aria-current={on ? "page" : undefined} className={cn(item, "shrink-0 md:shrink", on && "bg-accent font-medium")}>
      {children}
    </Link>
  );
}
