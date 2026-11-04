import { ArrowUpCircleIcon, PlusIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { AddServer } from "@/components/add-server";
import { Dot, Empty, serverTone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { ServerDetail } from "./ServerDetail";

/** 旧地址 `/servers?tab=x` 指向的页面，现在是独立页面。 */
const OLD_TABS: Record<string, string> = { entries: "/entries", network: "/network", topology: "/network", data: "/data" };

/** 服务器：左边一列机器，贴着侧边栏；右边是选中那台的详情。 */
export function Servers() {
  const { name } = useParams();
  const { search } = useLocation();
  const { status } = useStatus();
  const params = new URLSearchParams(search);
  const old = OLD_TABS[params.get("tab") ?? ""];

  if (old) {
    params.delete("tab");
    const q = params.toString();
    return <Navigate to={q ? `${old}?${q}` : old} replace />;
  }
  // 没选机器：默认打开第一台。
  if (!name && status?.servers.length) {
    return <Navigate to={`/servers/${encodeURIComponent(status.servers[0].name)}`} replace />;
  }

  return (
    <div className="flex flex-1 flex-col md:flex-row">
      <Side name={name} />
      <div className="min-w-0 flex-1 px-4 py-8 md:px-8">
        <div className="mx-auto max-w-5xl">
          {name ? (
            <ServerDetail key={name} />
          ) : !status ? (
            <Skeleton className="h-64 rounded-xl" />
          ) : (
            <Empty>还没有服务器。点左边"加服务器"，在那台机器上执行给出的一条命令，agent 连上后这里会出现。</Empty>
          )}
        </div>
      </div>
    </div>
  );
}

const item = "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors hover:bg-accent";

function Side({ name }: { name?: string }) {
  const { status } = useStatus();
  const [adding, setAdding] = useState(false);

  return (
    <nav className="grid content-start gap-0.5 border-b p-2 md:sticky md:top-14 md:h-[calc(100svh-3.5rem)] md:w-56 md:flex-none md:overflow-y-auto md:border-r md:border-b-0">
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
      <AddServer open={adding} onClose={() => setAdding(false)} />
    </nav>
  );
}

function Entry({ to, on, children }: { to: string; on: boolean; children: ReactNode }) {
  return (
    <Link to={to} aria-current={on ? "page" : undefined} className={cn(item, on && "bg-accent font-medium")}>
      {children}
    </Link>
  );
}
