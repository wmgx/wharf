import { ChevronRightIcon, TerminalIcon } from "lucide-react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CardsSkeleton, Empty, ErrorNote, PageHeader, StatusBadge, ago, type Tone } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { Run, ShellLog } from "@/types";

const TABS = ["runs", "shell"] as const;

const RUN_TONE: Record<Run["status"], [Tone, string]> = {
  running: ["warn", "执行中"],
  succeeded: ["ok", "成功"],
  failed: ["bad", "失败"],
  cancelled: ["idle", "已取消"],
};

/** 一次执行的标题：步骤标题合起来，太多时只列前两个。 */
function runTitle(r: Run): string {
  const titles = r.steps.map((s) => s.title);
  if (titles.length === 0) return "空执行";
  return titles.length <= 2 ? titles.join("、") : `${titles.slice(0, 2).join("、")} 等 ${titles.length} 步`;
}

function duration(from?: string, to?: string): string {
  if (!from || !to) return "";
  const s = Math.round((new Date(to).getTime() - new Date(from).getTime()) / 1000);
  return s < 60 ? `${s} 秒` : `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
}

/** 活动：执行记录（页面、CLI、AI 发起的都在这里）和宿主机命令审计。 */
export function Activity() {
  const [tab, setTab] = useTab(TABS, "runs");
  return (
    <>
      <PageHeader title="活动" description="谁在什么时候改了什么；点开可以回看每一步的日志" />
      <Tabs value={tab} onValueChange={(v) => setTab(v as (typeof TABS)[number])}>
        <TabsList className="mb-4">
          <TabsTrigger value="runs">执行记录</TabsTrigger>
          <TabsTrigger value="shell">宿主机命令</TabsTrigger>
        </TabsList>
        <TabsContent value="runs">{tab === "runs" && <Runs />}</TabsContent>
        <TabsContent value="shell">{tab === "shell" && <Shell />}</TabsContent>
      </Tabs>
    </>
  );
}

function Runs() {
  const { data, error } = usePoll<Run[]>("/api/runs?limit=50", 5000);
  const actions = useActions();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <CardsSkeleton count={2} />;
  if (data.length === 0) return <Empty>还没有执行过改动</Empty>;
  return (
    <div className="divide-y overflow-hidden rounded-xl border bg-card shadow-xs">
      {data.map((r) => {
        const [tone, text] = RUN_TONE[r.status];
        const title = runTitle(r);
        const failed = r.steps.find((s) => s.status === "failed");
        return (
          <button
            key={r.run_id}
            onClick={() => actions.view(r.run_id, title)}
            className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-accent/50"
          >
            <StatusBadge tone={tone}>{text}</StatusBadge>
            <div className="grid min-w-0 flex-1 gap-0.5">
              <span className="truncate text-sm font-medium">{title}</span>
              <span className="truncate text-xs text-muted-foreground">
                {[ago(r.started_at), duration(r.started_at, r.finished_at), failed?.error?.message].filter(Boolean).join(" · ")}
              </span>
            </div>
            <ChevronRightIcon className="size-4 shrink-0 text-muted-foreground" />
          </button>
        );
      })}
    </div>
  );
}

function Shell() {
  const { data, error } = usePoll<ShellLog[]>("/api/shell-log?limit=200", 10000);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <CardsSkeleton count={2} />;
  if (data.length === 0) return <Empty>还没有在宿主机上开过终端或执行过命令</Empty>;
  return (
    <div className="divide-y overflow-hidden rounded-xl border bg-card shadow-xs">
      {data.map((l) => {
        const ok = !l.error && (l.exit_code == null || l.exit_code === 0);
        return (
          <div key={l.id} className="flex items-start gap-3 px-4 py-3">
            <TerminalIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            <div className="grid min-w-0 flex-1 gap-0.5">
              <span className="truncate font-mono text-sm">{l.command ?? (l.kind === "terminal" ? "打开终端" : l.kind)}</span>
              <span className="truncate text-xs text-muted-foreground">
                {[l.server, l.actor, ago(l.at), l.duration_ms != null && `${(l.duration_ms / 1000).toFixed(1)} 秒`, l.error].filter(Boolean).join(" · ")}
              </span>
            </div>
            {l.exit_code != null && <StatusBadge tone={ok ? "ok" : "bad"}>{`退出 ${l.exit_code}`}</StatusBadge>}
          </div>
        );
      })}
    </div>
  );
}
