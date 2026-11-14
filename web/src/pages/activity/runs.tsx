import { ChevronRightIcon, LoaderCircleIcon } from "lucide-react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CardsSkeleton, Empty, ErrorNote, StatusBadge, ago, type Tone } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import type { Run } from "@/types";

const RUN_TONE: Record<Run["status"], [Tone, string]> = {
  running: ["warn", "执行中"],
  succeeded: ["ok", "成功"],
  failed: ["bad", "失败"],
  cancelled: ["idle", "已取消"],
};

/** 一次执行的标题：步骤标题合起来，太多时只列前两个。 */
export function runTitle(r: Run): string {
  const titles = r.steps.map((s) => s.title);
  if (titles.length === 0) return "空执行";
  return titles.length <= 2 ? titles.join("、") : `${titles.slice(0, 2).join("、")} 等 ${titles.length} 步`;
}

function duration(from?: string, to?: string): string {
  if (!from || !to) return "";
  const s = Math.round((new Date(to).getTime() - new Date(from).getTime()) / 1000);
  return s < 60 ? `${s} 秒` : `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
}

export function Runs() {
  const { data, error } = usePoll<Run[]>("/api/runs?limit=50", 5000);
  const actions = useActions();
  if (error) return <ErrorNote error={error} />;
  if (!data) return <CardsSkeleton count={2} />;
  if (data.length === 0) return <Empty>还没有执行过改动</Empty>;
  return (
    <Rows>
      {[...data].sort((a, b) => Number(b.status === "running") - Number(a.status === "running")).map((r) => {
        const [tone, text] = RUN_TONE[r.status];
        const title = runTitle(r);
        const failed = r.steps.find((s) => s.status === "failed");
        return (
          <Row key={r.run_id} onClick={() => actions.view(r.run_id, title)}>
            <StatusBadge tone={tone}>{r.status === "running" && <LoaderCircleIcon className="size-3 animate-spin" />}{text}</StatusBadge>
            <div className="grid min-w-0 flex-1 gap-0.5">
              <span className="truncate text-sm font-medium">{title}</span>
              <span className="truncate text-xs text-muted-foreground">
                {[ago(r.started_at), duration(r.started_at, r.finished_at), failed?.error?.message].filter(Boolean).join(" · ")}
              </span>
            </div>
            <ChevronRightIcon className="size-4 shrink-0 text-muted-foreground" />
          </Row>
        );
      })}
    </Rows>
  );
}
