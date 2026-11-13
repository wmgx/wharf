import { LoaderIcon } from "lucide-react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Button } from "@/components/ui/button";
import { runTitle } from "@/pages/activity/runs";
import type { Run } from "@/types";

/** 顶栏：有执行在跑时显示在做什么、到第几步，点开看每一步和取消。 */
export function Running() {
  const { data } = usePoll<Run[]>("/api/runs?limit=5", 3000);
  const actions = useActions();
  const run = data?.find((r) => r.status === "running");
  if (!run) return null;
  const done = run.steps.filter((s) => s.status !== "running" && s.status !== "pending").length;
  const current = run.steps.find((s) => s.status === "running") ?? run.steps[done];
  const title = runTitle(run);
  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-8 min-w-0 gap-1.5 bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
      title={`${run.run_id}：${title}`}
      onClick={() => actions.view(run.run_id, title)}
    >
      <LoaderIcon className="animate-spin" />
      <span className="truncate">
        <span className="hidden sm:inline">正在执行 </span>
        {done}/{run.steps.length}
        <span className="hidden md:inline">：{current?.title ?? title}</span>
      </span>
    </Button>
  );
}
