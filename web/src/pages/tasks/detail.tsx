import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { usePoll } from "@/api";
import { Empty, ErrorNote, PageHeader, StatusBadge } from "@/components/common";
import { OpBar, taskOps } from "@/components/ops";
import { useTab } from "@/components/page-tabs";
import { useActions } from "@/components/actions";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { TaskView } from "@/types";
import { TaskForm } from "./form";
import { KIND, STATUS, cronText, where } from "./model";
import { Overview } from "./overview";
import { Runs } from "./runs";

const TABS = ["overview", "runs", "settings"] as const;

export function TaskDetail() {
  const { name = "" } = useParams();
  const actions = useActions();
  const { data, error, refresh } = usePoll<TaskView[]>("/api/tasks", 10000);
  const [tab, setTab] = useTab(TABS, "overview");
  useEffect(() => { window.addEventListener("wharf:tasks", refresh); return () => window.removeEventListener("wharf:tasks", refresh); }, [refresh]);
  const task = data?.find((t) => t.name === name);
  if (!data) return <>
    <ErrorNote error={error} />
    <Skeleton className="h-40 rounded-xl" />
  </>;
  if (!task) return <Empty>没有任务 {name}
  </Empty>;
  const last = task.last;
  const badge = !task.spec.enabled ? ["idle", "已停用"] as const : last ? STATUS[last.status] : ["idle", "没运行过"] as const;
  return <>
    <PageHeader back={{ to: "/tasks", label: "任务" }} title={<>
      {task.name}<StatusBadge tone={badge[0]}>
        {badge[1]}
      </StatusBadge>
    </>} description={`${KIND[task.spec.kind]} · ${where(task.spec)} · ${cronText(task.spec.schedule) ?? task.spec.schedule}`} actions={<OpBar ops={taskOps} target={task} label={`${task.name} 的操作`} />} />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList>
        <TabsTrigger value="overview">概览</TabsTrigger>
        <TabsTrigger value="runs">运行记录</TabsTrigger>
        <TabsTrigger value="settings">设置</TabsTrigger>
      </TabsList>
      <TabsContent value="overview" className="mt-4">
        <Overview task={task} onRuns={() => setTab("runs")} />
      </TabsContent>
      <TabsContent value="runs" className="mt-4">
        <Runs task={task} />
      </TabsContent>
      <TabsContent value="settings" className="mt-4">
        <TaskForm key={`${task.name}-${task.updated_at}`} task={task} taken={data.map((t) => t.name)} onSaved={() => refresh()} />
        <div className="mt-8 flex max-w-2xl items-center gap-3 rounded-xl border border-destructive/30 p-4">
          <span className="flex-1 text-sm">删除任务</span>
          <Button variant="destructive" size="sm" onClick={() => actions.removeTask(name)}>删除</Button>
        </div>
      </TabsContent>
    </Tabs>
  </>;
}
