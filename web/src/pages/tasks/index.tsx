import { useEffect } from "react";
import { PlusIcon } from "lucide-react";
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { Empty, ErrorNote, PageHeader, StatusBadge, ago, useClickable } from "@/components/common";
import { Segmented } from "@/components/fields";
import { Panel } from "@/components/kit";
import { OpMenu, taskOps } from "@/components/ops";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { TaskView } from "@/types";
import { TaskForm } from "./form";
import { KIND, STATUS, cronText, where } from "./model";

export function TasksPage() {
  const { status } = useStatus();
  const { data, error, refresh } = usePoll<TaskView[]>("/api/tasks", 10000);
  const [params, setParams] = useSearchParams();
  const [failed, setFailed] = useState(false);
  useEffect(() => { window.addEventListener("wharf:tasks", refresh); return () => window.removeEventListener("wharf:tasks", refresh); }, [refresh]);
  const nav = useNavigate();
  const clickable = useClickable();
  const server = params.get("server") ?? "";
  const failures = (data ?? []).filter((t) => t.last?.status === "failed" || t.last?.status === "timed_out");
  const rows = (data ?? []).filter((t) => (!server || t.spec.server === server) && (!failed || t.last?.status === "failed" || t.last?.status === "timed_out"));
  const add = <Button onClick={() => { const next = new URLSearchParams(params); next.set("new", "1"); setParams(next); }}>
    <PlusIcon />新建任务</Button>;
  const close = () => { const next = new URLSearchParams(params); next.delete("new"); setParams(next); };
  return <>
    <PageHeader title="任务" count={data?.length} actions={add} />
    <div className="mb-4 flex flex-wrap items-center gap-2">
      <div className="max-w-full overflow-x-auto">
        <Segmented value={server} options={[["", "全部"], ...(status?.servers ?? []).map((s): [string, string] => [s.name, s.name])]} onChange={(v) => { const next = new URLSearchParams(params); if (v) next.set("server", v); else next.delete("server"); setParams(next, { replace: true }); }} />
      </div>
      {failures.length > 0 && <Button variant={failed ? "secondary" : "outline"} size="sm" onClick={() => setFailed(!failed)}>只看失败的</Button>}
    </div>
    <ErrorNote error={error} />
    {!data ? <Skeleton className="h-40 rounded-xl" /> : data.length === 0 ? <Empty action={add}>还没有任务</Empty> : rows.length === 0 ? <Empty>没有符合条件的任务</Empty> : <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>任务</TableHead>
            <TableHead>形式</TableHead>
            <TableHead>在哪</TableHead>
            <TableHead>时间</TableHead>
            <TableHead>上次</TableHead>
            <TableHead>下次</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((t) => {
            const friendly = cronText(t.spec.schedule);
            return <TableRow key={t.name} className="cursor-pointer" {...clickable({ to: `/tasks/${encodeURIComponent(t.name)}` })}>
              <TableCell className="font-medium">
                {t.name} {!t.spec.enabled && <Badge variant="outline">已停用</Badge>}
              </TableCell>
              <TableCell>
                {KIND[t.spec.kind]}
              </TableCell>
              <TableCell>
                {where(t.spec)}
              </TableCell>
              <TableCell>
                <div>
                  {t.spec.kind === "ping" && "预期 "}{friendly ?? t.spec.schedule}
                </div>
                {friendly && <div className="font-mono text-xs text-muted-foreground">
                  {t.spec.schedule}
                </div>}
              </TableCell>
              <TableCell>
                {t.last ? <>
                  <StatusBadge tone={STATUS[t.last.status][0]}>
                    {STATUS[t.last.status][1]}
                  </StatusBadge>
                  <div className="text-xs text-muted-foreground">
                    {ago(t.last.started_at)}
                  </div>
                </> : "没运行过"}
              </TableCell>
              <TableCell>
                {!t.spec.enabled ? "-" : t.next_at ? new Date(t.next_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "-"}
              </TableCell>
              <TableCell onClick={(e) => e.stopPropagation()}>
                <OpMenu ops={taskOps} target={t} label={`${t.name} 的操作`} size="icon-sm" />
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
    <Sheet open={params.get("new") === "1"} onOpenChange={(open) => !open && close()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        <SheetHeader className="border-b">
          <SheetTitle>新建任务</SheetTitle>
        </SheetHeader>
        <div className="flex-1 overflow-auto p-4">
          {params.get("new") === "1" && <TaskForm task={null} server={server || undefined} taken={(data ?? []).map((t) => t.name)} onCancel={close} onSaved={(name) => { close(); refresh(); nav(`/tasks/${encodeURIComponent(name)}`); }} />}
        </div>
      </SheetContent>
    </Sheet>
  </>;
}
