import { LoaderCircleIcon } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { CodeBlock, Empty, ErrorNote, StatusBadge } from "@/components/common";
import { Panel } from "@/components/kit";
import { useOpCtx, taskOps } from "@/components/ops";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { TaskRunView, TaskView } from "@/types";
import { STATUS } from "./model";

export function Runs({ task }: { task: TaskView }) {
  const { data, error, refresh } = usePoll<TaskRunView[]>(`/api/tasks/${encodeURIComponent(task.name)}/runs?limit=20`, 10000);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => { window.addEventListener("wharf:tasks", refresh); return () => window.removeEventListener("wharf:tasks", refresh); }, [refresh]);
  const ctx = useOpCtx();
  const nav = useNavigate();
  const run = taskOps.find((op) => op.id === "run")!;
  const triggers: Record<string, string> = { schedule: "定时", scheduled: "定时", manual: "手动", ping: "报到", late: "迟到" };
  return <>
    <ErrorNote error={error} />
    {data?.length === 0 ? <Empty action={task.spec.kind !== "ping" ? <Button onClick={() => run.run(task, { ...ctx, nav })}>立即运行</Button> : undefined}>
      {task.spec.kind === "ping" ? "还没有收到过报到" : "还没有运行过"}
    </Empty> : !!data?.length && <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>开始</TableHead>
            <TableHead>耗时</TableHead>
            <TableHead>结果</TableHead>
            <TableHead>退出码</TableHead>
            <TableHead>触发</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((r) => <Fragment key={r.id}>
            <TableRow className="cursor-pointer" onClick={() => setOpen(open === r.id ? null : r.id)}>
              <TableCell>
                {new Date(r.started_at).toLocaleString("zh-CN")}
              </TableCell>
              <TableCell>
                {r.ended_at ? `${Math.round((new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()) / 1000)} 秒` : "-"}
              </TableCell>
              <TableCell>
                <StatusBadge tone={STATUS[r.status][0]}>
                  {r.status === "running" && <LoaderCircleIcon className="size-3 animate-spin" />}{STATUS[r.status][1]}
                </StatusBadge>
              </TableCell>
              <TableCell>
                {r.exit_code ?? "-"}
              </TableCell>
              <TableCell>
                {triggers[r.trigger] ?? r.trigger}
              </TableCell>
            </TableRow>
            {open === r.id && <TableRow>
              <TableCell colSpan={5}>
                <CodeBlock className="max-h-80 whitespace-pre-wrap break-all">
                  {r.output || "（没有输出）"}
                </CodeBlock>
              </TableCell>
            </TableRow>}
          </Fragment>)}
        </TableBody>
      </Table>
    </Panel>}
  </>;
}
