import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { CodeBlock, CopyButton, SectionTitle, StatusBadge } from "@/components/common";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { TaskRunView, TaskView } from "@/types";
import { KIND, STATUS, cronText, where } from "./model";

export function Overview({ task, onRuns }: { task: TaskView; onRuns: () => void }) {
  const { data } = usePoll<TaskRunView[]>(`/api/tasks/${encodeURIComponent(task.name)}/runs?limit=5`, 10000);
  const s = task.spec;
  const triggers: Record<string, string> = { schedule: "定时", scheduled: "定时", manual: "手动", ping: "报到", late: "迟到" };
  const friendly = cronText(s.schedule);
  return <>
    {s.kind === "ping" && task.ping_url && <Panel className="mb-3 grid gap-2 p-4">
      <p className="text-sm">脚本跑完后请求这个地址，没按时请求就会通知。</p>
      {[task.ping_url, `${task.ping_url}/fail`].map((url) => <div key={url} className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 flex-1 break-all font-mono text-xs">
          {url}
        </span>
        <CopyButton text={url} />
      </div>)}<div className="flex min-w-0 items-start gap-2">
        <CodeBlock className="min-w-0 flex-1 break-all">
          {`curl -fsS -m 10 ${task.ping_url}`}
        </CodeBlock>
        <CopyButton text={`curl -fsS -m 10 ${task.ping_url}`} />
      </div>
    </Panel>}
    <Panel className="p-4">
      <Facts items={[
        ["形式", KIND[s.kind]], ["在哪", where(s)],
        ["时间", <>
          {friendly && <span>
            {friendly} </span>}<span className="font-mono text-xs text-muted-foreground">
            {s.schedule}
          </span> <span className="text-xs text-muted-foreground">北京时间</span>
        </>],
        ["下次", !s.enabled ? "-" : task.next_at ? new Date(task.next_at).toLocaleString("zh-CN") : "-"],
        ["超时", s.kind === "ping" ? `宽限 ${s.grace_mins} 分钟` : `${s.timeout_secs} 秒`], ["失败时通知", s.notify ? "是" : "否"],
        ["服务", s.kind === "exec" && <Link to={`/services/${encodeURIComponent(s.service)}`} className="hover:underline">
          {s.service}
        </Link>],
        ["镜像", s.kind === "container" && s.image],
        ["命令", s.kind !== "ping" && s.command && <CodeBlock className="max-h-40 whitespace-pre-wrap break-all">
          {s.command}
        </CodeBlock>],
      ]} />
    </Panel>
    {!!data?.length && <>
      <SectionTitle action={<Button variant="ghost" size="xs" onClick={onRuns}>全部</Button>}>最近 5 次</SectionTitle>
      <Rows>
        {data.map((r) => <Row key={r.id}>
          <StatusBadge tone={STATUS[r.status][0]}>
            {STATUS[r.status][1]}
          </StatusBadge>
          <span>
            {new Date(r.started_at).toLocaleString("zh-CN")}
          </span>
          <span className="text-xs text-muted-foreground">
            {r.ended_at ? `${Math.round((new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()) / 1000)} 秒` : "-"}
          </span>
          <span className="text-xs text-muted-foreground">
            {triggers[r.trigger] ?? r.trigger}
          </span>
        </Row>)}
      </Rows>
    </>}
  </>;
}
