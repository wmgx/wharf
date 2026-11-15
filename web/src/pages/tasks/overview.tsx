import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { CodeBlock, CopyButton, SectionTitle, StatusBadge } from "@/components/common";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { TaskRunView, TaskView } from "@/types";
import { KIND, STATUS, cronText, where } from "./model";

export function Overview({ task, onRuns }: { task: TaskView; onRuns: () => void }) {
  const { data } = usePoll<TaskRunView[]>(`/api/tasks/${encodeURIComponent(task.name)}/runs?limit=50`, 10000);
  const s = task.spec;
  const recent = (data ?? []).filter((r) => r.status !== "skipped" && r.status !== "running");
  const durations = recent.filter((r) => r.ended_at).map((r) => new Date(r.ended_at!).getTime() - new Date(r.started_at).getTime()).sort((a, b) => a - b);
  const middle = Math.floor(durations.length / 2);
  const median = durations.length ? (durations[middle] + durations[Math.floor((durations.length - 1) / 2)]) / 2 : null;
  const peaks = recent.flatMap((r) => r.mem_peak == null ? [] : [r.mem_peak]);
  const triggers: Record<string, string> = { schedule: "定时", scheduled: "定时", manual: "手动", hook: "网址", ping: "报到", late: "迟到" };
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
    {s.kind === "script" && task.hook_url && <Panel className="mb-3 grid gap-2 p-4">
      <span className="text-sm">触发地址</span>
      <div className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 flex-1 break-all font-mono text-xs">{task.hook_url}</span>
        <CopyButton text={task.hook_url} />
      </div>
      {!task.hook_url.startsWith("https://") && <span className="text-xs text-muted-foreground">控制面还没有公网域名，外部调不到</span>}
    </Panel>}
    <Panel className="p-4">
      <Facts items={[
        ["形式", KIND[s.kind]], ["在哪", where(s)],
        ["时间", !s.schedule ? "不定时" : <>
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
        ["运行环境", s.kind === "script" && ({ python: "Python", node: "Node", shell: "Shell" }[s.runtime])],
        ["镜像", (s.kind === "container" || s.kind === "script") && s.image],
        ["持久目录", s.kind === "script" && (task.data_bytes == null ? "未知" : `${task.data_bytes} 字节`)],
        ["依赖", s.kind === "script" && s.deps && <CodeBlock className="whitespace-pre-wrap break-all">{s.deps}</CodeBlock>],
        ["代码", s.kind === "script" && <CodeBlock className="max-h-80 whitespace-pre-wrap break-all">{s.code}</CodeBlock>],
        ["命令", s.kind !== "ping" && s.kind !== "script" && s.command && <CodeBlock className="max-h-40 whitespace-pre-wrap break-all">
          {s.command}
        </CodeBlock>],
      ]} />
    </Panel>
    {s.kind === "script" && recent.length > 0 && <>
      <SectionTitle>最近 {recent.length} 次运行</SectionTitle>
      <Panel className="p-4"><Facts items={[
        ["运行次数", String(recent.length)],
        ["成功率", `${Math.round(recent.filter((r) => r.status === "succeeded").length / recent.length * 100)}%`],
        ["耗时中位数", median == null ? "—" : `${(median / 1000).toFixed(1)} 秒`],
        ["最长耗时", durations.length ? `${(durations[durations.length - 1] / 1000).toFixed(1)} 秒` : "—"],
        ["内存峰值", peaks.length ? `${(Math.max(...peaks) / 1024 / 1024).toFixed(1)} MB` : "—"],
      ]} /></Panel>
    </>}
    {!!data?.length && <>
      <SectionTitle action={<Button variant="ghost" size="xs" onClick={onRuns}>全部</Button>}>最近 5 次</SectionTitle>
      <Rows>
        {data.slice(0, 5).map((r) => <Row key={r.id}>
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
