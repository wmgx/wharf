import {
  HistoryIcon,
  PencilIcon,
  PlayIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import {
  ago,
  CodeBlock,
  Empty,
  ErrorNote,
  StatusBadge,
  type Tone,
} from "@/components/common";
import {
  Field,
  formatEnv,
  Picker,
  parseEnv,
  Segmented,
  toName,
} from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { TaskRunView, TaskSpec, TaskStatus, TaskView } from "@/types";

const STATUS: Record<TaskStatus, [Tone, string]> = {
  running: ["warn", "运行中"],
  succeeded: ["ok", "成功"],
  failed: ["bad", "失败"],
  timed_out: ["bad", "超时"],
  skipped: ["idle", "跳过"],
};
const KIND = {
  exec: "容器内",
  container: "一次性容器",
  host: "宿主机",
} as const;

/** 服务器详情的"定时任务"标签。 */
export function ServerTasks({ server }: { server: string }) {
  const { data, error, refresh } = usePoll<TaskView[]>("/api/tasks", 10000);
  const [editing, setEditing] = useState<TaskView | "new" | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const tasks = data?.filter((t) => t.spec.server === server);

  const run = async (name: string) => {
    try {
      await api.post(`/api/tasks/${encodeURIComponent(name)}/run`, {});
      toast.success(`已开始运行 ${name}`);
      refresh();
    } catch (e) {
      toast.error(`没能运行 ${name}`, { description: (e as Error).message });
    }
  };

  const remove = async (name: string) => {
    setRemoving(null);
    try {
      await api.del(`/api/tasks/${encodeURIComponent(name)}`);
      toast.success(`已删除 ${name}`);
      refresh();
    } catch (e) {
      toast.error(`不能删除 ${name}`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <div className="mb-3 flex justify-end">
        <Button variant="ghost" size="sm" onClick={() => setEditing("new")}>
          <PlusIcon />
          新建
        </Button>
      </div>
      <ErrorNote error={error} />
      {tasks && tasks.length === 0 ? (
        <Empty>没有定时任务</Empty>
      ) : (
        tasks && (
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>时间</TableHead>
                  <TableHead>形式</TableHead>
                  <TableHead>上次</TableHead>
                  <TableHead>下次</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tasks.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {t.spec.schedule}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {KIND[t.spec.kind]}
                      {t.spec.kind === "exec" && ` · ${t.spec.service}`}
                    </TableCell>
                    <TableCell>
                      {t.last ? (
                        <span className="flex items-center gap-2">
                          <StatusBadge tone={STATUS[t.last.status][0]}>
                            {STATUS[t.last.status][1]}
                          </StatusBadge>
                          <span className="text-xs text-muted-foreground">
                            {ago(t.last.started_at)}
                          </span>
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          没运行过
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {!t.spec.enabled
                        ? "已停用"
                        : t.next_at
                          ? new Date(t.next_at).toLocaleString("zh-CN", {
                              month: "2-digit",
                              day: "2-digit",
                              hour: "2-digit",
                              minute: "2-digit",
                            })
                          : "-"}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label="立即运行"
                          title="立即运行"
                          onClick={() => run(t.name)}
                        >
                          <PlayIcon />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label="运行记录"
                          title="运行记录"
                          onClick={() => setHistory(t.name)}
                        >
                          <HistoryIcon />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label="编辑"
                          title="编辑"
                          onClick={() => setEditing(t)}
                        >
                          <PencilIcon />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          className="text-destructive"
                          aria-label="删除"
                          title="删除"
                          onClick={() => setRemoving(t.name)}
                        >
                          <Trash2Icon />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )
      )}
      {editing && (
        <EditTask
          server={server}
          task={editing === "new" ? null : editing}
          taken={(data ?? []).map((t) => t.name)}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}
      {history && <Runs name={history} onClose={() => setHistory(null)} />}
      <Dialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <DialogContent aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>删除定时任务 {removing}？</DialogTitle>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRemoving(null)}>
              取消
            </Button>
            <Button
              variant="destructive"
              onClick={() => removing && remove(removing)}
            >
              删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function Runs({ name, onClose }: { name: string; onClose: () => void }) {
  const { data, error } = usePoll<TaskRunView[]>(
    `/api/tasks/${encodeURIComponent(name)}/runs?limit=20`,
    5000,
  );
  const [open, setOpen] = useState<number | null>(null);
  const shown = data?.find((r) => r.id === open) ?? data?.[0];
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{name} 的运行记录</DialogTitle>
        </DialogHeader>
        <ErrorNote error={error} />
        {data && data.length === 0 && <Empty>没有运行记录</Empty>}
        {data && data.length > 0 && (
          <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
            <ul className="max-h-[460px] overflow-auto rounded-lg border">
              {data.map((r) => (
                <li key={r.id}>
                  <button
                    className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs hover:bg-muted ${shown?.id === r.id ? "bg-muted" : ""}`}
                    onClick={() => setOpen(r.id)}
                  >
                    <span>
                      {ago(r.started_at)}
                      {r.trigger === "manual" ? " · 手动" : ""}
                    </span>
                    <StatusBadge tone={STATUS[r.status][0]}>
                      {STATUS[r.status][1]}
                    </StatusBadge>
                  </button>
                </li>
              ))}
            </ul>
            {shown && (
              <div className="min-w-0">
                <div className="mb-2 text-xs text-muted-foreground">
                  #{shown.id} ·{" "}
                  {new Date(shown.started_at).toLocaleString("zh-CN")}
                  {shown.ended_at &&
                    ` · ${Math.round((new Date(shown.ended_at).getTime() - new Date(shown.started_at).getTime()) / 1000)} 秒`}
                  {shown.exit_code !== undefined &&
                    ` · 退出码 ${shown.exit_code}`}
                </div>
                <CodeBlock className="whitespace-pre-wrap break-all">
                  {shown.output || "（没有输出）"}
                </CodeBlock>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

type Kind = TaskSpec["kind"];

/** 只在打开时挂载。 */
function EditTask({
  server,
  task,
  taken,
  onClose,
  onSaved,
}: {
  server: string;
  task: TaskView | null;
  taken: string[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { status } = useStatus();
  const s = task?.spec;
  const [name, setName] = useState(task?.name ?? "");
  const [kind, setKind] = useState<Kind>(s?.kind ?? "exec");
  const [schedule, setSchedule] = useState(s?.schedule ?? "0 4 * * *");
  const [service, setService] = useState(s?.kind === "exec" ? s.service : "");
  const [container, setContainer] = useState(
    s?.kind === "exec" ? (s.container ?? "") : "",
  );
  const [image, setImage] = useState(s?.kind === "container" ? s.image : "");
  const [command, setCommand] = useState(
    s && s.kind !== "container"
      ? s.command
      : s?.kind === "container"
        ? (s.command ?? "")
        : "",
  );
  const [env, setEnv] = useState(
    s?.kind === "container" ? formatEnv(s.env) : "",
  );
  const [mounts, setMounts] = useState(
    s?.kind === "container" ? (s.mounts ?? []).join("\n") : "",
  );
  const [timeout, setTimeout_] = useState(String(s?.timeout_secs ?? 600));
  const [enabled, setEnabled] = useState(s?.enabled ?? true);
  const [notify, setNotify] = useState(s?.notify ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const services = (status?.services ?? []).filter(
    (v) => v.spec.server === server,
  );
  const clash = !task && taken.includes(name);

  const spec = (): TaskSpec => {
    const base = {
      server,
      schedule: schedule.trim(),
      timeout_secs: Number(timeout) || 600,
      enabled,
      notify,
    };
    if (kind === "exec")
      return {
        ...base,
        kind,
        service,
        container: container.trim() || undefined,
        command,
      };
    if (kind === "host") return { ...base, kind, command };
    return {
      ...base,
      kind,
      image: image.trim(),
      command: command.trim() || undefined,
      env: parseEnv(env),
      mounts: mounts
        .split("\n")
        .map((m) => m.trim())
        .filter(Boolean),
    };
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(`/api/tasks/${encodeURIComponent(name)}`, spec());
      toast.success(`已保存 ${name}`);
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  const ready =
    name &&
    !clash &&
    schedule.trim() &&
    (kind === "exec"
      ? service && command.trim()
      : kind === "host"
        ? command.trim()
        : image.trim());

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {task ? `编辑 ${task.name}` : "新建定时任务"}
          </DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          {!task && (
            <Field
              label="名称"
              htmlFor="task-name"
              help={clash ? "名称已被占用" : undefined}
            >
              <Input
                id="task-name"
                value={name}
                onChange={(e) => setName(toName(e.target.value))}
                className="font-mono"
              />
            </Field>
          )}
          <Field label="形式">
            <Segmented
              value={kind}
              options={[
                ["exec", "服务容器内"],
                ["container", "一次性容器"],
                ["host", "宿主机"],
              ]}
              onChange={setKind}
            />
          </Field>
          {kind === "exec" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="服务">
                <Picker
                  value={service}
                  options={services.map((v) => ({
                    value: v.name,
                    label: v.name,
                  }))}
                  onChange={setService}
                />
              </Field>
              <Field label="compose 服务名" htmlFor="task-container">
                <Input
                  id="task-container"
                  value={container}
                  onChange={(e) => setContainer(e.target.value)}
                  className="font-mono"
                />
              </Field>
            </div>
          )}
          {kind === "container" && (
            <Field label="镜像" htmlFor="task-image">
              <Input
                id="task-image"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                className="font-mono"
              />
            </Field>
          )}
          <Field
            label="命令"
            htmlFor="task-command"
            help={<>用 sh -c 执行，可以写 [[密钥]]</>}
          >
            <Textarea
              id="task-command"
              spellCheck={false}
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              className="min-h-20 font-mono text-xs"
            />
          </Field>
          {kind === "container" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="环境变量" htmlFor="task-env">
                <Textarea
                  id="task-env"
                  spellCheck={false}
                  value={env}
                  onChange={(e) => setEnv(e.target.value)}
                  className="min-h-16 font-mono text-xs"
                  placeholder="KEY=VALUE"
                />
              </Field>
              <Field label="挂载" htmlFor="task-mounts">
                <Textarea
                  id="task-mounts"
                  spellCheck={false}
                  value={mounts}
                  onChange={(e) => setMounts(e.target.value)}
                  className="min-h-16 font-mono text-xs"
                  placeholder="/srv/app:/data:ro"
                />
              </Field>
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="时间（cron，北京时间）" htmlFor="task-schedule">
              <Input
                id="task-schedule"
                value={schedule}
                onChange={(e) => setSchedule(e.target.value)}
                className="font-mono"
              />
            </Field>
            <Field label="超时（秒）" htmlFor="task-timeout">
              <Input
                id="task-timeout"
                inputMode="numeric"
                value={timeout}
                onChange={(e) => setTimeout_(e.target.value.replace(/\D/g, ""))}
                className="font-mono"
              />
            </Field>
          </div>
          <div className="flex gap-6 text-sm">
            <label className="flex items-center gap-2">
              <Checkbox
                checked={enabled}
                onCheckedChange={(v) => setEnabled(!!v)}
              />
              启用
            </label>
            <label className="flex items-center gap-2">
              <Checkbox
                checked={notify}
                onCheckedChange={(v) => setNotify(!!v)}
              />
              失败时通知
            </label>
          </div>
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!ready || saving} onClick={save}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
