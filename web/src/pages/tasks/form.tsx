import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { CodeEditor } from "@/components/code-editor";
import { Field, Picker, Segmented, formatEnv, parseEnv, serverOptions, toName } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { ScriptRuntime, TaskSpec, TaskView } from "@/types";
import { cronText } from "./model";

type Kind = TaskSpec["kind"];
const DESCRIPTIONS: Record<Kind, string> = {
  exec: "在某个服务的容器里执行命令。",
  container: "用一个镜像起容器跑一次，跑完就删。",
  host: "直接在服务器上执行，要先在服务器设置里开启命令执行。",
  ping: "任务在别处跑，跑完来报到；没按时报到就通知。",
  script: "直接写代码，在一次性容器里执行。",
};

export function TaskForm({ task, server: fixed, taken, onSaved, onCancel }: { task: TaskView | null; server?: string; taken: string[]; onSaved: (name: string) => void; onCancel?: () => void }) {
  const { status } = useStatus();
  const s = task?.spec;
  const servers = status?.servers ?? [];
  const [server, setServer] = useState(task?.target_server ?? s?.server ?? fixed ?? servers[0]?.name ?? "");
  const [name, setName] = useState(task?.name ?? "");
  const [kind, setKind] = useState<Kind>(s?.kind ?? "exec");
  const [schedule, setSchedule] = useState(s?.schedule ?? "0 4 * * *");
  const [service, setService] = useState(s?.kind === "exec" ? s.service : "");
  const [container, setContainer] = useState(s?.kind === "exec" ? s.container ?? "" : "");
  const [image, setImage] = useState(s?.kind === "container" ? s.image : "");
  const [runtime, setRuntime] = useState<ScriptRuntime>(s?.kind === "script" ? s.runtime : "python");
  const [deps, setDeps] = useState(s?.kind === "script" ? s.deps ?? "" : "");
  const [code, setCode] = useState(s?.kind === "script" ? s.code : "");
  const [scriptImage, setScriptImage] = useState(s?.kind === "script" ? s.image ?? "" : "");
  const [hook, setHook] = useState(s?.kind === "script" && s.hook != null);
  const [grace, setGrace] = useState(String(s?.kind === "ping" ? s.grace_mins : 60));
  const [command, setCommand] = useState(s && (s.kind === "exec" || s.kind === "host") ? s.command : s?.kind === "container" ? s.command ?? "" : "");
  const [env, setEnv] = useState(s?.kind === "container" || s?.kind === "script" ? formatEnv(s.env) : "");
  const [mounts, setMounts] = useState(s?.kind === "container" ? (s.mounts ?? []).join("\n") : "");
  const [timeout, setTimeout_] = useState(String(s?.timeout_secs ?? 600));
  const [enabled, setEnabled] = useState(s?.enabled ?? true);
  const [notify, setNotify] = useState(s?.notify ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const services = status?.services ?? [];
  const clash = !task && taken.includes(name);
  const validSchedule = (kind === "script" && !schedule.trim()) || schedule.trim().split(/\s+/).length === 5;
  const spec = (): TaskSpec => {
    const base = { server, schedule: schedule.trim(), timeout_secs: Number(timeout) || 600, enabled, notify, skip_if_stopped: s?.skip_if_stopped, catch_up_mins: s?.catch_up_mins };
    if (kind === "script") return { ...base, kind, runtime, code, deps: runtime === "shell" ? undefined : deps, image: scriptImage.trim() || undefined, env: parseEnv(env), hook: hook ? (s?.kind === "script" ? s.hook ?? "" : "") : undefined };
    if (kind === "exec") return { ...base, server: services.find((v) => v.name === service)?.spec.server ?? server, kind, service, container: container.trim() || undefined, command };
    if (kind === "host") return { ...base, kind, command };
    if (kind === "ping") return { ...base, kind, grace_mins: Number(grace) || 60 };
    return { ...base, kind, image: image.trim(), command: command.trim() || undefined, env: parseEnv(env), mounts: mounts.split("\n").map((m) => m.trim()).filter(Boolean) };
  };
  const [initial] = useState(() => JSON.stringify(spec()));
  const ready = name && server && !clash && validSchedule && (kind === "exec" ? service && command.trim() : kind === "host" ? command.trim() : kind === "ping" ? Number(grace) > 0 : kind === "script" ? code.trim() : image.trim());
  const save = async () => {
    setSaving(true); setError(null);
    try { await api.put(`/api/tasks/${encodeURIComponent(name)}`, spec()); toast.success("已保存"); onSaved(name); }
    catch(e) { setError(e); } finally { setSaving(false); }
  };
  const presets: [string, string][] = [["每小时", "0 * * * *"], ["每天 3 点", "0 3 * * *"], ["每周一 3 点", "0 3 * * 1"], ["每月 1 号", "0 3 1 * *"]];
  return <div className="max-w-2xl">
    <SectionTitle>做什么</SectionTitle>
    <div className="grid gap-4">
      <Field label="名称" htmlFor="task-name" help={clash ? "名称已被占用" : undefined}>
        <Input id="task-name" disabled={!!task} value={name} onChange={(e) => setName(toName(e.target.value))} className="font-mono" />
      </Field>
      <Field label="形式">
        <fieldset disabled={!!task} className="min-w-0 max-w-full overflow-x-auto whitespace-nowrap">
          <Segmented value={kind} options={[["exec", "在服务里执行"], ["container", "一次性容器"], ["host", "宿主机命令"], ["ping", "外部报到"], ["script", "脚本"]]} onChange={setKind} />
        </fieldset>
        <span className="text-xs text-muted-foreground">
          {DESCRIPTIONS[kind]}
        </span>
      </Field>
      {kind !== "exec" && <Field label="服务器" htmlFor="task-server">
        <Picker id="task-server" value={server} options={serverOptions(servers)} onChange={setServer} />
      </Field>}
      {kind === "exec" && <>
        <Field label="服务" htmlFor="task-service">
          <Picker id="task-service" value={service} options={services.map((v) => ({ value: v.name, label: v.name }))} onChange={setService} />
        </Field>
        {(services.find((v) => v.name === service)?.containers?.length ?? 0) > 1 && <Field label="容器" htmlFor="task-container" help="compose 里的服务名，不填用第一个。">
          <Input id="task-container" value={container} onChange={(e) => setContainer(e.target.value)} className="font-mono" />
        </Field>}
      </>}
      {kind === "container" && <Field label="镜像" htmlFor="task-image">
        <Input id="task-image" value={image} onChange={(e) => setImage(e.target.value)} className="font-mono" />
      </Field>}
      {kind === "script" && <>
        <Field label="运行环境">
          <Segmented value={runtime} options={[["python", "Python"], ["node", "Node"], ["shell", "Shell"]]} onChange={setRuntime} />
        </Field>
        <Field label="代码" htmlFor="task-code">
          {runtime === "shell" ? <CodeEditor id="task-code" lang="shell" value={code} onChange={setCode} className="min-h-64" /> : <Textarea id="task-code" rows={12} spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} className="min-h-64 font-mono text-xs" />}
        </Field>
        {runtime !== "shell" && <Field label="依赖" htmlFor="task-deps">
          <Textarea id="task-deps" rows={4} spellCheck={false} value={deps} onChange={(e) => setDeps(e.target.value)} className="font-mono text-xs" />
        </Field>}
        <Field label="镜像" htmlFor="task-script-image">
          <Input id="task-script-image" value={scriptImage} onChange={(e) => setScriptImage(e.target.value)} className="font-mono" />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={hook} onCheckedChange={(v) => setHook(!!v)} />可以用网址触发
        </label>
      </>}
      {kind !== "ping" && kind !== "script" && <Field label="命令" htmlFor="task-command" help="用 sh -c 执行，可以写 [[密钥名]]。">
        <Textarea id="task-command" spellCheck={false} value={command} onChange={(e) => setCommand(e.target.value)} className="min-h-20 font-mono text-xs" />
      </Field>}
      {(kind === "container" || kind === "script") && <details open={task && (env || mounts) ? true : undefined}>
        <summary className="cursor-pointer text-sm">{kind === "script" ? "环境变量" : "环境变量和挂载"}</summary>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <Field label="环境变量" htmlFor="task-env">
            <Textarea id="task-env" value={env} onChange={(e) => setEnv(e.target.value)} className="min-h-16 font-mono text-xs" placeholder="KEY=VALUE" />
          </Field>
          {kind === "container" && <Field label="挂载" htmlFor="task-mounts">
            <Textarea id="task-mounts" value={mounts} onChange={(e) => setMounts(e.target.value)} className="min-h-16 font-mono text-xs" placeholder="/srv/app:/data:ro" />
          </Field>}
        </div>
      </details>}
    </div>
    <SectionTitle>什么时候</SectionTitle>
    <div className="grid gap-4">
      <Field label={kind === "ping" ? "预期运行时间" : "时间"} htmlFor="task-schedule">
        <Input id="task-schedule" value={schedule} onChange={(e) => setSchedule(e.target.value)} placeholder="0 3 * * *" className="font-mono" />
        <span className={validSchedule ? "text-xs text-muted-foreground" : "text-xs text-destructive"}>
          {kind === "script" && !schedule.trim() ? "不定时" : validSchedule ? `${cronText(schedule) ? `${cronText(schedule)}，` : ""}北京时间` : "cron 格式不对，要 5 段"}
        </span>
        <div className="flex flex-wrap gap-1.5">
          {presets.map(([label, value]) => <button type="button" key={value} className="h-6 rounded-full border px-2.5 text-xs text-muted-foreground hover:border-primary hover:text-primary" onClick={() => setSchedule(value)}>
            {label}
          </button>)}
        </div>
      </Field>
      {kind === "ping" ? <Field label="宽限（分钟）" htmlFor="task-grace" help="过了预期时间多久还没报到算迟到。">
        <Input id="task-grace" inputMode="numeric" value={grace} onChange={(e) => setGrace(e.target.value.replace(/\D/g, ""))} />
      </Field> : <Field label="超时（秒）" htmlFor="task-timeout" help={kind === "host" ? "1 到 600 秒，默认 600 秒。" : "1 到 21600 秒，默认 600 秒。"}>
        <Input id="task-timeout" inputMode="numeric" value={timeout} onChange={(e) => setTimeout_(e.target.value.replace(/\D/g, ""))} />
      </Field>}
    </div>
    <SectionTitle>其他</SectionTitle>
    <div className="grid gap-3 text-sm">
      <label className="flex items-center gap-2">
        <Checkbox checked={enabled} onCheckedChange={(v) => setEnabled(!!v)} />启用</label>
      <label className="flex items-center gap-2">
        <Checkbox checked={notify} onCheckedChange={(v) => setNotify(!!v)} />失败时通知</label>
    </div>
    <ErrorNote error={error} />
    <div className="mt-6 flex justify-end gap-2">
      {kind === "script" && task && server !== s?.server && <span className="text-sm text-muted-foreground">数据不会跟着换服务器</span>}
      {onCancel && <Button variant="ghost" onClick={onCancel}>取消</Button>}<Button disabled={!ready || saving || (!!task && JSON.stringify(spec()) === initial)} onClick={save}>
        {saving ? "保存中…" : "保存"}
      </Button>
    </div>
  </div>;
}
