import { useEffect, useMemo, useState } from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { BuildEditor } from "@/components/build-editor";
import { cleanHow, howOf, howReady, type BuildHow } from "@/lib/build-how";
import { CodeEditor } from "@/components/code-editor";
import { CodeBlock, SectionTitle } from "@/components/common";
import { ComposeField, MirrorHint, composePorts, parseCompose } from "@/components/compose";
import { Field, PortsEditor, formatEnv, parseEnv, portsFor } from "@/components/fields";
import { Panel, Row, Rows, SaveBar, useDraft } from "@/components/kit";
import { bytes } from "@/components/metrics";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { editableServiceSpec } from "@/lib/draft";
import { useStatus } from "@/status";
import type { Limits, PortSpec, ServiceSpec, ServiceView, UsageRow } from "@/types";
import { ConfigFiles, filePathOk } from "./config-files";
import { importText } from "./status-text";

export function Settings({ svc, active }: { svc: ServiceView; active: boolean }) {
  const editable = useMemo(() => editableServiceSpec(svc.spec), [svc.spec]);
  const { draft, set, reset, dirty, mergeInto } = useDraft(editable);
  const [key, setKey] = useState(0);
  const location = useLocation();
  const actions = useActions();
  useEffect(() => {
    if (active && location.hash) {
      document.getElementById(location.hash.slice(1))?.scrollIntoView();
      if (location.hash === "#backup") document.getElementById("service-backup")?.focus();
    }
  }, [active, location.hash]);
  const changed = ([['来源', 'source'], ['端口', 'ports'], ['目标容器', 'container'], ['环境变量', 'env'], ['配置文件', 'files'], ['资源上限', 'limits'], ['组件资源上限', 'container_limits'], ['自动更新', 'auto_update']] as [string, keyof ServiceSpec][]).filter(([, field]) => dirty([field])).map(([label]) => label);
  return <SettingsFields key={key} svc={svc} active={active} draft={draft} set={set} dirty={dirty} changed={changed} onReset={() => { reset(); setKey((n) => n + 1); }} onSubmit={() => {
    const spec = mergeInto(svc.spec);
    if ("build" in spec.source && "build" in svc.spec.source) {
      spec.source = { build: { ...spec.source.build, upload: svc.spec.source.build.upload } };
    }
    actions.plan({ title: `修改 ${svc.name}`, changes: [{ op: "upsert_service", name: svc.name, spec }] });
  }} />;
}

function SettingsFields({ svc, active, draft, set, dirty, changed, onReset, onSubmit }: { svc: ServiceView; active: boolean; draft: ServiceSpec; set: (p: Partial<ServiceSpec>) => void; dirty: (keys: (keyof ServiceSpec)[]) => boolean; changed: string[]; onReset: () => void; onSubmit: () => void }) {
  const actions = useActions();
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const source = draft.source;
  const isImage = "image" in source;
  const isCompose = "compose" in source;
  const build = "build" in source ? source.build : null;
  const [env, setEnv] = useState(formatEnv(draft.env));
  const [ports, setPorts] = useState<PortSpec[]>(() => isCompose && !draft.ports?.length ? composePorts(parseCompose(source.compose.content ?? "")) : (draft.ports ?? []));
  const [how, setHow] = useState<BuildHow>(howOf(build));
  const envDirty = dirty(["env"]);
  const portsDirty = dirty(["ports"]);
  const sourceDirty = dirty(["source"]);
  const compose = isCompose ? source.compose.content ?? "" : "";
  const composeInfo = useMemo(() => parseCompose(compose), [compose]);
  const saved = svc.spec;
  const savedEnv = formatEnv(saved.env);
  const savedPorts = JSON.stringify(saved.ports ?? []);
  const savedHow = JSON.stringify(howOf("build" in saved.source ? saved.source.build : null));
  useEffect(() => { if (!envDirty) setEnv(savedEnv); }, [savedEnv]);
  useEffect(() => {
    if (!portsDirty) {
      const declared: PortSpec[] = JSON.parse(savedPorts);
      setPorts(isCompose && !declared.length ? composePorts(composeInfo) : declared);
    }
  }, [portsDirty, savedPorts, isCompose, composeInfo]);
  useEffect(() => { if (!sourceDirty) setHow(JSON.parse(savedHow)); }, [savedHow]);
  const [selectedComponent, setSelectedComponent] = useState("");
  const component = composeInfo.services.includes(selectedComponent) ? selectedComponent : (composeInfo.services[0] ?? "");
  const legacyTarget = draft.container ?? (composeInfo.services.length === 1 ? component : "");
  const declared = isCompose ? (draft.container_limits?.[component] ?? (component === legacyTarget ? draft.limits : undefined)) : draft.limits;
  const base = {
    memory: declared?.memory_mb?.toString() ?? "",
    cpu: declared?.cpu_milli ? String(declared.cpu_milli / 1000) : "",
    pids: declared?.pids?.toString() ?? "",
  };
  const [limitText, setLimitText] = useState<{ target: string; memory: string; cpu: string; pids: string } | null>(null);
  const target = isCompose ? component : "";
  const inputs = limitText?.target === target ? limitText : base;
  const { data } = usePoll<{ series: Record<string, [number, number][]> }>(isCompose ? null : `/api/metrics?subject=${encodeURIComponent(svc.name)}&range=7d`, 60000);
  const { data: componentUsage } = usePoll<UsageRow[]>(isCompose && active ? `/api/metrics/top?service=${encodeURIComponent(svc.name)}&containers=true` : null, 60000);
  const usage = componentUsage?.[0]?.components?.find((entry) => entry.name === component);
  const points = data?.series["svc.mem"] ?? [];
  const peak = points.reduce((max, [, value]) => Math.max(max, value), 0);
  const parsed = (value: string) => value.trim() ? Number(value) : undefined;
  const memoryNum = parsed(inputs.memory);
  const cpuNum = parsed(inputs.cpu);
  const pidsNum = parsed(inputs.pids);
  const limitsValid = (memoryNum === undefined || (Number.isInteger(memoryNum) && memoryNum >= 32 && memoryNum <= 4294967295))
    && (cpuNum === undefined || (Number.isFinite(cpuNum) && cpuNum >= 0.01 && cpuNum * 1000 <= 4294967295))
    && (pidsNum === undefined || (Number.isInteger(pidsNum) && pidsNum >= 1 && pidsNum <= 4294967295));
  const needsContainer = isCompose && composeInfo.services.length > 1 && !draft.container && (Object.keys(draft.env ?? {}).length > 0 || !!draft.limits || !!draft.files?.length || Boolean(svc.spec.heartbeat));
  const files = draft.files ?? [];
  const filesValid = files.every((f) => filePathOk(f.path)) && new Set(files.map((f) => f.path)).size === files.length;
  const disabled = needsContainer ? "compose 里有多个容器，先选环境变量、配置文件和资源上限加在哪个容器上" : !filesValid ? "配置文件的路径不正确或重复" : !limitsValid ? "资源上限不正确" : build && !howReady(how) ? "来源的 Dockerfile 不能为空" : undefined;
  const updateLimits = (field: "memory" | "cpu" | "pids", value: string) => {
    const next = { ...inputs, target, [field]: value };
    setLimitText(next);
    const memory_mb = parsed(next.memory);
    const cpu = parsed(next.cpu);
    const pids = parsed(next.pids);
    const limits: Limits | undefined = memory_mb === undefined && cpu === undefined && pids === undefined
      ? undefined : { memory_mb, cpu_milli: cpu === undefined ? undefined : Math.round(cpu * 1000), pids };
    if (!isCompose) {
      set({ limits });
    } else if (component) {
      const container_limits = { ...draft.container_limits };
      if (limits) container_limits[component] = limits;
      else delete container_limits[component];
      set({ container_limits: Object.keys(container_limits).length ? container_limits : undefined,
        ...(component === legacyTarget ? { limits: undefined } : {}) });
    }
  };
  return <div className="max-w-5xl">
    <SectionTitle>来源</SectionTitle>
    <Panel className="grid gap-3 p-4">
      {isImage ? <Field label="镜像" htmlFor="service-image">
        <Input id="service-image" value={source.image} onChange={(e) => set({ source: { image: e.target.value } })} />
      </Field> : isCompose ? <Field label="compose.yaml" htmlFor="service-compose">
        <ComposeField id="service-compose" value={compose} onChange={(value) => set({ source: { compose: { ...source.compose, content: value } } })} info={composeInfo} />
      </Field> : build?.git ? <div className="grid grid-cols-[minmax(0,1fr)_8rem] gap-3">
        <Field label="仓库" htmlFor="service-repo">
          <Input id="service-repo" value={build.git.repo} onChange={(e) => set({ source: { build: { ...build, git: { ...build.git!, repo: e.target.value } } } })} />
        </Field>
        <Field label="分支 / 标签" htmlFor="service-ref">
          <Input id="service-ref" value={build.git.ref} onChange={(e) => set({ source: { build: { ...build, git: { ...build.git!, ref: e.target.value } } } })} />
        </Field>
      </div> : build && <div className="flex items-center gap-2 text-sm">代码包 {"build" in svc.spec.source && svc.spec.source.build.upload?.slice(0, 12)}<Button variant="outline" size="sm" onClick={() => { const next = new URLSearchParams(params); next.set("repack", "1"); setParams(next); }}>更新代码包</Button>
      </div>}
      {(isImage || isCompose) && <MirrorHint server={status?.servers.find((s) => s.name === svc.spec.server)} images={isImage ? [source.image] : composeInfo.images} />}
      {isCompose && composeInfo.images.filter((i) => !i.includes("@") && !i.includes("$")).length > 1 && <div className="grid gap-1">
        <span className="text-xs text-muted-foreground">单独检查某个镜像的新版本，其他镜像保持现在的版本、容器不重建</span>
        {composeInfo.images.filter((i) => !i.includes("@") && !i.includes("$")).map((image) => <div key={image} className="flex items-center justify-between gap-2">
          <span className="min-w-0 break-all font-mono text-xs">{image}</span>
          <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `检查 ${svc.name} 的 ${image} 的更新`, changes: [{ op: "refresh_images", name: svc.name, image }] })}>检查更新</Button>
        </div>)}
      </div>}
      {build && <BuildEditor value={how} onChange={(value) => { setHow(value); set({ source: { build: { git: build.git, path: build.path, ...cleanHow(value) } } }); }} />}
      {svc.import && <div className="text-xs text-muted-foreground">
        {importText(svc.import)}
      </div>}
    </Panel>
    <SectionTitle>端口</SectionTitle>
    <Panel className="p-4">
      <PortsEditor ports={ports} compose={isCompose} onChange={(value) => { setPorts(value); set({ ports: portsFor(value, isCompose) }); }} />
    </Panel>
    {isCompose && composeInfo.services.length > 1 && <>
      <SectionTitle>设置作用的容器</SectionTitle>
      <Panel className="grid gap-2 p-4">
        <select id="service-container" className="h-9 w-full rounded-md border bg-background px-3 text-sm sm:w-64" value={draft.container ?? ""} onChange={(e) => set({ container: e.target.value || undefined })}>
          <option value="">选择容器</option>
          {composeInfo.services.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <span className="text-xs text-muted-foreground">下面的环境变量和配置文件加在这个容器上，compose 文件本身不改。</span>
      </Panel>
    </>}
    {<>
      <SectionTitle>环境变量</SectionTitle>
      <Panel className="p-4">
        <Field label={isCompose ? "环境变量（部署时加到 compose 里，和 compose 里已有的不能重名）" : "环境变量"} htmlFor="service-env">
          <CodeEditor id="service-env" lang="env" secrets className="min-h-32" placeholder={"KEY=value\nTOKEN=[[MY_SECRET]]"} value={env} onChange={(value) => { setEnv(value); set({ env: parseEnv(value) }); }} />
        </Field>
      </Panel>
    </>}
    <div id="files">
      <SectionTitle>配置文件</SectionTitle>
    </div>
    <ConfigFiles files={files} onChange={(next) => set({ files: next.length ? next : undefined })} />
    <div id="monitor" className="mt-8">
      <SectionTitle>健康检查</SectionTitle>
    </div>
    <Button variant="outline" onClick={() => setParams({ tab: "metrics" })}>到监控页设置健康检查</Button>
    <SectionTitle>资源上限</SectionTitle>
    <Panel className="grid gap-3 p-4 sm:grid-cols-2">
      {isCompose && <Field label="容器" htmlFor="limits-component">
        <select id="limits-component" className="h-9 w-full rounded-md border bg-background px-3 text-sm"
          value={component} disabled={!limitsValid} onChange={(e) => { setSelectedComponent(e.target.value); setLimitText(null); }}>
          {composeInfo.services.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </Field>}
      <Field label="内存（MB）" htmlFor="service-memory">
        <Input id="service-memory" type="number" min={32} step={1} value={inputs.memory} disabled={isCompose && !component} onChange={(e) => updateLimits("memory", e.target.value)} />
        {isCompose ? <span className="text-xs text-muted-foreground">生效 {usage?.memory_limit == null ? "—" : bytes(usage.memory_limit)} · 近 7 天最高 {usage?.memory_peak == null ? "—" : bytes(usage.memory_peak)}</span>
          : points.length > 0 && <span className="text-xs text-muted-foreground">近 7 天最高 {bytes(peak)}</span>}
      </Field>
      <Field label="CPU（核）" htmlFor="service-cpu">
        <Input id="service-cpu" type="number" min={0.01} step={0.01} value={inputs.cpu} disabled={isCompose && !component} onChange={(e) => updateLimits("cpu", e.target.value)} />
        {isCompose && <span className="text-xs text-muted-foreground">生效 {usage?.cpu_limit_milli == null ? "—" : usage.cpu_limit_milli / 1000} · 近 7 天最高 {usage?.cpu_peak == null ? "—" : `${usage.cpu_peak.toFixed(1)}%`}</span>}
      </Field>
      <Field label="PID" htmlFor="service-pids">
        <Input id="service-pids" type="number" min={1} step={1} value={inputs.pids} disabled={isCompose && !component} onChange={(e) => updateLimits("pids", e.target.value)} />
        {isCompose && <span className="text-xs text-muted-foreground">生效 {usage?.pids_limit ?? "—"}</span>}
      </Field>
    </Panel>
    {((isImage && !source.image.includes("@")) || !!build?.git || (isCompose && composeInfo.images.some((i) => !i.includes("@") && !i.includes("$")) && composeInfo.volumes.length === 0)) && !draft.volumes?.length && <>
      <SectionTitle>自动更新</SectionTitle>
      <Panel className="grid gap-3 p-4">
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={!!draft.auto_update} onCheckedChange={(checked) => set({ auto_update: checked ? true : undefined })} />有新版本时自动更新
        </label>
        <span className="text-xs text-muted-foreground">每天凌晨 3 点到 6 点检查一次。新版本起不来时线上不受影响，会发通知。</span>
      </Panel>
    </>}
    <div id="backup" className="mt-8">
      <SectionTitle>备份</SectionTitle>
    </div>
    <Button variant="outline" onClick={() => setParams({ tab: "data" })}>到数据页设置备份</Button>
    <SectionTitle>危险操作</SectionTitle>
    <Panel className="border-destructive/30">
      <Rows>
        <Row>
          <div className="flex-1">
            <div>
              {svc.spec.stopped ? "启动服务" : "停止服务"}
            </div>
            <div className="text-xs text-muted-foreground">
              {svc.spec.stopped ? "按现在的配置启动。" : "容器保留，不再运行。"}
            </div>
          </div>
          <Button variant="outline" onClick={() => actions.setStopped(svc, !svc.spec.stopped)}>
            {svc.spec.stopped ? "启动" : "停止"}
          </Button>
        </Row>
        <Row>
          <div className="flex-1">
            <div>迁移到其他服务器</div>
            <div className="text-xs text-muted-foreground">域名不变；有数据时会短暂停服。</div>
          </div>
          <Button variant="outline" onClick={() => actions.move(svc)}>迁移</Button>
        </Row>
        <Row>
          <div className="flex-1">
            <div>删除服务</div>
            <div className="text-xs text-muted-foreground">连同它的域名一起移除，数据默认保留。</div>
          </div>
          <Button variant="destructive" onClick={() => actions.remove(svc.name)}>删除</Button>
        </Row>
      </Rows>
    </Panel>
    <details className="mt-8 text-sm">
      <summary className="cursor-pointer text-muted-foreground">原始配置（JSON）</summary>
      <CodeBlock className="mt-2">
        {JSON.stringify(svc.spec, null, 2)}
      </CodeBlock>
    </details>
    <SaveBar changed={changed} disabled={disabled} onReset={onReset} onSubmit={onSubmit} />
  </div>;
}
