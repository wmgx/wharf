import { useEffect, useMemo, useState } from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { BuildEditor, cleanHow, howOf, howReady, type BuildHow } from "@/components/build-editor";
import { CodeEditor } from "@/components/code-editor";
import { CodeBlock, SectionTitle } from "@/components/common";
import { ComposeField, MirrorHint, composePorts, parseCompose } from "@/components/compose";
import { Field, Picker, PortsEditor, formatEnv, parseEnv, portsFor, serverOptions } from "@/components/fields";
import { Panel, Row, Rows, SaveBar, useDraft } from "@/components/kit";
import { bytes } from "@/components/metrics";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { PortSpec, ServiceSpec, ServiceView } from "@/types";
import { importText } from "./status-text";

export function Settings({ svc, active }: { svc: ServiceView; active: boolean }) {
  const { draft, set, reset, dirty } = useDraft(svc.spec);
  const [key, setKey] = useState(0);
  const location = useLocation();
  const actions = useActions();
  useEffect(() => { if (active && location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView(); }, [active, location.hash]);
  const changed = ([['来源', 'source'], ['端口', 'ports'], ['环境变量', 'env'], ['健康检查', 'monitor'], ['资源上限', 'limits'], ['备份', 'backup']] as [string, keyof ServiceSpec][]).filter(([, field]) => dirty([field])).map(([label]) => label);
  return <SettingsFields key={key} svc={svc} draft={draft} set={set} changed={changed} onReset={() => { reset(); setKey((n) => n + 1); }} onSubmit={() => actions.plan({ title: `修改 ${svc.name}`, changes: [{ op: "upsert_service", name: svc.name, spec: draft }] })} />;
}

function SettingsFields({ svc, draft, set, changed, onReset, onSubmit }: { svc: ServiceView; draft: ServiceSpec; set: (p: Partial<ServiceSpec>) => void; changed: string[]; onReset: () => void; onSubmit: () => void }) {
  const actions = useActions();
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const source = draft.source;
  const isImage = "image" in source;
  const isCompose = "compose" in source;
  const build = "build" in source ? source.build : null;
  const [env, setEnv] = useState(formatEnv(draft.env));
  const [envTouched, setEnvTouched] = useState(false);
  const [ports, setPorts] = useState<PortSpec[]>(() => isCompose && !draft.ports?.length ? composePorts(parseCompose(source.compose.content ?? "")) : (draft.ports ?? []));
  const [portsTouched, setPortsTouched] = useState(!!draft.ports?.length);
  const [how, setHow] = useState<BuildHow>(howOf(build));
  const [expect, setExpect] = useState(draft.monitor?.expect?.toString() ?? "");
  const [memory, setMemory] = useState(draft.limits?.memory_mb?.toString() ?? "");
  const [cpus, setCpus] = useState(draft.limits?.cpu_milli ? String(draft.limits.cpu_milli / 1000) : "");
  useEffect(() => { if (!changed.length) { if (!envTouched) setEnv(formatEnv(draft.env)); setPorts(isCompose && !draft.ports?.length ? composePorts(parseCompose(source.compose.content ?? "")) : (draft.ports ?? [])); setHow(howOf("build" in draft.source ? draft.source.build : null)); setExpect(draft.monitor?.expect?.toString() ?? ""); setMemory(draft.limits?.memory_mb?.toString() ?? ""); setCpus(draft.limits?.cpu_milli ? String(draft.limits.cpu_milli / 1000) : ""); } }, [draft, changed.length, envTouched, isCompose, source]);
  useEffect(() => { if (isCompose && changed.length && !portsTouched && !draft.ports?.length && ports.length) set({ ports: portsFor(ports, true) }); }, [isCompose, changed.length, portsTouched, draft.ports, ports, set]);
  const compose = isCompose ? source.compose.content ?? "" : "";
  const composeInfo = useMemo(() => parseCompose(compose), [compose]);
  const { data } = usePoll<{ series: Record<string, [number, number][]> }>(isCompose ? null : `/api/metrics?subject=${encodeURIComponent(svc.name)}&range=7d`, 60000);
  const points = data?.series["svc.mem"] ?? [];
  const peak = points.reduce((max, [, value]) => Math.max(max, value), 0);
  const expectNum = Number(expect.trim() || 0);
  const memoryNum = memory.trim() ? Number(memory) : undefined;
  const cpuNum = cpus.trim() ? Number(cpus) : undefined;
  const monitorValid = !draft.monitor || (draft.monitor.path.startsWith("/") && Number.isInteger(expectNum) && (expectNum === 0 || (expectNum >= 100 && expectNum < 600)));
  const limitsValid = (memoryNum === undefined || (Number.isInteger(memoryNum) && memoryNum >= 32 && memoryNum <= 4294967295)) && (cpuNum === undefined || (Number.isFinite(cpuNum) && cpuNum >= 0.01 && cpuNum * 1000 <= 4294967295));
  const disabled = !monitorValid ? "健康检查的路径或状态码不正确" : !limitsValid ? "资源上限不正确" : build && !howReady(how) ? "来源的 Dockerfile 不能为空" : undefined;
  const updateLimits = (m: string, c: string) => { const mn = m.trim() ? Number(m) : undefined; const cn = c.trim() ? Number(c) : undefined; set({ limits: mn === undefined && cn === undefined ? undefined : { memory_mb: mn, cpu_milli: cn === undefined ? undefined : Math.round(cn * 1000) } }); };
  const monitor = draft.monitor;
  const updateMonitor = (patch: Partial<NonNullable<ServiceSpec['monitor']>>) => { if (monitor) set({ monitor: { ...monitor, ...patch } }); };
  const servers = serverOptions((status?.servers ?? []).filter((s) => s.joined && s.name !== svc.spec.server));
  const hasData = !!svc.spec.volumes?.length || "compose" in svc.spec.source;
  return <div className="max-w-2xl">
    <SectionTitle>来源</SectionTitle>
    <Panel className="grid gap-3 p-4">
      {isImage ? <Field label="镜像" htmlFor="service-image">
        <Input id="service-image" value={source.image} onChange={(e) => set({ source: { image: e.target.value } })} />
      </Field> : isCompose ? <Field label="compose.yaml" htmlFor="service-compose">
        <ComposeField id="service-compose" value={compose} onChange={(value) => { const next = !portsTouched ? composePorts(parseCompose(value)) : ports; if (!portsTouched) setPorts(next); set({ source: { compose: { ...source.compose, content: value } }, ...(!portsTouched ? { ports: portsFor(next, true) } : {}) }); }} info={composeInfo} />
      </Field> : build?.git ? <div className="grid grid-cols-[minmax(0,1fr)_8rem] gap-3">
        <Field label="仓库" htmlFor="service-repo">
          <Input id="service-repo" value={build.git.repo} onChange={(e) => set({ source: { build: { ...build, git: { ...build.git!, repo: e.target.value } } } })} />
        </Field>
        <Field label="分支 / 标签" htmlFor="service-ref">
          <Input id="service-ref" value={build.git.ref} onChange={(e) => set({ source: { build: { ...build, git: { ...build.git!, ref: e.target.value } } } })} />
        </Field>
      </div> : build && <div className="flex items-center gap-2 text-sm">代码包 {build.upload?.slice(0, 12)}<Button variant="outline" size="sm" onClick={() => { const next = new URLSearchParams(params); next.set("repack", "1"); setParams(next); }}>更新代码包</Button>
      </div>}
      {(isImage || isCompose) && <MirrorHint server={status?.servers.find((s) => s.name === svc.spec.server)} images={isImage ? [source.image] : composeInfo.images} />}
      {build && <BuildEditor value={how} onChange={(value) => { setHow(value); set({ source: { build: { ...build, ...cleanHow(value) } } }); }} />}
      {svc.import && <div className="text-xs text-muted-foreground">
        {importText(svc.import)}
      </div>}
    </Panel>
    <SectionTitle>端口</SectionTitle>
    <Panel className="p-4">
      <PortsEditor ports={ports} compose={isCompose} onChange={(value) => { setPortsTouched(true); setPorts(value); set({ ports: portsFor(value, isCompose) }); }} />
    </Panel>
    {!isCompose && <>
      <SectionTitle>环境变量</SectionTitle>
      <Panel className="p-4">
        <Field label="环境变量" htmlFor="service-env">
          <CodeEditor id="service-env" lang="env" secrets className="min-h-32" placeholder={"KEY=value\nTOKEN=[[MY_SECRET]]"} value={env} onChange={(value) => { setEnvTouched(true); setEnv(value); set({ env: parseEnv(value) }); }} />
        </Field>
      </Panel>
    </>}
    <div id="monitor" className="mt-8">
      <SectionTitle>健康检查</SectionTitle>
    </div>
    <Panel className="grid gap-3 p-4">
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={!!monitor} disabled={!ports.length} onCheckedChange={(checked) => set({ monitor: checked ? { path: "/" } : undefined })} />每分钟检查一次，连续 3 次不正常就通知</label>
      {!ports.length && <span className="text-xs text-muted-foreground">服务没有端口，检查不了</span>}{monitor && <div className="grid gap-3 sm:grid-cols-2">
        <Field label="路径" htmlFor="service-monitor-path">
          <Input id="service-monitor-path" placeholder="/health" value={monitor.path} onChange={(e) => updateMonitor({ path: e.target.value })} />
        </Field>
        <Field label="端口" htmlFor="service-monitor-port">
          <Picker id="service-monitor-port" value={monitor.port ?? ""} options={[{ value: "", label: `默认（${ports[0]?.name ?? "-"}）` }, ...ports.map((p) => ({ value: p.name, label: p.name }))]} onChange={(v) => updateMonitor({ port: v || undefined })} />
        </Field>
        <Field label="期望状态码" htmlFor="service-monitor-expect" help="不填时 2xx、3xx 都算正常">
          <Input id="service-monitor-expect" inputMode="numeric" value={expect} onChange={(e) => { const v = e.target.value; setExpect(v); updateMonitor({ expect: Number(v.trim() || 0) || undefined }); }} />
        </Field>
        <Field label="应答里要包含" htmlFor="service-monitor-keyword" help="不填就只看状态码">
          <Input id="service-monitor-keyword" value={monitor.keyword ?? ""} onChange={(e) => updateMonitor({ keyword: e.target.value || undefined })} />
        </Field>
      </div>}
    </Panel>
    {!isCompose && <>
      <SectionTitle>资源上限</SectionTitle>
      <Panel className="grid gap-3 p-4 sm:grid-cols-2">
        <Field label="内存（MB）" htmlFor="service-memory">
          <Input id="service-memory" type="number" min={32} step={1} value={memory} onChange={(e) => { setMemory(e.target.value); updateLimits(e.target.value, cpus); }} />
          {points.length > 0 && <span className="text-xs text-muted-foreground">近 7 天最高 {bytes(peak)}
          </span>}
        </Field>
        <Field label="CPU（核）" htmlFor="service-cpu">
          <Input id="service-cpu" type="number" min={0.01} step={0.01} value={cpus} onChange={(e) => { setCpus(e.target.value); updateLimits(memory, e.target.value); }} />
        </Field>
      </Panel>
    </>}
    <div id="backup" className="mt-8">
      <SectionTitle>备份</SectionTitle>
    </div>
    <Panel className="p-4">
      {!hasData ? <span className="text-sm text-muted-foreground">这个服务没有数据卷</span> : !servers.length ? <span className="text-sm text-muted-foreground">需要另一台服务器存放备份</span> : <Field label="备份到" htmlFor="service-backup" help="每天自动备份到选中的服务器。">
        <Picker id="service-backup" value={draft.backup?.to ?? ""} options={[{ value: "", label: "不备份" }, ...servers]} onChange={(v) => set({ backup: v ? { to: v } : undefined })} />
      </Field>}
    </Panel>
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
