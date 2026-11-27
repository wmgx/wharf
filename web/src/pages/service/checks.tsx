import { useEffect, useState } from "react";
import { useActions } from "@/components/actions";
import { Field, Picker, serverOptions } from "@/components/fields";
import { Panel, SaveBar, useDraft } from "@/components/kit";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { ServiceSpec, ServiceView } from "@/types";

export function ServiceChecks({ svc, kind }: { svc: ServiceView; kind: "monitor" | "backup" }) {
  const { draft, set, reset, dirty } = useDraft(svc.spec);
  const actions = useActions();
  const { status } = useStatus();
  const [expect, setExpect] = useState(draft.monitor?.expect?.toString() ?? "");
  useEffect(() => { setExpect(svc.spec.monitor?.expect?.toString() ?? ""); }, [svc.spec.monitor?.expect]);
  const monitor = draft.monitor;
  const ports = (draft.ports ?? []).filter((p) => !p.udp);
  const servers = serverOptions((status?.servers ?? []).filter((s) => s.joined && s.name !== svc.spec.server));
  const hasData = !!svc.spec.volumes?.length || "compose" in svc.spec.source;
  const updateMonitor = (patch: Partial<NonNullable<ServiceSpec['monitor']>>) => { if (monitor) set({ monitor: { ...monitor, ...patch } }); };
  const expectNum = Number(expect.trim() || 0);
  const valid = kind !== "monitor" || !monitor || (monitor.path.startsWith("/") && Number.isInteger(expectNum) && (expectNum === 0 || expectNum >= 100 && expectNum < 600));
  return <>
    {kind === "monitor" ? (<Panel className="grid gap-3 p-4">
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={!!monitor} disabled={!ports.length} onCheckedChange={(checked) => set({ monitor: checked ? { path: "/" } : undefined })} />每分钟检查一次，连续 3 次不正常就通知</label>
      {!ports.length && <span className="text-xs text-muted-foreground">服务没有 TCP 端口，检查不了</span>}{monitor && <div className="grid gap-3 sm:grid-cols-2">
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
    </Panel>) : (<Panel className="p-4">
      {!hasData ? <span className="text-sm text-muted-foreground">这个服务没有数据卷</span> : !servers.length ? <span className="text-sm text-muted-foreground">需要另一台服务器存放备份</span> : <Field label="备份到" htmlFor="service-backup" help="每天自动备份到选中的服务器。">
        <Picker id="service-backup" value={draft.backup?.to ?? ""} options={[{ value: "", label: "不备份" }, ...servers]} onChange={(v) => set({ backup: v ? { to: v } : undefined })} />
      </Field>}
    </Panel>)}
    <SaveBar changed={dirty([kind]) ? [kind === "monitor" ? "健康检查" : "备份"] : []} disabled={valid ? undefined : "健康检查的路径或状态码不正确"} onReset={() => { reset(); setExpect(svc.spec.monitor?.expect?.toString() ?? ""); }} onSubmit={() => actions.plan({ title: `修改 ${svc.name}`, changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, [kind]: draft[kind] } }] })} />
  </>;
}
