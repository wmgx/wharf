import { Trash2Icon } from "lucide-react";
import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Field, Picker } from "@/components/fields";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CodeBlock, Empty, SectionTitle, ServerTag } from "@/components/common";
import { CertDays, diagnosisOf } from "@/components/health";
import { ConfirmDialog, Facts, Row, Rows } from "@/components/kit";
import { LogStream } from "@/components/LogStream";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { AccountView, GatewayTls, GatewayView, ServiceView } from "@/types";
import { GatewayErrorPage } from "../gateway-error-page";

const TLS_TEXT: Record<GatewayTls, string> = { auto: "自动签证书", internal: "自签证书", off: "只走 HTTP" };

export function GatewayDetail({ g, onDone, onDomain }: { g: GatewayView; onDone: () => void; onDomain: (hostname: string) => void }) {
  const actions = useActions();
  const [removing, setRemoving] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const { status } = useStatus();
  const [wildcardOpen, setWildcardOpen] = useState(false);
  const [zone, setZone] = useState("");
  const { data: accounts } = usePoll<AccountView[]>(g.spec.kind === "caddy" && g.spec.tls !== "off" ? "/api/accounts" : null, 30000);
  const [forwardOpen, setForwardOpen] = useState(false);
  const [listen, setListen] = useState("");
  const [udp, setUdp] = useState(false);
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [upstream, setUpstream] = useState("");
  const { data: services } = usePoll<ServiceView[]>(forwardOpen ? "/api/services" : null, 30000);
  const forwards = g.spec.layer4 ?? [];
  const service = services?.find((s) => s.name === target);
  const ports = service?.spec.ports ?? [];
  const validListen = Number.isInteger(Number(listen)) && Number(listen) >= 1 && Number(listen) <= 65535;
  const saveForwards = (next: NonNullable<GatewayView["spec"]["layer4"]>, title: string) => {
    setForwardOpen(false);
    actions.plan({ title, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, layer4: next } }] });
  };
  const addForward = <Button variant="ghost" size="xs" onClick={() => { setListen(""); setUdp(false); setTarget(""); setPort(""); setUpstream(""); setForwardOpen(true); }}>加转发</Button>;
  const wildcard = g.spec.wildcard ?? [];
  const zones = [...new Set((accounts ?? []).flatMap((a) => a.zones))].filter((z) => !wildcard.includes(z)).sort();
  const saveWildcard = (next: string[], title: string) => {
    setWildcardOpen(false);
    actions.plan({ title, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, wildcard: next } }] });
  };
  const { data: config } = usePoll<{ config: string; compose: string }>(configOpen ? `/api/gateways/${encodeURIComponent(g.name)}/config` : null, 30000);
  return <>
    <SheetHeader className="border-b">
      <SheetTitle>
        {g.name}
      </SheetTitle>
      <SheetDescription>入口（网关）</SheetDescription>
    </SheetHeader>
    <div className="flex-1 overflow-auto p-4">
      <Facts items={[
        ["服务器", <ServerTag name={g.spec.server} />],
        ["类型", g.spec.kind === "cloudflare_tunnel" && `Cloudflare 隧道（wharf-${g.name}）`],
        ["厂商账号", g.spec.kind === "cloudflare_tunnel" && g.spec.account],
        ["证书", g.spec.kind === "caddy" && TLS_TEXT[g.spec.tls ?? "auto"]],
        ["端口", g.spec.kind === "caddy" && <span className="font-mono text-xs">HTTP {g.spec.http_port ?? 80} · HTTPS {g.spec.https_port ?? 443}
        </span>],
        ["错误页", g.spec.kind === "caddy" && <GatewayErrorPage g={g} />],
        ["泛域名证书", g.spec.kind === "caddy" && g.spec.tls !== "off" && <div className="flex flex-wrap items-center gap-2">
          {wildcard.length ? wildcard.map((z) => <span key={z} className="inline-flex min-w-0 max-w-full items-center gap-1">
            <span className="break-all font-mono text-xs">*.{z}</span>
            <Button variant="ghost" size="xs" onClick={() => saveWildcard(wildcard.filter((v) => v !== z), `关闭 *.${z} 的泛域名证书`)}>关闭</Button>
          </span>) : "没开"}
          <Button variant="ghost" size="xs" disabled={!zones.length} onClick={() => { setZone(zones[0] ?? ""); setWildcardOpen(true); }}>开启</Button>
        </div>],
      ]} />
      <SectionTitle>域名</SectionTitle>
      {g.routes.length ? <Rows>
        {g.routes.map((hostname) => <Row key={hostname} onClick={() => onDomain(hostname)}>
          <span className="min-w-0 flex-1 truncate font-mono text-xs">
            {hostname}
          </span>
          <CertDays d={diagnosisOf(status, hostname)} />
        </Row>)}
      </Rows> : <Empty>没有域名</Empty>}
      {g.spec.kind === "caddy" && <>
        <SectionTitle action={addForward}>四层转发</SectionTitle>
        {forwards.length ? <Rows>{forwards.map((f) => <Row key={`${!!f.udp}:${f.listen}`}>
          <span className="shrink-0 font-mono text-xs">:{f.listen}{f.udp ? "/udp" : ""}</span>
          <span className="text-muted-foreground">→</span>
          <span className="min-w-0 flex-1 break-all font-mono text-xs">{f.service ? `${f.service}${f.port ? `:${f.port}` : ""}` : f.upstream}</span>
          <Button variant="ghost" size="xs" onClick={() => saveForwards(forwards.filter((v) => v.listen !== f.listen || !!v.udp !== !!f.udp), `移除 ${g.name} 的四层转发 :${f.listen}`)}>移除</Button>
        </Row>)}</Rows> : <Empty action={addForward}>还没有四层转发</Empty>}
      </>}
      <details className="mt-8 text-sm" onToggle={(e) => setConfigOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer">生成的配置</summary>
        {configOpen && <CodeBlock className="mt-3">
          {config?.config ?? "载入中…"}
        </CodeBlock>}
      </details>
      <details className="mt-8 text-sm" onToggle={(e) => setLogsOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer">日志</summary>
        {logsOpen && <LogStream path={`/api/gateways/${encodeURIComponent(g.name)}/logs/stream`} />}
      </details>
    </div>
    <SheetFooter className="flex-row items-center justify-between border-t">
      <span className="text-xs text-muted-foreground">
        {g.routes.length ? "先移除这个入口上的域名" : ""}
      </span>
      <Button variant="outline" className="text-destructive" disabled={g.routes.length > 0} onClick={() => setRemoving(true)}>
        <Trash2Icon />删除入口</Button>
    </SheetFooter>
    <Dialog open={wildcardOpen} onOpenChange={setWildcardOpen}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>开启泛域名证书</DialogTitle></DialogHeader>
        <Picker value={zone} options={zones.map((z) => ({ value: z, label: z }))} onChange={setZone} />
        <DialogFooter><Button disabled={!zones.includes(zone)} onClick={() => saveWildcard([...wildcard, zone].sort(), `开启 *.${zone} 的泛域名证书`)}>预览改动</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <Dialog open={forwardOpen} onOpenChange={setForwardOpen}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>加四层转发</DialogTitle></DialogHeader>
        <Field label="端口" htmlFor="layer4-listen"><Input id="layer4-listen" type="number" value={listen} onChange={(e) => setListen(e.target.value)} /></Field>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={udp} onCheckedChange={(v) => setUdp(v === true)} />UDP</label>
        <Field label="转到"><Picker value={target} options={[...(services ?? []).map((s) => ({ value: s.name, label: s.name, hint: s.spec.server })), { value: "", label: "其他地址" }]} onChange={(v) => { setTarget(v); setPort(""); }} /></Field>
        {ports.length > 1 && <Field label="端口名"><Picker value={port} options={ports.map((p) => ({ value: p.name, label: p.name }))} onChange={setPort} /></Field>}
        {!target && <Field label="地址" htmlFor="layer4-upstream"><Input id="layer4-upstream" placeholder="127.0.0.1:5432" value={upstream} onChange={(e) => setUpstream(e.target.value)} /></Field>}
        <DialogFooter><Button disabled={!validListen} onClick={() => saveForwards([
          ...forwards.filter((f) => f.listen !== Number(listen) || !!f.udp !== udp),
          { listen: Number(listen), udp, ...(target ? { service: target, ...(port ? { port } : {}) } : { upstream }) },
        ].sort((a, b) => Number(!!a.udp) - Number(!!b.udp) || a.listen - b.listen), `加四层转发 :${Number(listen)}`)}>预览改动</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <ConfirmDialog open={removing} title={`删除入口 ${g.name}？`} onCancel={() => setRemoving(false)} onConfirm={() => { setRemoving(false); onDone(); actions.plan({ title: `删除入口 ${g.name}`, changes: [{ op: "remove_gateway", name: g.name }] }); }}>入口的容器会被删除。</ConfirmDialog>
  </>;
}
