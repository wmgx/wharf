import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Field, Picker } from "@/components/fields";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { useStatus } from "@/status";
import type { GatewayView, ServiceView } from "@/types";

export function ForwardDialog({ gateway, service: fixed, onClose }: { gateway?: GatewayView; service?: string; onClose: () => void }) {
  const actions = useActions();
  const { status } = useStatus();
  const gateways = (status?.gateways ?? []).filter((v) => v.spec.kind === "caddy");
  const [picked, setPicked] = useState(gateways[0]?.name ?? "");
  const g = gateway ?? gateways.find((v) => v.name === picked);
  const [listen, setListen] = useState("");
  const [udp, setUdp] = useState(false);
  const [target, setTarget] = useState(fixed ?? "");
  const [port, setPort] = useState("");
  const [upstream, setUpstream] = useState("");
  const { data: services } = usePoll<ServiceView[]>("/api/services", 30000);
  const service = services?.find((s) => s.name === target);
  const ports = (service?.spec.ports ?? []).filter((p) => !!p.udp === udp);
  const validListen = Number.isInteger(Number(listen)) && Number(listen) >= 1 && Number(listen) <= 65535;
  const saveForwards = (next: NonNullable<GatewayView["spec"]["layer4"]>, title: string) => {
    if (!g) return;
    onClose();
    actions.plan({ title, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, layer4: next } }] });
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>加四层转发</DialogTitle></DialogHeader>
        {!gateway && <Field label="入口"><Picker value={g?.name ?? ""} options={gateways.map((v) => ({ value: v.name, label: v.name }))} onChange={setPicked} /></Field>}
        <Field label="端口" htmlFor="layer4-listen"><Input id="layer4-listen" type="number" value={listen} onChange={(e) => setListen(e.target.value)} /></Field>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={udp} onCheckedChange={(v) => { setUdp(v === true); setPort(""); }} />UDP</label>
        <Field label="转到">{fixed ? <span className="text-sm">{fixed}</span> : <Picker value={target} options={[...(services ?? []).map((s) => ({ value: s.name, label: s.name, hint: s.spec.server })), { value: "", label: "其他地址" }]} onChange={(v) => { setTarget(v); setPort(""); }} />}</Field>
        {ports.length > 1 && <Field label="端口名"><Picker value={port} options={ports.map((p) => ({ value: p.name, label: p.name }))} onChange={setPort} /></Field>}
        {!target && <Field label="地址" htmlFor="layer4-upstream"><Input id="layer4-upstream" placeholder="127.0.0.1:5432" value={upstream} onChange={(e) => setUpstream(e.target.value)} /></Field>}
        <DialogFooter><Button disabled={!g || !validListen || (!target && !upstream.trim()) || (!!target && (!services || !ports.length)) || (ports.length > 1 && !port)} onClick={() => saveForwards([
          ...(g?.spec.layer4 ?? []).filter((f) => f.listen !== Number(listen) || !!f.udp !== udp),
          { listen: Number(listen), udp, ...(target ? { service: target, ...((port || ports[0]?.name) ? { port: port || ports[0].name } : {}) } : { upstream }) },
        ].sort((a, b) => Number(!!a.udp) - Number(!!b.udp) || a.listen - b.listen), `加四层转发 :${Number(listen)}`)}>预览改动</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
