import { useState } from "react";
import { useActions } from "@/components/actions";
import { DomainChips, Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";

export function AddRedirect({ open, onClose, target: initialTarget, gateway: initialGateway }: { open: boolean; onClose: () => void; target?: string; gateway?: string }) {
  const { status } = useStatus();
  const actions = useActions();
  const [hostname, setHostname] = useState("");
  const [target, setTarget] = useState(initialTarget ?? "");
  const [picked, setPicked] = useState("");
  const gateways = (status?.gateways ?? []).filter((g) => g.spec.kind === "caddy");
  const gateway = picked || gateways.find((g) => g.name === initialGateway)?.name || gateways.find((g) => g.spec.default)?.name || gateways[0]?.name || "";
  const submit = () => {
    actions.plan({ title: "加跳转", changes: [{ op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), redirect: target.trim(), gateway } }] });
    onClose();
    setHostname("");
    setTarget(initialTarget ?? "");
    setPicked("");
  };
  return <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>加跳转</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        <Field label="域名" htmlFor="redirect-hostname">
          <Input id="redirect-hostname" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="www.example.com" />
        </Field>
        <Field label="跳转到" htmlFor="redirect-target">
          <Input id="redirect-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" />
          <DomainChips suggestions={(status?.routes ?? []).filter((r) => !r.spec.redirect).slice(0, 6).map((r) => `https://${r.spec.hostname}`)} onPick={setTarget} />
        </Field>
        <Field label="入口" htmlFor="redirect-gateway">
          <Picker id="redirect-gateway" value={gateway} onChange={setPicked} options={gateways.map((g) => ({ value: g.name, label: `${g.name}（${g.spec.server}）` }))} />
          {!gateways.length && <p className="text-sm text-muted-foreground">还没有 caddy 入口</p>}
        </Field>
      </div>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>取消</Button>
        <Button disabled={!hostname.trim() || !/^https?:\/\//.test(target.trim()) || !gateway} onClick={submit}>预览改动</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
