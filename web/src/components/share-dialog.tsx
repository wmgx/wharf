import { useState } from "react";
import { useActions } from "@/components/actions";
import { AuthFields, authReady, saveAuth } from "@/components/basic-auth";
import { ErrorNote } from "@/components/common";
import { Field, Picker, Segmented } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { WildcardDialog } from "@/components/wildcard-dialog";
import { useStatus } from "@/status";

export function ShareDialog({ service, open, onClose }: { service: string; open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const [ttl, setTtl] = useState("7200000");
  const [gateway, setGateway] = useState("");
  const [zone, setZone] = useState("");
  const [port, setPort] = useState("");
  const [setting, setSetting] = useState(false);
  const [protection, setProtection] = useState<"none" | "basic" | "gate">("none");
  const [user, setUser] = useState("guest");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const candidates = (status?.gateways ?? []).filter((g) => g.spec.kind === "caddy" && g.spec.tls !== "off");
  const gateways = (status?.gateways ?? []).filter((g) => g.spec.kind === "caddy" && (g.spec.wildcard ?? []).length > 0);
  const selected = gateways.find((g) => g.name === gateway) ?? gateways.find((g) => g.spec.default) ?? gateways[0];
  const zones = selected?.spec.wildcard ?? [];
  const suffix = zones.includes(zone) ? zone : zones[0];
  const ports = (status?.services.find((s) => s.name === service)?.spec.ports ?? []).filter((p) => !p.udp);
  const selectedPort = ports.find((p) => p.name === port)?.name ?? ports[0]?.name;
  const submit = async () => {
    if (!selected || !suffix) return;
    const label = [...crypto.getRandomValues(new Uint8Array(10))].map((b) => "0123456789abcdefghijklmnopqrstuvwxyz"[b % 36]).join("");
    const hostname = `${label}.${suffix}`;
    const basic = protection === "basic";
    setSaving(true); setFailure(null);
    try { if (basic) await saveAuth(hostname, user, password); }
    catch (e) { setFailure(e); return; }
    finally { setSaving(false); }
    setPassword("");
    actions.plan({ title: `分享 ${service}`, changes: [{ op: "upsert_route", spec: { hostname, service, port: selectedPort, gateway: selected.name, expires_at: Date.now() + Number(ttl), auth: basic, sso: protection === "gate" ? { mode: "gate" } : undefined } }] });
    onClose();
  };
  if (setting) return <WildcardDialog gateways={candidates} title="设置分享域名" initialPrefix="s" onDone={onClose} onClose={() => setSetting(false)} />;
  return <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>分享 {service}</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        <Field label="有效期" htmlFor="share-ttl">
          <Picker id="share-ttl" value={ttl} options={[{ value: "3600000", label: "1 小时" }, { value: "7200000", label: "2 小时" }, { value: "86400000", label: "1 天" }, { value: "604800000", label: "7 天" }]} onChange={setTtl} />
        </Field>
        {selected ? <Field label="入口" htmlFor="share-gateway">
          <Picker id="share-gateway" value={selected.name} options={gateways.map((g) => ({ value: g.name, label: g.name }))} onChange={setGateway} />
        </Field> : <div className="grid gap-2 text-sm">
          <p className="text-muted-foreground">还没有设置分享域名。分享会在它下面生成一个随机子域名，例如 k3x9q2m7ab.s.example.com，不用等签证书。</p>
          <Button variant="outline" className="justify-self-start" disabled={!candidates.length} onClick={() => setSetting(true)}>设置分享域名</Button>
          {!candidates.length && <p className="text-muted-foreground">没有可用的 caddy 入口</p>}
        </div>}
        {zones.length > 1 && <Field label="域名后缀" htmlFor="share-zone">
          <Picker id="share-zone" value={suffix} options={zones.map((z) => ({ value: z, label: z }))} onChange={setZone} />
        </Field>}
        {selected && <Field label="访问保护" help={protection === "basic" ? "对方打开链接时要输入这组账号密码，密码至少 8 位" : protection === "gate" ? "要先登录 Wharf 才能打开，只适合你自己用" : "拿到链接的人都能直接访问"}>
          <Segmented value={protection} options={[["none", "不保护"], ["basic", "账号密码"], ["gate", "Wharf 登录"]]} onChange={setProtection} />
        </Field>}
        {selected && protection === "basic" && <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />}
        {ports.length > 1 && <Field label="端口" htmlFor="share-port">
          <Picker id="share-port" value={selectedPort ?? ""} options={ports.map((p) => ({ value: p.name, label: p.name }))} onChange={setPort} />
        </Field>}
      </div>
      <ErrorNote error={failure} />
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>取消</Button>
        <Button disabled={!selected || saving || (protection === "basic" && !authReady(user, password))} onClick={submit}>{saving ? "保存中…" : "预览改动"}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
