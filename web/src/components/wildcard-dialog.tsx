import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { AccountView, GatewayView } from "@/types";

const PREFIX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

/** 给 caddy 入口开泛域名证书。可以加前缀，例如 s → *.s.example.com，专门给临时分享用。 */
export function WildcardDialog({ gateways, title = "开启泛域名证书", initialPrefix = "", onDone, onClose }: {
  gateways: GatewayView[];
  title?: string;
  initialPrefix?: string;
  onDone?: () => void;
  onClose: () => void;
}) {
  const actions = useActions();
  const [gateway, setGateway] = useState("");
  const [root, setRoot] = useState("");
  const [prefix, setPrefix] = useState(initialPrefix);
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 30000);
  const roots = [...new Set((accounts ?? []).flatMap((a) => a.zones))].sort();
  const g = gateways.find((x) => x.name === gateway) ?? gateways.find((x) => x.spec.default) ?? gateways[0];
  const chosenRoot = roots.includes(root) ? root : roots[0] ?? "";
  const p = prefix.trim().toLowerCase().replace(/\.+$/, "");
  const zone = p ? `${p}.${chosenRoot}` : chosenRoot;
  const exists = !!g?.spec.wildcard?.includes(zone);
  const valid = !!g && !!chosenRoot && (!p || PREFIX.test(p)) && !exists;
  const submit = () => {
    if (!g) return;
    onClose();
    onDone?.();
    actions.plan({ title: `开启 *.${zone} 的泛域名证书`, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, wildcard: [...(g.spec.wildcard ?? []), zone].sort() } }] });
  };
  return <Dialog open onOpenChange={(open) => !open && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>{title}</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        {gateways.length > 1 && <Field label="入口" htmlFor="wildcard-gateway">
          <Picker id="wildcard-gateway" value={g?.name ?? ""} options={gateways.map((x) => ({ value: x.name, label: x.name }))} onChange={setGateway} />
        </Field>}
        <Field label="域名" htmlFor="wildcard-root" help={roots.length ? undefined : "厂商账号里还没有域名，先在 设置 · 厂商账号 里添加"}>
          <Picker id="wildcard-root" value={chosenRoot} options={roots.map((z) => ({ value: z, label: z }))} onChange={setRoot} />
        </Field>
        <Field label="前缀" htmlFor="wildcard-prefix" help={exists ? `入口 ${g?.name} 已经开了 *.${zone}` : p && !PREFIX.test(p) ? "只能用小写字母、数字、横线和点" : `证书是 *.${zone}${p ? "，不影响其他域名" : "，这个入口上它下一级的域名都会改用这张证书"}`}>
          <Input id="wildcard-prefix" value={prefix} placeholder="留空就是整个域名" onChange={(e) => setPrefix(e.target.value)} />
        </Field>
      </div>
      <DialogFooter><Button disabled={!valid} onClick={submit}>预览改动</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
