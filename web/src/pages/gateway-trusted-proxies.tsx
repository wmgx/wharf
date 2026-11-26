import { useState } from "react";
import { useActions } from "@/components/actions";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import type { GatewayView } from "@/types";

export function GatewayTrustedProxies({ g }: { g: GatewayView }) {
  const actions = useActions();
  const [open, setOpen] = useState(false);
  const [cloudflare, setCloudflare] = useState(false);
  const [cluster, setCluster] = useState(false);
  const [cidrs, setCidrs] = useState("");
  const current = g.spec.trusted_proxies;
  const count = current?.cidrs?.length ?? 0;
  const status = [
    current?.cloudflare && "Cloudflare",
    current?.cluster && "集群网关与组网服务器",
    count > 0 && `自定义 ${count} 条`,
  ].filter(Boolean).join(" · ");

  const save = () => {
    const entries = cidrs.split("\n").map((cidr) => cidr.trim()).filter(Boolean);
    const trusted_proxies = cloudflare || cluster || entries.length
      ? { cloudflare, cluster, cidrs: entries }
      : undefined;
    setOpen(false);
    actions.plan({
      title: `修改入口 ${g.name} 的可信代理`,
      changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, trusted_proxies } }],
    });
  };

  return (
    <>
      <span className="inline-flex flex-wrap items-center gap-2">
        {status || "未配置"}
        <Button variant="ghost" size="xs" onClick={() => {
          setCloudflare(current?.cloudflare ?? false);
          setCluster(current?.cluster ?? false);
          setCidrs(current?.cidrs?.join("\n") ?? "");
          setOpen(true);
        }}>编辑</Button>
      </span>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>可信代理</DialogTitle>
          </DialogHeader>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={cloudflare} onCheckedChange={(checked) => setCloudflare(checked === true)} />
            Cloudflare
          </label>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={cluster} onCheckedChange={(checked) => setCluster(checked === true)} />
            集群网关与组网服务器
          </label>
          <label className="space-y-2 text-sm">
            <span>自定义 IP 或 CIDR</span>
            <Textarea className="min-h-32 font-mono text-xs" value={cidrs} onChange={(e) => setCidrs(e.target.value)} />
          </label>
          <DialogFooter>
            <Button onClick={save}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
