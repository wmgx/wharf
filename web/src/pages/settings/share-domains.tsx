import { useState } from "react";
import { useActions } from "@/components/actions";
import { SectionTitle } from "@/components/common";
import { Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { WildcardDialog } from "@/components/wildcard-dialog";
import { useStatus } from "@/status";

/** 分享域名就是 caddy 入口上的泛域名证书，临时分享在它下面生成随机子域名。 */
export function ShareDomains() {
  const { status } = useStatus();
  const actions = useActions();
  const [adding, setAdding] = useState(false);
  const gateways = (status?.gateways ?? []).filter((g) => g.spec.kind === "caddy" && g.spec.tls !== "off");
  const rows = gateways.flatMap((g) => (g.spec.wildcard ?? []).map((zone) => ({ g, zone })));
  return <>
    <div className="mt-8 flex items-center justify-between gap-2">
      <SectionTitle count={rows.length}>分享域名</SectionTitle>
      <Button variant="outline" size="sm" disabled={!gateways.length} onClick={() => setAdding(true)}>添加</Button>
    </div>
    <p className="mb-2 text-sm text-muted-foreground">临时分享在这些域名下生成随机子域名，用入口上的泛域名证书，不用等签证书。建议单独用一个前缀，例如 *.s.example.com。</p>
    <Panel className="divide-y text-sm">
      {rows.length ? rows.map(({ g, zone }) => <div key={`${g.name}/${zone}`} className="flex items-center justify-between gap-2 p-3">
        <span className="min-w-0 break-all"><span className="font-mono text-xs">*.{zone}</span><span className="text-muted-foreground"> · 入口 {g.name}</span></span>
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `关闭 *.${zone} 的泛域名证书`, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, wildcard: (g.spec.wildcard ?? []).filter((z) => z !== zone) } }] })}>关闭</Button>
      </div>) : <p className="p-3 text-muted-foreground">还没有设置</p>}
    </Panel>
    {adding && <WildcardDialog gateways={gateways} title="添加分享域名" initialPrefix="s" onClose={() => setAdding(false)} />}
  </>;
}
