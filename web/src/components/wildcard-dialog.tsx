import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { AccountView, GatewayView } from "@/types";

export function WildcardDialog({ g, initialZone = "", onClose }: { g: GatewayView; initialZone?: string; onClose: () => void }) {
  const actions = useActions();
  const [zone, setZone] = useState(initialZone);
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 30000);
  const zones = [...new Set((accounts ?? []).flatMap((a) => a.zones))].filter((z) => !g.spec.wildcard?.includes(z)).sort();
  const chosen = zone || zones[0] || "";
  return <Dialog open onOpenChange={(open) => !open && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>开启泛域名证书</DialogTitle></DialogHeader>
      <Picker value={chosen} options={zones.map((z) => ({ value: z, label: z }))} onChange={setZone} />
      <DialogFooter><Button disabled={!zones.includes(chosen)} onClick={() => {
        onClose();
        actions.plan({ title: `开启 *.${chosen} 的泛域名证书`, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, wildcard: [...(g.spec.wildcard ?? []), chosen].sort() } }] });
      }}>预览改动</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
