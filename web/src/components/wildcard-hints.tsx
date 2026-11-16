import { useState } from "react";
import { usePoll } from "@/api";
import { Button } from "@/components/ui/button";
import { WildcardDialog } from "@/components/wildcard-dialog";
import type { AccountView, GatewayView, Status } from "@/types";

export function WildcardHints({ status, gateway }: { status: Status; gateway?: string }) {
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 30000);
  const [picked, setPicked] = useState<{ g: GatewayView; zone: string } | null>(null);
  const zones = [...new Set((accounts ?? []).flatMap((a) => a.zones))];
  const hints = status.gateways.filter((g) => (!gateway || g.name === gateway) && g.spec.kind === "caddy" && g.spec.tls !== "off").flatMap((g) => zones.filter((zone) => !g.spec.wildcard?.includes(zone) && status.routes.filter((r) => r.gateway === g.name && r.spec.hostname.endsWith(`.${zone}`) && r.spec.hostname.slice(0, -zone.length - 1).split(".").length === 1).length >= 2).map((zone) => ({ g, zone })));
  return <>
    {hints.map(({ g, zone }) => <Button key={`${g.name}/${zone}`} variant="outline" size="sm" className="mb-3 h-auto max-w-full whitespace-normal text-left" onClick={() => setPicked({ g, zone })}>{g.name} · {zone} 有多个域名，开启泛域名证书</Button>)}
    {picked && <WildcardDialog g={picked.g} initialZone={picked.zone} onClose={() => setPicked(null)} />}
  </>;
}
