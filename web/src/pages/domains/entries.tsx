import { PlusIcon } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { CardsSkeleton, Empty, ServerTag, StatusBadge, liveTone, useClickable } from "@/components/common";
import { Panel } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import { GatewayDetail } from "./entry-detail";
import { NewGateway } from "./new-entry";

const tlsText = { auto: "自动签证书", internal: "自签证书", off: "只走 HTTP" };

export function Entries() {
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const clickable = useClickable();
  const gateways = status?.gateways ?? [];
  const selected = gateways.find((g) => g.name === params.get("entry"));
  const creating = params.get("new") === "1";
  const add = <Button variant="outline" size="sm" onClick={() => setParams({ tab: "entries", new: "1" })}>
    <PlusIcon />新建入口</Button>;
  return <>
    <div className="mb-4 flex justify-end">
      {gateways.length > 0 && add}
    </div>
    {!status ? <CardsSkeleton count={2} /> : !gateways.length ? <Empty action={add}>还没有入口</Empty> : <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>入口</TableHead>
            <TableHead>类型</TableHead>
            <TableHead>所在</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>域名</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {gateways.map((g) => {
            const { tone, text } = liveTone(g.live); return <TableRow key={g.name} className="cursor-pointer" {...clickable({ to: `?tab=entries&entry=${encodeURIComponent(g.name)}` })}>
              <TableCell>
                {g.name} {g.spec.default && <Badge variant="secondary">默认</Badge>}
              </TableCell>
              <TableCell>
                {g.spec.kind === "cloudflare_tunnel" ? "Cloudflare 隧道" : `Caddy · ${tlsText[g.spec.tls ?? "auto"]}`}
              </TableCell>
              <TableCell>
                <ServerTag name={g.spec.server} />
              </TableCell>
              <TableCell>
                <StatusBadge tone={tone}>
                  {text}
                </StatusBadge>
              </TableCell>
              <TableCell>
                <Button variant="ghost" size="xs" onClick={(e) => { e.stopPropagation(); setParams({ gateway: g.name }); }}>
                  {g.routes.length}
                </Button>
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
    <Sheet open={!!selected} onOpenChange={(open) => !open && setParams({ tab: "entries" })}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" onOpenAutoFocus={(e) => e.preventDefault()}>
        {selected && <GatewayDetail g={selected} onDone={() => setParams({ tab: "entries" })} onDomain={(hostname) => setParams({ open: hostname })} />}
      </SheetContent>
    </Sheet>
    <Sheet open={creating} onOpenChange={(open) => !open && setParams({ tab: "entries" })}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        <SheetHeader className="border-b">
          <SheetTitle>新建入口</SheetTitle>
        </SheetHeader>
        {creating && <NewGateway onDone={() => setParams({ tab: "entries" })} />}
      </SheetContent>
    </Sheet>
  </>;
}
