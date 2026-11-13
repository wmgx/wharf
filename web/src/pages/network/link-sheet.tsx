import { useState } from "react";
import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { Empty, Notice, SectionTitle, StatusBadge, ago } from "@/components/common";
import { Segmented } from "@/components/fields";
import { hopOf } from "@/components/hop";
import { Row, Rows } from "@/components/kit";
import { Chart } from "@/components/metrics";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { NetworkView, Status } from "@/types";
import { affected, linkState, pairs } from "./model";

interface MetricsView { from: number; to: number; step_ms: number; series: Record<string, [number, number][]> }

export function LinkSheet({ a, b, net, status, onClose }: { a: string; b: string; net: NetworkView; status: Status; onClose: () => void }) {
  const [range, setRange] = useState<"24h" | "7d">("24h");
  const path = (from: string, to: string) => `/api/metrics?subject=${encodeURIComponent(`${from}>${to}`)}&names=link.ms,link.loss&range=${range}`;
  const { data: ab } = usePoll<MetricsView>(path(a, b), 60000);
  const { data: ba } = usePoll<MetricsView>(path(b, a), 60000);
  const pair = pairs(net).find((p) => p.a === a && p.b === b);
  const through = affected(a, b, status);
  const span: [number, number] = ab ? [ab.from, ab.to] : ba ? [ba.from, ba.to] : [0, 1];
  const gap = (ab?.step_ms ?? ba?.step_ms ?? 60000) * 2.5;
  const series = (name: string) => [{ label: `${a} → ${b}`, points: ab?.series[name] ?? [], color: "var(--primary)" }, { label: `${b} → ${a}`, points: ba?.series[name] ?? [], color: "var(--success)" }];
  const empty = [ab, ba].every((d) => !d || !Object.values(d.series).some((points) => points.length));
  return <Sheet open onOpenChange={(open) => !open && onClose()}>
    <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
      <SheetHeader className="border-b">
        <SheetTitle>
          {a} ⇄ {b}
        </SheetTitle>
      </SheetHeader>
      <div className="flex-1 overflow-auto p-4">
        <SectionTitle>现在</SectionTitle>
        <Rows>
          {[[a, b], [b, a]].map(([from, to]) => {
            const state = linkState(from, to, net);
            const link = net.links?.find((l) => l.from === from && l.to === to);
            const reach = net.reach.find((r) => r.from === from && r.to === to);
            return <Row key={from}>
              <span className="flex-1">
                {from} → {to}
              </span>
              <StatusBadge tone={state.tone}>
                {state.text}
              </StatusBadge>
              <span className="text-xs text-muted-foreground">
                {link ? `${ago(link.at)}测量` : reach ? `${ago(reach.checked_at)}检查` : ""}
              </span>
            </Row>;
          })}
        </Rows>
        {[[a, b], [b, a]].map(([from, to]) => linkState(from, to, net).text === "不通" && <Notice key={from} kind="warn" className="mt-3">
          {from} 连不上 {to}：不能把服务从 {from} 迁到 {to}，也不能备份到 {to}；经过这条链路的域名会改走反向隧道。</Notice>)}
        {pair?.relay && <Notice kind="info" className="mt-3">
          {pair.relay}
        </Notice>}
        <SectionTitle action={<Segmented value={range} options={[["24h", "24 小时"], ["7d", "7 天"]]} onChange={setRange} />}>历史</SectionTitle>
        {empty ? <Empty>还没有历史数据，每 5 分钟测一次</Empty> : <div className="grid gap-3">
          <Chart title="延迟" span={span} gap={gap} format={(n) => `${n.toFixed(0)} ms`} lines={series("link.ms")} />
          <Chart title="丢包" span={span} gap={gap} max={100} format={(n) => `${n.toFixed(0)}%`} lines={series("link.loss")} />
        </div>}
        <SectionTitle>经过这条链路的</SectionTitle>
        {!through.routes.length && !through.deps.length && !through.egress.length ? <p className="text-sm text-muted-foreground">现在没有东西经过这条链路</p> : <Rows>
          {through.routes.map((r) => <Row key={r.id}>
            <Link className="hover:underline" to={`/domains?open=${encodeURIComponent(r.spec.hostname)}`}>
              {r.spec.hostname}
            </Link>
            <span className="text-xs text-muted-foreground">
              {hopOf(r, status).text}
            </span>
          </Row>)}
          {through.deps.map(([from, to]) => <Row key={`${from}-${to}`}>
            <Link className="hover:underline" to={`/services/${encodeURIComponent(from)}`}>
              {from}
            </Link> → <Link className="hover:underline" to={`/services/${encodeURIComponent(to)}`}>
              {to}
            </Link>
          </Row>)}
          {through.egress.map(([from, to]) => <Row key={from}>
            {from} 经 {to}
          </Row>)}
        </Rows>}
      </div>
    </SheetContent>
  </Sheet>;
}
