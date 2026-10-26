import { useMemo, useRef, useState } from "react";
import { usePoll } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { Segmented } from "@/components/fields";
import { Card, CardContent } from "@/components/ui/card";

type Range = "1h" | "24h" | "7d";
const RANGES: [Range, string][] = [
  ["1h", "1 小时"],
  ["24h", "24 小时"],
  ["7d", "7 天"],
];

type Point = [number, number];

interface MetricsView {
  from: number;
  to: number;
  step_ms: number;
  series: Record<string, Point[]>;
}

export function bytes(n: number): string {
  const units = ["B", "K", "M", "G", "T"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)}${units[i]}`;
}

const pct = (n: number) => `${n.toFixed(1)}%`;
const rate = (n: number) => `${bytes(n)}/s`;
const secs = (n: number) => (n < 90 ? `${n.toFixed(0)} 秒` : `${(n / 60).toFixed(1)} 分`);

interface Line {
  label: string;
  points: Point[];
  color: string;
}

/** 服务器（`host`）或服务（`svc`）的资源曲线，加上事件点（部署、备份耗时）。 */
export function MetricsPanel({ subject, kind, title = "资源" }: { subject: string; kind: "host" | "svc"; title?: string }) {
  const [range, setRange] = useState<Range>("24h");
  const { data, error } = usePoll<MetricsView>(`/api/metrics?subject=${encodeURIComponent(subject)}&range=${range}`, 60000);
  const s = data?.series ?? {};
  const get = (name: string) => s[`${kind}.${name}`] ?? [];
  const last = (name: string) => get(name).at(-1)?.[1];
  const span: [number, number] = data ? [data.from, data.to] : [0, 1];
  const gap = (data?.step_ms ?? 60000) * 2.5;
  const memTotal = last("mem_total");
  const diskTotal = last("disk_total");
  const deploys = s["deploy.secs"] ?? [];
  const backups = s["backup.secs"] ?? [];

  return (
    <>
      <div className={`${title ? "mt-8" : ""} mb-3 flex items-center justify-between [&>h2]:my-0`}>
        {title ? <SectionTitle>{title}</SectionTitle> : <span />}
        <Segmented value={range} options={RANGES} onChange={setRange} />
      </div>
      <ErrorNote error={error} />
      <div className="grid gap-3 md:grid-cols-2">
        <Chart title="CPU" span={span} gap={gap} max={kind === "host" ? 100 : undefined} format={pct} lines={[{ label: "CPU", points: get("cpu"), color: "var(--primary)" }]} />
        <Chart
          title="内存"
          note={memTotal ? `共 ${bytes(memTotal)}` : undefined}
          span={span}
          gap={gap}
          max={memTotal}
          format={bytes}
          lines={[{ label: "已用", points: get("mem"), color: "var(--primary)" }]}
        />
        <Chart
          title="网络"
          span={span}
          gap={gap}
          format={rate}
          lines={[
            { label: "收", points: get("net_rx"), color: "var(--primary)" },
            { label: "发", points: get("net_tx"), color: "var(--success)" },
          ]}
        />
        {kind === "host" ? (
          <Chart
            title="磁盘"
            note={diskTotal ? `共 ${bytes(diskTotal)}` : undefined}
            span={span}
            gap={gap}
            max={diskTotal}
            format={bytes}
            lines={[{ label: "已用", points: get("disk"), color: "var(--warning)" }]}
          />
        ) : (
          (deploys.length > 0 || backups.length > 0) && (
            <Chart
              title="耗时"
              span={span}
              gap={0}
              format={secs}
              lines={[
                { label: "部署", points: deploys, color: "var(--primary)" },
                { label: "备份", points: backups, color: "var(--warning)" },
              ].filter((l) => l.points.length > 0)}
            />
          )
        )}
      </div>
    </>
  );
}

const W = 600;
const H = 140;
const PAD = { top: 8, bottom: 18, left: 0, right: 0 };

/** 折线图：时间是横轴；相邻两点隔得比 `gap` 远就断开（agent 离线）。`gap` 为 0 时只画点（事件）。 */
function Chart({
  title,
  note,
  lines,
  span,
  gap,
  max,
  format,
}: {
  title: string;
  note?: string;
  lines: Line[];
  span: [number, number];
  gap: number;
  max?: number;
  format: (n: number) => string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const ref = useRef<SVGSVGElement>(null);
  const [from, to] = span;
  const top = useMemo(() => {
    const peak = Math.max(0, ...lines.flatMap((l) => l.points.map((p) => p[1])));
    return max && max > 0 ? max : peak > 0 ? peak * 1.15 : 1;
  }, [lines, max]);
  const x = (t: number) => ((t - from) / (to - from || 1)) * W;
  const y = (v: number) => PAD.top + (1 - Math.min(v, top) / top) * (H - PAD.top - PAD.bottom);
  const empty = lines.every((l) => l.points.length === 0);

  const path = (points: Point[]) => {
    let d = "";
    points.forEach(([t, v], i) => {
      const jump = i === 0 || t - points[i - 1][0] > gap;
      d += `${jump ? "M" : "L"}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
    });
    return d;
  };

  // 鼠标所在时间点上每条线最近的值。
  const nearest = (points: Point[], t: number) => {
    let best: Point | null = null;
    for (const p of points) if (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
    return best && Math.abs(best[0] - t) <= Math.max(gap, (to - from) / 60) ? best : null;
  };
  const hoverT = hover != null ? from + (hover / W) * (to - from) : null;
  const hovered = hoverT != null ? lines.map((l) => ({ l, p: nearest(l.points, hoverT) })) : [];
  const shown = hovered.length ? hovered : lines.map((l) => ({ l, p: l.points.at(-1) ?? null }));
  const at = hovered.find((h) => h.p)?.p?.[0];

  const onMove = (e: React.PointerEvent) => {
    const r = ref.current?.getBoundingClientRect();
    if (r) setHover(((e.clientX - r.left) / r.width) * W);
  };

  return (
    <Card className="gap-2 py-4">
      <CardContent className="px-4">
        <div className="mb-2 flex items-baseline justify-between gap-2 text-sm">
          <span className="font-medium">
            {title}
            {note && <span className="ml-2 text-xs font-normal text-muted-foreground">{note}</span>}
          </span>
          <span className="flex gap-3 font-mono text-xs tabular-nums">
            {at != null && <span className="text-muted-foreground">{clock(at, to - from)}</span>}
            {shown.map(({ l, p }) => (
              <span key={l.label} className="flex items-center gap-1">
                {lines.length > 1 && <span className="size-2 rounded-full" style={{ background: l.color }} />}
                {lines.length > 1 && <span className="text-muted-foreground">{l.label}</span>}
                {p ? format(p[1]) : "-"}
              </span>
            ))}
          </span>
        </div>
        <svg
          ref={ref}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="h-32 w-full touch-none overflow-visible"
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
        >
          {[0.25, 0.5, 0.75].map((f) => (
            <line key={f} x1={0} x2={W} y1={y(top * f)} y2={y(top * f)} className="stroke-border" strokeDasharray="2 4" vectorEffect="non-scaling-stroke" />
          ))}
          <line x1={0} x2={W} y1={y(0)} y2={y(0)} className="stroke-border" vectorEffect="non-scaling-stroke" />
          {empty && (
            <text x={W / 2} y={H / 2} textAnchor="middle" className="fill-muted-foreground text-[11px]" style={{ fontSize: 11 }}>
              没有数据
            </text>
          )}
          {lines.map((l) =>
            gap > 0 ? (
              <path key={l.label} d={path(l.points)} fill="none" stroke={l.color} strokeWidth={1.5} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
            ) : (
              l.points.map(([t, v]) => <circle key={`${l.label}${t}`} cx={x(t)} cy={y(v)} r={3} fill={l.color} vectorEffect="non-scaling-stroke" />)
            ),
          )}
          {hover != null && <line x1={hover} x2={hover} y1={PAD.top} y2={H - PAD.bottom} className="stroke-muted-foreground/50" vectorEffect="non-scaling-stroke" />}
        </svg>
        <div className="mt-1 flex justify-between font-mono text-[10px] text-muted-foreground">
          <span>{clock(from, to - from)}</span>
          <span>{empty ? "" : `最高 ${format(top)}`}</span>
          <span>现在</span>
        </div>
      </CardContent>
    </Card>
  );
}

function clock(ms: number, span: number): string {
  const d = new Date(ms);
  const hm = d.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false });
  return span > 86400000 ? `${d.getMonth() + 1}-${d.getDate()} ${hm}` : hm;
}
