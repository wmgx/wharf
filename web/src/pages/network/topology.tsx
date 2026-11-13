import { Facts, Panel, Tip } from "@/components/kit";
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeChange, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ExternalLinkIcon, LayoutGridIcon, XIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { diskText, Dot, MODES, liveTone, serverText, serviceTone, serverTone, type Tone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import type { NetworkView, Status } from "@/types";
import { hopOf } from "@/components/hop";
import { pairs } from "./model";

const COL = 200;
const GROUP_H = 250;

type BoxData = { kind: string; name: string; tone?: Tone; cls?: string; to?: string };
type GroupData = { name: string; tone: Tone; sub: string; disk?: { text: string; low: boolean } | null };
/** 域名链路上的线都记着属于哪个域名，点一个节点时顺着域名找上下游。 */
type LinkData = { route?: string; reachOk?: boolean; okLabel?: string };

function BoxNode({ data }: NodeProps<Node<BoxData>>) {
  return (
    <div
      className={cn(
        "min-w-36 cursor-pointer rounded-lg border bg-card px-3 py-2 shadow-xs transition-colors hover:border-foreground/20",
        data.cls === "core" && "border-primary ring-3 ring-primary/10",
      )}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="text-xs text-muted-foreground">{data.kind}</div>
      <div className={cn("flex items-center gap-1.5 text-sm font-medium", data.cls === "route" && "font-mono text-xs font-normal")}>
        {data.tone && <Dot tone={data.tone} />}
        {data.name}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle id="r" type="source" position={Position.Right} style={{ opacity: 0 }} />
      <Handle id="l" type="target" position={Position.Left} style={{ opacity: 0 }} />
    </div>
  );
}

function GroupNode({ data }: NodeProps<Node<GroupData>>) {
  return (
    <div className="size-full rounded-xl border bg-muted/40">
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle id="bs" type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle id="bt" type="target" position={Position.Bottom} style={{ opacity: 0 }} />
      <div className="absolute top-2.5 left-3.5 flex items-center gap-2 text-sm font-semibold">
        <Dot tone={data.tone} />
        {data.name}
        <span className="font-mono text-xs font-normal text-muted-foreground">{data.sub}</span>
      </div>
      {data.disk && (
        <div className={cn("absolute right-3.5 bottom-2.5 font-mono text-xs", data.disk.low ? "text-warning" : "text-muted-foreground")}>
          磁盘剩 {data.disk.text}
        </div>
      )}
    </div>
  );
}

const nodeTypes = { box: BoxNode, group: GroupNode };

const go = "var(--success)";
const signal = "var(--warning)";
const stop = "var(--destructive)";
const fog = "var(--muted-foreground)";
const labelStyle = { fill: "var(--muted-foreground)", fontFamily: "Geist Mono, monospace", fontSize: 11 };

function perServerCount(status: Status, server: string): number {
  return status.routes.filter((r) => status.gateways.find((g) => g.name === r.gateway)?.spec.server === server).length;
}

type XY = { x: number; y: number };
const LAYOUT_KEY = "wharf.topology.layout";
function loadLayout(): Record<string, XY> {
  try {
    return JSON.parse(localStorage.getItem(LAYOUT_KEY) ?? "{}");
  } catch {
    return {};
  }
}
function saveLayout(l: Record<string, XY>) {
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(l));
  } catch {
    // 存不了就只在这次有效
  }
}

function build(status: Status, net: NetworkView | null): { nodes: Node[]; edges: Edge<LinkData>[] } {
  const nodes: Node[] = [];
  const edges: Edge<LinkData>[] = [];
  const modeOf = new Map(net?.servers.map((s) => [s.name, s.mode]));

  let x = 0;
  status.servers.forEach((srv) => {
    const gws = status.gateways.filter((g) => g.spec.server === srv.name);
    const svcs = status.services.filter((s) => s.spec.server === srv.name);
    const width = Math.max(gws.length, svcs.length, 1) * COL + 40;
    const tone: Tone = serverTone(srv);
    const mode = modeOf.get(srv.name);
    const addr = [mode && MODES[mode], srv.private_addr?.ip ?? "无内网地址"].filter(Boolean).join(" · ");
    nodes.push({
      id: `srv:${srv.name}`,
      type: "group",
      position: { x, y: 0 },
      data: { name: srv.name, tone, sub: addr, disk: diskText(srv) },
      style: { width, height: GROUP_H },
    });
    gws.forEach((g, i) => {
      nodes.push({
        id: `gw:${g.name}`,
        type: "box",
        parentId: `srv:${srv.name}`,
        position: { x: 20 + i * COL, y: 44 },
        data: { kind: "入口", name: g.name, tone: liveTone(g.live).tone, to: "/domains?tab=entries" },
      });
    });
    svcs.forEach((s, i) => {
      nodes.push({
        id: `svc:${s.name}`,
        type: "box",
        parentId: `srv:${srv.name}`,
        position: { x: 20 + i * COL, y: 150 },
        data: { kind: "服务", name: s.name, tone: serviceTone(s).tone, to: `/services/${s.name}` },
      });
    });
    edges.push({
      id: `core-${srv.name}`,
      source: "core",
      target: `srv:${srv.name}`,
      label: srv.online ? (srv.rtt_ms != null ? `${srv.rtt_ms} ms` : "在线") : "离线",
      style: { stroke: !srv.online ? stop : fog, strokeDasharray: srv.online ? undefined : "6 4" },
      labelStyle: { ...labelStyle, fill: !srv.online ? stop : labelStyle.fill },
    });
    x += width + 60;
  });

  nodes.unshift({
    id: "core",
    type: "box",
    position: { x: Math.max(0, x - 60) / 2 - 80, y: -110 - Math.ceil(Math.max(1, ...status.servers.map((s) => perServerCount(status, s.name))) / 3) * 70 - 60 },
    data: { kind: "控制面", name: "wharf-core", cls: "core" },
  });

  // 域名放在它的网关所在机器上方，一排排往上摞；没有网关的放最左。
  const groupX = new Map(nodes.filter((n) => n.type === "group").map((n) => [n.id.slice(4), n.position.x]));
  const perServer = new Map<string, number>();
  status.routes.forEach((r) => {
    const id = `rt:${r.spec.hostname}`;
    const server = status.gateways.find((g) => g.name === r.gateway)?.spec.server ?? "";
    const k = perServer.get(server) ?? 0;
    perServer.set(server, k + 1);
    const base = groupX.get(server) ?? -COL - 60;
    nodes.push({
      id,
      type: "box",
      position: { x: base + 20 + (k % 3) * COL, y: -110 - Math.floor(k / 3) * 70 },
      data: { kind: "域名", name: r.spec.hostname, cls: "route", to: r.spec.service ? `/services/${r.spec.service}` : undefined },
    });
    if (!r.gateway) return;
    edges.push({
      id: `${id}-gw`,
      source: id,
      sourceHandle: "r",
      target: `gw:${r.gateway}`,
      targetHandle: "l",
      animated: true,
      data: { route: id },
      style: { stroke: go },
    });
    if (!r.spec.service) return;
    const hop = hopOf(r, status);
    const plain = hop.kind === "direct" && hop.plain;
    edges.push({
      id: `${id}-svc`,
      source: `gw:${r.gateway}`,
      target: `svc:${r.spec.service}`,
      label: hop.kind === "local" ? undefined : hop.text.replace(/^直连 · /, ""),
      type: "smoothstep",
      data: { route: id },
      style: { stroke: plain ? signal : go, strokeDasharray: plain ? "6 4" : hop.kind === "tunnel" ? "2 4" : undefined },
      labelStyle: { ...labelStyle, fill: plain ? signal : labelStyle.fill },
    });
  });

  const known = new Set(status.servers.map((s) => s.name));
  (net ? pairs(net) : []).filter((p) => p.tone !== "idle" && known.has(p.a) && known.has(p.b)).forEach((p, i) => {
    const order = { bad: 0, warn: 1, idle: 2, ok: 3 };
    const worst = order[p.ab.tone] <= order[p.ba.tone] ? p.ab : p.ba;
    const metrics = net?.links?.filter((l) => (l.from === p.a && l.to === p.b) || (l.from === p.b && l.to === p.a)).map((l) => l.ms).filter((v): v is number => v != null) ?? [];
    const okLabel = metrics.length ? `${Math.max(...metrics).toFixed(0)} ms` : "正常";
    const color = p.tone === "bad" ? stop : p.tone === "warn" ? signal : go;
    edges.push({
      id: `reach:${p.a}|${p.b}`, source: `srv:${p.a}`, sourceHandle: "bs", target: `srv:${p.b}`, targetHandle: "bt",
      type: "smoothstep", pathOptions: { offset: 24 + i * 16 },
      data: { reachOk: p.tone === "ok", okLabel }, label: p.tone === "ok" ? undefined : worst.text,
      style: { stroke: color, strokeDasharray: p.tone === "bad" ? "6 4" : undefined }, labelStyle: { ...labelStyle, fill: color },
    } as Edge<LinkData>);
  });

  return { nodes, edges };
}

/** 选中节点的上下游：碰到它的线，以及这些线所属域名的整条链路。 */
function related(nodes: Node[], edges: Edge<LinkData>[], sel: string): { nodes: Set<string>; edges: Set<string> } {
  const start = new Set([sel, ...nodes.filter((n) => n.parentId === sel).map((n) => n.id)]);
  const touched = edges.filter((e) => start.has(e.source) || start.has(e.target));
  const routes = new Set(touched.map((e) => e.data?.route).filter(Boolean));
  if (sel.startsWith("rt:")) routes.add(sel);
  const hit = edges.filter((e) => touched.includes(e) || (e.data?.route && routes.has(e.data.route)));
  const ids = new Set(start);
  for (const e of hit) {
    ids.add(e.source);
    ids.add(e.target);
  }
  // 高亮的节点所在的机器也保持清楚。
  for (const n of nodes) if (ids.has(n.id) && n.parentId) ids.add(n.parentId);
  return { nodes: ids, edges: new Set(hit.map((e) => e.id)) };
}

export function Topology() {
  const { status } = useStatus();
  const { data: net } = usePoll<NetworkView>("/api/network", 30000);
  const { theme } = useTheme();
  const [sel, setSel] = useState<string | null>(null);
  const [layout, setLayout] = useState<Record<string, XY>>(loadLayout);
  const graph = useMemo(() => {
    if (!status) return null;
    const g = build(status, net);
    return { ...g, nodes: g.nodes.map((n) => (layout[n.id] ? { ...n, position: layout[n.id] } : n)) };
  }, [status, net, layout]);
  const onNodesChange = (changes: NodeChange[]) => {
    const moved = changes.flatMap((c) => (c.type === "position" && c.position ? [[c.id, c.position] as const] : []));
    if (!moved.length) return;
    setLayout((cur) => ({ ...cur, ...Object.fromEntries(moved) }));
  };
  const resetLayout = () => {
    setLayout({});
    saveLayout({});
  };
  const shown = useMemo(() => {
    if (!graph || !sel || !graph.nodes.some((n) => n.id === sel)) return graph;
    const r = related(graph.nodes, graph.edges, sel);
    return {
      nodes: graph.nodes.map((n) => ({ ...n, selected: n.id === sel, style: { ...n.style, opacity: r.nodes.has(n.id) ? 1 : 0.3 } })),
      edges: graph.edges.map((e) =>
        r.edges.has(e.id)
          ? { ...e, label: e.data?.reachOk && sel.startsWith("srv:") ? e.data.okLabel : e.label, animated: !e.data?.reachOk, style: { ...e.style, strokeWidth: 2, opacity: 1 } }
          : { ...e, animated: false, style: { ...e.style, opacity: 0.12 }, label: e.id.startsWith("reach:") && !e.data?.reachOk ? e.label : undefined },
      ),
    };
  }, [graph, sel]);

  return (
    <>
      <div className="mb-3 flex flex-wrap gap-5 text-xs text-muted-foreground">
        <Legend color={go}>加密或本机</Legend><Legend color={signal} dashed>没加密的内网</Legend><Legend color={stop} dashed>不通或离线</Legend>
      </div>
      <Panel className="relative h-[calc(100svh-13rem)] min-h-[480px]">
        {Object.keys(layout).length > 0 && <Tip text="重置布局"><Button aria-label="重置布局" variant="outline" size="icon-sm" className="absolute top-3 right-3 z-10" onClick={resetLayout}><LayoutGridIcon /></Button></Tip>}
        {shown && (
          <ReactFlow
            nodes={shown.nodes}
            edges={shown.edges}
            nodeTypes={nodeTypes}
            fitView
            nodesDraggable
            onNodesChange={onNodesChange}
            onNodeDragStop={() => setLayout((cur) => (saveLayout(cur), cur))}
            nodesConnectable={false}
            fitViewOptions={{ padding: 0.2 }}
            colorMode={theme}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_, n) => setSel((cur) => (cur === n.id ? null : n.id))}
            onPaneClick={() => setSel(null)}
          >
            <Background gap={20} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
        {status && sel && sel !== "core" && <NodePanel status={status} sel={sel} onClose={() => setSel(null)} />}
      </Panel>
    </>
  );
}

/** 选中节点的信息。 */
function NodePanel({ status, sel, onClose }: { status: Status; sel: string; onClose: () => void }) {
  const nav = useNavigate();
  const [kind, name] = [sel.slice(0, sel.indexOf(":")), sel.slice(sel.indexOf(":") + 1)];
  let rows: [string, string][] = [];
  let to = "";
  let url: string | undefined;
  if (kind === "srv") {
    const s = status.servers.find((x) => x.name === name);
    if (!s) return null;
    rows = [["状态", serverText(s)], ["内网地址", s.private_addr?.ip ?? "-"], ["公网 IP", s.public_ip ?? "-"], ["磁盘", diskText(s)?.text ?? "-"]];
    to = `/servers/${encodeURIComponent(name)}`;
  } else if (kind === "svc") {
    const s = status.services.find((x) => x.name === name);
    if (!s) return null;
    rows = [["所在", s.spec.server], ["状态", serviceTone(s).text]];
    to = `/services/${encodeURIComponent(name)}`;
  } else if (kind === "gw") {
    const g = status.gateways.find((x) => x.name === name);
    if (!g) return null;
    rows = [["所在", g.spec.server], ["状态", liveTone(g.live).text], ["域名数", String(g.routes.length)]];
    to = `/domains?tab=entries&entry=${encodeURIComponent(name)}`;
  } else if (kind === "rt") {
    const r = status.routes.find((x) => x.spec.hostname === name);
    if (!r) return null;
    rows = [["指向", r.spec.service ?? r.spec.redirect ?? r.spec.upstream ?? "-"], ["入口", r.gateway ?? "-"], ["走法", hopOf(r, status).text]];
    to = `/domains?open=${encodeURIComponent(name)}`;
    url = r.url;
  } else return null;
  return <div className="absolute top-3 right-3 z-10 w-64 rounded-lg border bg-card p-3 text-sm shadow-md">
    <div className="mb-2 flex items-center justify-between"><span className={cn("font-medium", kind === "rt" && "font-mono text-xs")}>{name}</span><Tip text="关闭"><Button variant="ghost" size="icon-xs" onClick={onClose} aria-label="关闭"><XIcon /></Button></Tip></div>
    <Facts items={rows.map(([k, v]) => [k, <span className="truncate font-mono text-xs">{v}</span>])} />
    <div className="mt-3 flex flex-wrap gap-2"><Button size="sm" variant="outline" onClick={() => nav(to)}>打开</Button>{url && <Button size="sm" variant="outline" asChild><a href={url} target="_blank" rel="noreferrer"><ExternalLinkIcon />访问</a></Button>}</div>
  </div>;
}

function Legend({ color, dashed, children }: { color: string; dashed?: boolean; children: React.ReactNode }) {
  return (
    <span className="flex items-center gap-1.5">
      <i className="inline-block w-5 border-t-2" style={{ borderColor: color, borderStyle: dashed ? "dashed" : "solid" }} />
      {children}
    </span>
  );
}
