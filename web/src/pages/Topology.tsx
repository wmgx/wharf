import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowUpCircleIcon, ExternalLinkIcon, Trash2Icon, XIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { diskText, Dot, MODES, PageHeader, liveTone, serverText, serverTone, type Tone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import type { NetworkView, Status } from "@/types";

/** 控制面到 agent 超过这个延迟标红。 */
const SLOW_MS = 150;
const COL = 200;
const GROUP_H = 250;

type BoxData = { kind: string; name: string; tone?: Tone; cls?: string; to?: string };
type GroupData = { name: string; tone: Tone; sub: string; disk?: { text: string; low: boolean } | null };
/** 域名链路上的线都记着属于哪个域名，点一个节点时顺着域名找上下游。 */
type LinkData = { route?: string };

function BoxNode({ data }: NodeProps<Node<BoxData>>) {
  return (
    <div
      className={cn(
        "min-w-36 cursor-pointer rounded-lg border bg-card px-3 py-2 shadow-xs transition-colors hover:border-foreground/20",
        data.cls === "core" && "border-primary ring-3 ring-primary/10",
      )}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="text-[10px] text-muted-foreground">{data.kind}</div>
      <div className={cn("flex items-center gap-1.5 text-[13px] font-medium", data.cls === "route" && "font-mono text-xs font-normal")}>
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
      <div className="absolute top-2.5 left-3.5 flex items-center gap-2 text-[13px] font-semibold">
        <Dot tone={data.tone} />
        {data.name}
        <span className="font-mono text-[11px] font-normal text-muted-foreground">{data.sub}</span>
      </div>
      {data.disk && (
        <div className={cn("absolute right-3.5 bottom-2.5 font-mono text-[11px]", data.disk.low ? "text-warning" : "text-muted-foreground")}>
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

function build(status: Status, net: NetworkView | null): { nodes: Node[]; edges: Edge<LinkData>[] } {
  const nodes: Node[] = [];
  const edges: Edge<LinkData>[] = [];
  const modeOf = new Map(net?.servers.map((s) => [s.name, s.mode]));
  const serverOf = new Map(status.services.map((s) => [s.name, s.spec.server]));
  const addrOf = new Map(status.servers.map((s) => [s.name, s.private_addr]));

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
        extent: "parent",
        position: { x: 20 + i * COL, y: 44 },
        data: { kind: "网关", name: g.name, tone: liveTone(g.live).tone, to: "/gateways" },
      });
    });
    svcs.forEach((s, i) => {
      nodes.push({
        id: `svc:${s.name}`,
        type: "box",
        parentId: `srv:${srv.name}`,
        extent: "parent",
        position: { x: 20 + i * COL, y: 150 },
        data: { kind: "服务", name: s.name, tone: liveTone(s.live).tone, to: `/services/${s.name}` },
      });
    });
    const slow = srv.rtt_ms != null && srv.rtt_ms > SLOW_MS;
    edges.push({
      id: `core-${srv.name}`,
      source: "core",
      target: `srv:${srv.name}`,
      label: srv.online ? (srv.rtt_ms != null ? `${srv.rtt_ms} ms` : "在线") : "断开",
      style: { stroke: !srv.online ? stop : slow ? stop : fog, strokeDasharray: srv.online ? undefined : "6 4" },
      labelStyle: { ...labelStyle, fill: slow || !srv.online ? stop : labelStyle.fill },
    });
    x += width + 60;
  });

  nodes.unshift({
    id: "core",
    type: "box",
    position: { x: Math.max(0, x - 60) / 2 - 80, y: -150 },
    data: { kind: "控制面", name: "wharf-core", cls: "core" },
  });

  status.routes.forEach((r, i) => {
    const id = `rt:${r.spec.hostname}`;
    nodes.push({
      id,
      type: "box",
      position: { x: -300, y: i * 74 },
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
    const gwServer = status.gateways.find((g) => g.name === r.gateway)?.spec.server;
    const svcServer = serverOf.get(r.spec.service);
    const same = gwServer === svcServer;
    const net = svcServer ? addrOf.get(svcServer)?.network : undefined;
    const plain = !same && net === "lan";
    edges.push({
      id: `${id}-svc`,
      source: `gw:${r.gateway}`,
      target: `svc:${r.spec.service}`,
      label: same ? undefined : plain ? "明文" : net,
      type: "smoothstep",
      data: { route: id },
      style: { stroke: plain ? signal : go, strokeDasharray: plain ? "6 4" : undefined },
      labelStyle: { ...labelStyle, fill: plain ? signal : labelStyle.fill },
    });
  });

  // 机器之间能不能连上对方的内网地址，两个方向合成一条线。
  const pairs = new Map<string, { a: string; b: string; ok: boolean }>();
  for (const r of net?.reach ?? []) {
    const [a, b] = [r.from, r.to].sort();
    const p = pairs.get(`${a}|${b}`) ?? { a, b, ok: true };
    pairs.set(`${a}|${b}`, { ...p, ok: p.ok && r.ok });
  }
  for (const p of pairs.values()) {
    if (!status.servers.some((s) => s.name === p.a) || !status.servers.some((s) => s.name === p.b)) continue;
    edges.push({
      id: `reach:${p.a}|${p.b}`,
      source: `srv:${p.a}`,
      sourceHandle: "bs",
      target: `srv:${p.b}`,
      targetHandle: "bt",
      label: p.ok ? undefined : "不通",
      style: { stroke: p.ok ? go : stop, strokeDasharray: p.ok ? undefined : "6 4", opacity: p.ok ? 0.5 : 1 },
      labelStyle: { ...labelStyle, fill: stop },
    });
  }

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
  const nav = useNavigate();
  const [sel, setSel] = useState<string | null>(null);
  const graph = useMemo(() => (status ? build(status, net) : null), [status, net]);
  const shown = useMemo(() => {
    if (!graph || !sel || !graph.nodes.some((n) => n.id === sel)) return graph;
    const r = related(graph.nodes, graph.edges, sel);
    return {
      nodes: graph.nodes.map((n) => ({ ...n, selected: n.id === sel, style: { ...n.style, opacity: r.nodes.has(n.id) ? 1 : 0.3 } })),
      edges: graph.edges.map((e) =>
        r.edges.has(e.id)
          ? { ...e, animated: true, style: { ...e.style, strokeWidth: 2, opacity: 1 } }
          : { ...e, animated: false, style: { ...e.style, opacity: 0.12 }, label: undefined },
      ),
    };
  }, [graph, sel]);

  return (
    <>
      <PageHeader title="拓扑" />
      <div className="mb-3 flex flex-wrap gap-5 text-xs text-muted-foreground">
        <Legend color={go}>加密 / 本机 / 互通</Legend>
        <Legend color={signal} dashed>
          内网直连（明文）
        </Legend>
        <Legend color={stop}>延迟超过 {SLOW_MS}ms、断开或不通</Legend>
      </div>
      <div className="relative h-[calc(100svh-15rem)] min-h-[480px] overflow-hidden rounded-xl border bg-card shadow-xs">
        {shown && (
          <ReactFlow
            nodes={shown.nodes}
            edges={shown.edges}
            nodeTypes={nodeTypes}
            fitView
            nodesDraggable={false}
            nodesConnectable={false}
            fitViewOptions={{ padding: 0.2 }}
            colorMode={theme}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_, n) => setSel((cur) => (cur === n.id ? null : n.id))}
            onNodeDoubleClick={(_, n) => {
              const to = (n.data as BoxData).to;
              if (to) nav(to);
            }}
            onPaneClick={() => setSel(null)}
          >
            <Background gap={20} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
        {status && sel && <Panel status={status} sel={sel} onClose={() => setSel(null)} />}
      </div>
    </>
  );
}

/** 选中节点的信息和操作。 */
function Panel({ status, sel, onClose }: { status: Status; sel: string; onClose: () => void }) {
  const actions = useActions();
  const nav = useNavigate();
  const [kind, name] = [sel.slice(0, sel.indexOf(":")), sel.slice(sel.indexOf(":") + 1)];
  let title = name;
  let rows: [string, string][] = [];
  let buttons: React.ReactNode = null;
  if (kind === "srv") {
    const s = status.servers.find((x) => x.name === name);
    if (!s) return null;
    rows = [
      ["状态", serverText(s)],
      ["内网", s.private_addr?.ip ?? "-"],
      ["公网", s.public_ip ?? "-"],
      ["磁盘剩", diskText(s)?.text ?? "-"],
    ];
    buttons = (
      <>
        <Button size="sm" variant="outline" disabled={!s.online} onClick={() => actions.prune(s.name)}>
          <Trash2Icon />
          清理镜像
        </Button>
        {s.agent_outdated && (
          <Button size="sm" variant="outline" onClick={() => actions.upgradeAgent(s.name)}>
            <ArrowUpCircleIcon />
            升级 agent
          </Button>
        )}
      </>
    );
  } else if (kind === "svc") {
    const s = status.services.find((x) => x.name === name);
    if (!s) return null;
    rows = [
      ["服务器", s.spec.server],
      ["状态", liveTone(s.live).text],
    ];
    buttons = (
      <Button size="sm" variant="outline" onClick={() => nav(`/services/${s.name}`)}>
        打开
      </Button>
    );
  } else if (kind === "gw") {
    const g = status.gateways.find((x) => x.name === name);
    if (!g) return null;
    rows = [
      ["服务器", g.spec.server],
      ["状态", liveTone(g.live).text],
      ["路由", String(status.routes.filter((r) => r.gateway === g.name).length)],
    ];
    buttons = (
      <Button size="sm" variant="outline" onClick={() => nav("/gateways")}>
        打开
      </Button>
    );
  } else if (kind === "rt") {
    const r = status.routes.find((x) => x.spec.hostname === name);
    if (!r) return null;
    rows = [
      ["服务", r.spec.service ?? "-"],
      ["网关", r.gateway ?? "-"],
    ];
    buttons = (
      <Button size="sm" variant="outline" asChild>
        <a href={r.url} target="_blank" rel="noreferrer">
          <ExternalLinkIcon />
          访问
        </a>
      </Button>
    );
  } else {
    title = "wharf-core";
  }
  return (
    <div className="absolute top-3 right-3 z-10 w-64 rounded-lg border bg-card p-3 text-sm shadow-md">
      <div className="mb-2 flex items-center justify-between">
        <span className={cn("font-medium", kind === "rt" && "font-mono text-xs")}>{title}</span>
        <button type="button" className="text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="关闭">
          <XIcon className="size-4" />
        </button>
      </div>
      {rows.length > 0 && (
        <dl className="grid grid-cols-[4rem_1fr] gap-y-1 text-xs">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="truncate font-mono">{v}</dd>
            </div>
          ))}
        </dl>
      )}
      {buttons && <div className="mt-3 flex flex-wrap gap-2">{buttons}</div>}
    </div>
  );
}

function Legend({ color, dashed, children }: { color: string; dashed?: boolean; children: React.ReactNode }) {
  return (
    <span className="flex items-center gap-1.5">
      <i className="inline-block w-5 border-t-2" style={{ borderColor: color, borderStyle: dashed ? "dashed" : "solid" }} />
      {children}
    </span>
  );
}
