import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Dot, PageHeader, liveTone, serverTone, type Tone } from "@/components/common";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import type { Status } from "@/types";

/** 控制面到 agent 超过这个延迟标红。 */
const SLOW_MS = 150;
const COL = 200;
const GROUP_H = 250;

type BoxData = { kind: string; name: string; tone?: Tone; cls?: string; to?: string };
type GroupData = { name: string; tone: Tone; sub: string };

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
      <div className="absolute top-2.5 left-3.5 flex items-center gap-2 text-[13px] font-semibold">
        <Dot tone={data.tone} />
        {data.name}
        <span className="font-mono text-[11px] font-normal text-muted-foreground">{data.sub}</span>
      </div>
    </div>
  );
}

const nodeTypes = { box: BoxNode, group: GroupNode };

const go = "var(--success)";
const signal = "var(--warning)";
const stop = "var(--destructive)";
const fog = "var(--muted-foreground)";
const labelStyle = { fill: "var(--muted-foreground)", fontFamily: "Geist Mono, monospace", fontSize: 11 };

function build(status: Status): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const serverOf = new Map(status.services.map((s) => [s.name, s.spec.server]));
  const addrOf = new Map(status.servers.map((s) => [s.name, s.private_addr]));

  let x = 0;
  status.servers.forEach((srv) => {
    const gws = status.gateways.filter((g) => g.spec.server === srv.name);
    const svcs = status.services.filter((s) => s.spec.server === srv.name);
    const width = Math.max(gws.length, svcs.length, 1) * COL + 40;
    const tone: Tone = serverTone(srv);
    const addr = srv.private_addr ? `${srv.private_addr.ip} · ${srv.private_addr.network}` : "无内网地址";
    nodes.push({
      id: `srv:${srv.name}`,
      type: "group",
      position: { x, y: 0 },
      data: { name: srv.name, tone, sub: addr },
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
      data: { kind: "域名", name: r.spec.hostname, cls: "route", to: `/services/${r.spec.service}` },
    });
    if (!r.gateway) return;
    edges.push({
      id: `${id}-gw`,
      source: id,
      sourceHandle: "r",
      target: `gw:${r.gateway}`,
      targetHandle: "l",
      animated: true,
      style: { stroke: go },
    });
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
      style: { stroke: plain ? signal : go, strokeDasharray: plain ? "6 4" : undefined },
      labelStyle: { ...labelStyle, fill: plain ? signal : labelStyle.fill },
    });
  });

  return { nodes, edges };
}

export function Topology() {
  const { status } = useStatus();
  const { theme } = useTheme();
  const nav = useNavigate();
  const graph = useMemo(() => (status ? build(status) : null), [status]);

  return (
    <>
      <PageHeader title="拓扑" />
      <div className="mb-3 flex flex-wrap gap-5 text-xs text-muted-foreground">
        <Legend color={go}>加密 / 本机</Legend>
        <Legend color={signal} dashed>
          内网直连（明文）
        </Legend>
        <Legend color={stop}>延迟超过 {SLOW_MS}ms 或断开</Legend>
      </div>
      <div className="h-[calc(100svh-15rem)] min-h-[480px] overflow-hidden rounded-xl border bg-card shadow-xs">
        {graph && (
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            nodeTypes={nodeTypes}
            fitView
            nodesDraggable={false}
            nodesConnectable={false}
            fitViewOptions={{ padding: 0.2 }}
            colorMode={theme}
            proOptions={{ hideAttribution: true }}
            onNodeClick={(_, n) => {
              const to = (n.data as BoxData).to;
              if (to) nav(to);
            }}
          >
            <Background gap={20} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
      </div>
    </>
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
