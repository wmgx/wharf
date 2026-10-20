import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useStatus } from "../App";
import { Light, PageHead, liveTone, type Tone } from "../components/ui";
import type { Status } from "../types";

/** 控制面到 agent 超过这个延迟标红。 */
const SLOW_MS = 150;
const COL = 200;
const GROUP_H = 250;

type BoxData = { kind: string; name: string; tone?: Tone; cls?: string; to?: string };
type GroupData = { name: string; tone: Tone; sub: string };

function BoxNode({ data }: NodeProps<Node<BoxData>>) {
  return (
    <div className={`topo-node ${data.cls ?? ""}`}>
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="k">{data.kind}</div>
      <div className="n">
        {data.tone && <Light tone={data.tone} />}
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
    <div className="topo-group">
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="label">
        <Light tone={data.tone} />
        {data.name}
        <span className="sub">{data.sub}</span>
      </div>
    </div>
  );
}

const nodeTypes = { box: BoxNode, group: GroupNode };

const go = "var(--ok)";
const signal = "var(--warn)";
const stop = "var(--bad)";
const fog = "var(--border-strong)";
const labelStyle = { fill: "var(--text-2)", fontFamily: "Geist Mono, monospace", fontSize: 11 };

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
    const tone: Tone = !srv.joined ? "fog" : srv.online ? "go" : "stop";
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
  const { status, theme } = useStatus();
  const nav = useNavigate();
  const graph = useMemo(() => (status ? build(status) : null), [status]);

  return (
    <>
      <PageHead title="拓扑" sub="域名经过网关到达服务；虚线表示明文或断开。点节点进入详情。" />
      <div className="legend">
        <span>
          <i />
          加密 / 本机
        </span>
        <span>
          <i className="dash" />
          内网直连（明文）
        </span>
        <span>
          <i className="slow" />
          延迟超过 {SLOW_MS}ms 或断开
        </span>
      </div>
      <div className="topo">
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
