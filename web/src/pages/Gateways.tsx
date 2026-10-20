import { useState } from "react";
import { usePoll } from "../api";
import { useStatus } from "../App";
import { toName } from "../components/fields";
import { LogStream } from "../components/LogStream";
import { PlanFlow } from "../components/PlanFlow";
import { Badge, Drawer, PageHead, liveTone } from "../components/ui";
import type { Change, GatewayTls, GatewayView } from "../types";

const TLS_TEXT: Record<GatewayTls, string> = {
  auto: "自动签证书",
  internal: "自签证书",
  off: "只走 HTTP",
};

export function Gateways() {
  const { status, refresh } = useStatus();
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [flow, setFlow] = useState<{ title: string; changes: Change[] } | null>(null);
  const gateways = status?.gateways ?? [];
  const selected = gateways.find((g) => g.name === open);

  return (
    <>
      <PageHead title="网关" sub="公网流量从网关进来，再转发到各台服务器上的服务。" />
      <div className="yard">
        {gateways.map((g, i) => {
          const { tone, text } = liveTone(g.live);
          const tls = g.spec.tls ?? "auto";
          return (
            <button className="crate" key={g.name} style={{ ["--i" as string]: i }} onClick={() => setOpen(g.name)}>
              <div className="head">
                <span className="mark">⇄</span>
                <div>
                  <div className="name">{g.name}</div>
                  <div className="meta">
                    {g.spec.kind} · {TLS_TEXT[tls]} · {tls === "off" ? `HTTP ${g.spec.http_port ?? 80}` : `HTTPS ${g.spec.https_port ?? 443}`}
                  </div>
                </div>
              </div>
              <div className="foot">
                <span className="row" style={{ gap: 6 }}>
                  <Badge tone={tone}>{text}</Badge>
                  <span className="tag">{g.spec.server}</span>
                  {g.spec.default && <span className="badge">默认</span>}
                </span>
                <span>{g.routes.length} 个域名</span>
              </div>
            </button>
          );
        })}
        <button className="crate add" onClick={() => setCreating(true)}>
          <span className="plus">+</span>
          在某台服务器上新建网关
        </button>
      </div>

      {selected && (
        <GatewayDrawer
          g={selected}
          onClose={() => setOpen(null)}
          onRemove={() => {
            setOpen(null);
            setFlow({ title: `删除网关 ${selected.name}`, changes: [{ op: "remove_gateway", name: selected.name }] });
          }}
        />
      )}
      {creating && (
        <NewGateway
          onClose={() => setCreating(false)}
          onSubmit={(c) => {
            setCreating(false);
            setFlow({ title: "新建网关", changes: [c] });
          }}
        />
      )}
      {flow && (
        <Drawer
          title="Plan"
          zh={flow.title}
          onClose={() => {
            setFlow(null);
            refresh();
          }}
        >
          <PlanFlow changes={flow.changes} onFinished={refresh} />
        </Drawer>
      )}
    </>
  );
}

function GatewayDrawer({ g, onClose, onRemove }: { g: GatewayView; onClose: () => void; onRemove: () => void }) {
  const [tab, setTab] = useState<"routes" | "config" | "logs">("routes");
  const { data: config } = usePoll<{ caddyfile: string; compose: string }>(`/api/gateways/${encodeURIComponent(g.name)}/config`, 30000);
  return (
    <Drawer
      title={g.name}
      zh="网关"
      onClose={onClose}
      footer={
        <button className="btn danger" disabled={g.routes.length > 0} title={g.routes.length ? "先移除这个网关上的域名" : ""} onClick={onRemove}>
          删除网关
        </button>
      }
    >
      <dl className="kv">
        <dt>服务器</dt>
        <dd>
          <span className="tag">{g.spec.server}</span>
        </dd>
        <dt>证书</dt>
        <dd>{TLS_TEXT[g.spec.tls ?? "auto"]}</dd>
        <dt>端口</dt>
        <dd className="mono">
          HTTP {g.spec.http_port ?? 80} · HTTPS {g.spec.https_port ?? 443}
        </dd>
      </dl>
      <div className="tabs">
        <button className={tab === "routes" ? "on" : ""} onClick={() => setTab("routes")}>
          域名
        </button>
        <button className={tab === "config" ? "on" : ""} onClick={() => setTab("config")}>
          生成的配置
        </button>
        <button className={tab === "logs" ? "on" : ""} onClick={() => setTab("logs")}>
          日志
        </button>
      </div>
      {tab === "routes" &&
        (g.routes.length ? (
          g.routes.map((h) => (
            <div className="mono" key={h} style={{ padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
              {h}
            </div>
          ))
        ) : (
          <div className="empty">还没有域名经过这个网关。</div>
        ))}
      {tab === "config" && <pre className="config">{config?.caddyfile ?? "载入中…"}</pre>}
      {tab === "logs" && <LogStream path={`/api/gateways/${encodeURIComponent(g.name)}/logs/stream`} />}
    </Drawer>
  );
}

function NewGateway({ onClose, onSubmit }: { onClose: () => void; onSubmit: (c: Change) => void }) {
  const { status } = useStatus();
  const servers = status?.servers ?? [];
  const hasDefault = status?.gateways.some((g) => g.spec.default) ?? false;
  const [server, setServer] = useState(servers.find((s) => s.online)?.name ?? "");
  const [name, setName] = useState("");
  const [tls, setTls] = useState<GatewayTls>("auto");
  const [httpPort, setHttpPort] = useState(80);
  const [httpsPort, setHttpsPort] = useState(443);
  const [isDefault, setDefault] = useState(!hasDefault);
  const gwName = name || (server ? `${server}-edge` : "");

  return (
    <Drawer
      title="New Gateway"
      zh="新建网关"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            取消
          </button>
          <button
            className="btn primary"
            disabled={!server || !gwName}
            onClick={() =>
              onSubmit({
                op: "upsert_gateway",
                name: gwName,
                spec: {
                  kind: "caddy",
                  server,
                  default: isDefault || undefined,
                  http_port: httpPort === 80 ? undefined : httpPort,
                  https_port: httpsPort === 443 ? undefined : httpsPort,
                  tls: tls === "auto" ? undefined : tls,
                },
              })
            }
          >
            生成计划 →
          </button>
        </>
      }
    >
      <div className="row">
        <div className="field">
          <label>服务器</label>
          <select value={server} onChange={(e) => setServer(e.target.value)}>
            {servers.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
                {s.public_ip ? `（公网 ${s.public_ip}）` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>名称</label>
          <input type="text" value={gwName} onChange={(e) => setName(toName(e.target.value))} />
        </div>
      </div>
      <div className="field">
        <label>证书</label>
        <div className="seg">
          {(["auto", "internal", "off"] as GatewayTls[]).map((t) => (
            <button key={t} className={tls === t ? "on" : ""} onClick={() => setTls(t)}>
              {TLS_TEXT[t]}
            </button>
          ))}
        </div>
        <span className="help">
          {tls === "auto" && "域名要能从公网解析到这台服务器，并且 80 端口可达。"}
          {tls === "internal" && "Caddy 自签证书，浏览器会提示不受信任。"}
          {tls === "off" && "不加密，只适合内网。"}
        </span>
      </div>
      <div className="row">
        <div className="field">
          <label>HTTP 端口</label>
          <input type="number" value={httpPort} onChange={(e) => setHttpPort(Number(e.target.value))} />
        </div>
        <div className="field">
          <label>HTTPS 端口</label>
          <input type="number" value={httpsPort} onChange={(e) => setHttpsPort(Number(e.target.value))} />
        </div>
      </div>
      <label className="check">
        <input type="checkbox" checked={isDefault} onChange={(e) => setDefault(e.target.checked)} />
        <span>设为默认网关（加域名时不选网关就用它）</span>
      </label>
    </Drawer>
  );
}
