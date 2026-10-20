import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, usePoll } from "../api";
import { useStatus } from "../App";
import { PortsEditor, formatEnv, parseEnv } from "../components/fields";
import { LogStream } from "../components/LogStream";
import { PlanFlow } from "../components/PlanFlow";
import { Drawer, ErrorNote, Light, ago, liveTone } from "../components/ui";
import type { Change, DeploymentView, PortSpec, RollbackTarget, ServiceView } from "../types";

type Tab = "logs" | "history" | "config";

export function ServiceDetail() {
  const { name = "" } = useParams();
  const nav = useNavigate();
  const { status, refresh } = useStatus();
  const { data: svc, error, refresh: reload } = usePoll<ServiceView>(`/api/services/${encodeURIComponent(name)}`, 8000);
  const [tab, setTab] = useState<Tab>("logs");
  const [flow, setFlow] = useState<{ title: string; changes: Change[]; leave?: boolean } | null>(null);
  const [editing, setEditing] = useState(false);
  const [addingRoute, setAddingRoute] = useState(false);

  const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];

  if (error && !svc) {
    return (
      <>
        <Link className="back" to="/services">
          ← 服务
        </Link>
        <ErrorNote error={error} />
      </>
    );
  }
  if (!svc) return <p>载入中…</p>;

  const { tone, text } = liveTone(svc.live);
  const source = "image" in svc.spec.source ? svc.spec.source.image : "compose 文件";

  const remove = () =>
    setFlow({
      title: `删除 ${name}`,
      leave: true,
      changes: [...routes.map((r) => ({ op: "remove_route", hostname: r.spec.hostname }) as Change), { op: "remove_service", name }],
    });

  return (
    <>
      <Link className="back" to="/services">
        ← 服务
      </Link>
      <div className="page-head">
        <div>
          <h1 style={{ display: "flex", alignItems: "center", gap: 16 }}>
            {svc.name}
            <span className="zh" style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: 15 }}>
              <Light tone={tone} />
              {text}
            </span>
          </h1>
          <p className="mono">
            {source} · 在 {svc.spec.server}
          </p>
        </div>
        <div className="row" style={{ flex: "none" }}>
          <button className="btn" onClick={() => setEditing(true)}>
            修改配置
          </button>
          <button className="btn" onClick={() => setFlow({ title: `重新部署 ${name}`, changes: [{ op: "upsert_service", name, spec: svc.spec }] })}>
            检查并修复
          </button>
          <button className="btn danger" onClick={remove}>
            删除
          </button>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel">
          <dl className="kv">
            <dt>域名</dt>
            <dd>
              {routes.map((r) => (
                <div key={r.id} className="row" style={{ justifyContent: "space-between" }}>
                  <a className="mono" href={r.url} target="_blank" rel="noreferrer">
                    {r.url} ↗
                  </a>
                  <button
                    className="btn small ghost fixed"
                    onClick={() => setFlow({ title: `移除 ${r.spec.hostname}`, changes: [{ op: "remove_route", hostname: r.spec.hostname }] })}
                  >
                    移除
                  </button>
                </div>
              ))}
              <button className="btn small" style={{ marginTop: routes.length ? 6 : 0 }} onClick={() => setAddingRoute(true)}>
                ＋ 加域名
              </button>
            </dd>
            <dt>内网地址</dt>
            <dd className="mono">
              {Object.entries(svc.addresses).map(([p, a]) => (
                <div key={p}>
                  {p} → {a}
                </div>
              ))}
              {Object.keys(svc.addresses).length === 0 && "-"}
            </dd>
            <dt>环境变量</dt>
            <dd className="mono">{Object.keys(svc.spec.env ?? {}).join(", ") || "-"}</dd>
          </dl>
        </div>
        <div className="panel">
          <dl className="kv">
            {svc.live?.containers.map((c) => (
              <Container key={c.name} name={c.service} state={c.state} status={c.status} />
            ))}
            {!svc.live?.containers.length && (
              <>
                <dt>容器</dt>
                <dd>{svc.live?.error ?? "没有容器"}</dd>
              </>
            )}
          </dl>
        </div>
      </div>

      <div className="tabs">
        {(
          [
            ["logs", "日志"],
            ["history", "部署历史"],
            ["config", "配置"],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "logs" && <LogStream path={`/api/services/${encodeURIComponent(name)}/logs/stream`} />}
      {tab === "history" && <History name={name} onRollback={(t) => setFlow({ title: `回滚到 #${t.deployment_id}`, changes: [{ op: "upsert_service", name, spec: t.spec }] })} />}
      {tab === "config" && <pre className="config">{JSON.stringify(svc.spec, null, 2)}</pre>}

      {editing && (
        <EditService
          svc={svc}
          onClose={() => setEditing(false)}
          onSubmit={(spec) => {
            setEditing(false);
            setFlow({ title: `修改 ${name}`, changes: [{ op: "upsert_service", name, spec }] });
          }}
        />
      )}
      {addingRoute && (
        <AddRoute
          service={name}
          onClose={() => setAddingRoute(false)}
          onSubmit={(c) => {
            setAddingRoute(false);
            setFlow({ title: "加域名", changes: [c] });
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
            reload();
          }}
        >
          <PlanFlow
            changes={flow.changes}
            onFinished={(ok) => {
              refresh();
              reload();
              if (ok && flow.leave) setTimeout(() => nav("/services"), 900);
            }}
          />
        </Drawer>
      )}
    </>
  );
}

function Container({ name, state, status }: { name: string; state: string; status: string }) {
  return (
    <>
      <dt>{name}</dt>
      <dd className="row" style={{ gap: 8 }}>
        <Light tone={state === "running" ? "go" : "stop"} />
        <span style={{ flex: 1 }}>{status || state}</span>
      </dd>
    </>
  );
}

function History({ name, onRollback }: { name: string; onRollback: (t: RollbackTarget) => void }) {
  const { data } = usePoll<DeploymentView[]>(`/api/services/${encodeURIComponent(name)}/deployments`, 15000);
  const [error, setError] = useState<unknown>(null);
  if (!data) return <p>载入中…</p>;
  if (data.length === 0) return <div className="empty">还没有部署记录。</div>;
  const rollback = async (id: number) => {
    setError(null);
    try {
      onRollback(await api.get<RollbackTarget>(`/api/services/${encodeURIComponent(name)}/rollback?to=${id}`));
    } catch (e) {
      setError(e);
    }
  };
  return (
    <>
      <ErrorNote error={error} />
      <table className="manifest">
        <thead>
          <tr>
            <th>#</th>
            <th>时间</th>
            <th>服务器</th>
            <th>镜像</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.map((d, i) => (
            <tr key={d.id}>
              <td className="mono">#{d.id}</td>
              <td>{ago(d.created_at)}</td>
              <td className="mono">{d.server}</td>
              <td className="mono" style={{ color: "var(--ink-2)", wordBreak: "break-all" }}>
                {d.images.map((im) => im.digest ?? im.image).join(" ")}
              </td>
              <td style={{ textAlign: "right" }}>
                {i === 0 || d.hash === data[0].hash ? (
                  <span style={{ color: "var(--ink-3)", fontSize: 12 }}>当前版本</span>
                ) : (
                  <button className="btn small" disabled={!d.spec} title={d.spec ? "" : "这条记录太早，没有保存当时的配置"} onClick={() => rollback(d.id)}>
                    回滚到这里
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function EditService({ svc, onClose, onSubmit }: { svc: ServiceView; onClose: () => void; onSubmit: (spec: ServiceView["spec"]) => void }) {
  const isImage = "image" in svc.spec.source;
  const [image, setImage] = useState(isImage ? (svc.spec.source as { image: string }).image : "");
  const [compose, setCompose] = useState(!isImage ? ((svc.spec.source as { compose: { content?: string } }).compose.content ?? "") : "");
  const [ports, setPorts] = useState<PortSpec[]>(svc.spec.ports ?? []);
  const [envText, setEnvText] = useState(formatEnv(svc.spec.env));
  const submit = () =>
    onSubmit({
      ...svc.spec,
      source: isImage ? { image: image.trim() } : { compose: { content: compose } },
      ports,
      env: isImage ? parseEnv(envText) : svc.spec.env,
    });
  return (
    <Drawer
      title="Edit"
      zh={`修改 ${svc.name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" onClick={submit}>
            生成计划 →
          </button>
        </>
      }
    >
      {isImage ? (
        <div className="field">
          <label>镜像</label>
          <input type="text" value={image} onChange={(e) => setImage(e.target.value)} />
        </div>
      ) : (
        <div className="field">
          <label>compose.yaml</label>
          <textarea value={compose} onChange={(e) => setCompose(e.target.value)} />
        </div>
      )}
      <div className="field">
        <label>端口</label>
        <PortsEditor ports={ports} onChange={setPorts} />
      </div>
      {isImage && (
        <div className="field">
          <label>环境变量</label>
          <textarea style={{ minHeight: 120 }} value={envText} onChange={(e) => setEnvText(e.target.value)} />
        </div>
      )}
    </Drawer>
  );
}

function AddRoute({ service, onClose, onSubmit }: { service: string; onClose: () => void; onSubmit: (c: Change) => void }) {
  const { status } = useStatus();
  const [hostname, setHostname] = useState("");
  const gateways = status?.gateways ?? [];
  const [gateway, setGateway] = useState(gateways.find((g) => g.spec.default)?.name ?? gateways[0]?.name ?? "");
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  return (
    <Drawer
      title="Domain"
      zh="加域名"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            取消
          </button>
          <button
            className="btn primary"
            disabled={!hostname.trim() || !gateway}
            onClick={() => onSubmit({ op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service, gateway } })}
          >
            生成计划 →
          </button>
        </>
      }
    >
      <div className="field">
        <label>域名</label>
        <input type="text" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="app.example.com" />
        {!hostname && (
          <div className="chips">
            {suffixes.map((s) => (
              <button className="chip" key={s} onClick={() => setHostname(`${service}.${s}`)}>
                {service}.{s}
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="field">
        <label>网关</label>
        <select value={gateway} onChange={(e) => setGateway(e.target.value)}>
          {gateways.map((g) => (
            <option key={g.name} value={g.name}>
              {g.name}（{g.spec.server}）
            </option>
          ))}
        </select>
      </div>
    </Drawer>
  );
}
