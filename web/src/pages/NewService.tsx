import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePoll } from "../api";
import { useStatus } from "../App";
import { PortsEditor, nameFromImage, parseEnv, toName } from "../components/fields";
import { PlanFlow } from "../components/PlanFlow";
import { Drawer } from "../components/ui";
import type { AccountView, Change, PortSpec, ServiceSpec } from "../types";

/**
 * 新建服务：选来源、选服务器、（可选）加域名，然后看计划、确认、看日志。
 * 服务和路由放在同一个计划里，一步完成。
 */
export function NewService({ onClose }: { onClose: () => void }) {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 60000);

  const [kind, setKind] = useState<"image" | "compose">("image");
  const [image, setImage] = useState("");
  const [compose, setCompose] = useState("");
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const servers = useMemo(() => [...(status?.servers ?? [])].sort((a, b) => Number(b.online) - Number(a.online)), [status]);
  const [server, setServer] = useState("");
  const [ports, setPorts] = useState<PortSpec[]>([{ name: "http", port: 80 }]);
  const [envText, setEnvText] = useState("");
  const [hostname, setHostname] = useState("");
  const gateways = status?.gateways ?? [];
  const [gateway, setGateway] = useState("");
  const [changes, setChanges] = useState<Change[] | null>(null);

  const svcName = nameTouched ? name : kind === "image" ? nameFromImage(image) : name;
  const chosenServer = server || servers.find((s) => s.online)?.name || servers[0]?.name || "";
  const chosenGateway = gateway || gateways.find((g) => g.spec.default)?.name || gateways[0]?.name || "";

  // 域名建议：已有路由的后缀 + 厂商账号里的 zone。
  const suggestions = useMemo(() => {
    const suffixes = new Set<string>();
    status?.routes.forEach((r) => {
      const i = r.spec.hostname.indexOf(".");
      if (i > 0) suffixes.add(r.spec.hostname.slice(i + 1));
    });
    accounts?.forEach((a) => a.zones.forEach((z) => suffixes.add(z)));
    return svcName ? [...suffixes].map((s) => `${svcName}.${s}`) : [];
  }, [status, accounts, svcName]);

  const source = kind === "image" ? image.trim() : compose.trim();
  const portsOk = ports.every((p) => p.name && p.port > 0 && p.port < 65536);
  const ready = !!svcName && !!source && !!chosenServer && portsOk && (!hostname || !!chosenGateway || gateways.length === 0);

  const submit = () => {
    const spec: ServiceSpec = {
      server: chosenServer,
      source: kind === "image" ? { image: source } : { compose: { content: source } },
      ports: ports.length ? ports : undefined,
      env: kind === "image" && envText.trim() ? parseEnv(envText) : undefined,
    };
    const list: Change[] = [{ op: "upsert_service", name: svcName, spec }];
    if (hostname.trim()) {
      list.push({
        op: "upsert_route",
        spec: { hostname: hostname.trim().toLowerCase(), service: svcName, gateway: chosenGateway || undefined },
      });
    }
    setChanges(list);
  };

  if (changes) {
    return (
      <Drawer title="Deploy" zh={`部署 ${svcName}`} onClose={onClose}>
        <PlanFlow
          changes={changes}
          onFinished={(ok) => {
            refresh();
            if (ok) setTimeout(() => nav(`/services/${svcName}`), 900);
          }}
        />
        <div style={{ marginTop: 16 }}>
          <button className="btn ghost small" onClick={() => setChanges(null)}>
            ← 返回修改
          </button>
        </div>
      </Drawer>
    );
  }

  return (
    <Drawer
      title="New Service"
      zh="新建服务"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" disabled={!ready} onClick={submit}>
            生成计划 →
          </button>
        </>
      }
    >
      <div className="field">
        <label>来源</label>
        <div className="seg">
          <button className={kind === "image" ? "on" : ""} onClick={() => setKind("image")}>
            镜像
          </button>
          <button className={kind === "compose" ? "on" : ""} onClick={() => setKind("compose")}>
            Compose 文件
          </button>
        </div>
      </div>

      {kind === "image" ? (
        <div className="field">
          <label htmlFor="image">镜像</label>
          <input id="image" type="text" autoFocus placeholder="例如 nginxdemos/hello 或 ghcr.io/owner/app:1.0" value={image} onChange={(e) => setImage(e.target.value)} />
        </div>
      ) : (
        <div className="field">
          <label htmlFor="compose">compose.yaml</label>
          <textarea id="compose" placeholder={"services:\n  app:\n    image: nginx\n    ports:\n      - 127.0.0.1:8080:80"} value={compose} onChange={(e) => setCompose(e.target.value)} />
          <span className="help">compose 来源原样使用，端口按文件里发布的宿主机端口填写。</span>
        </div>
      )}

      <div className="row">
        <div className="field">
          <label htmlFor="name">名称</label>
          <input
            id="name"
            type="text"
            value={svcName}
            placeholder="自动取镜像名"
            onChange={(e) => {
              setNameTouched(true);
              setName(toName(e.target.value));
            }}
          />
        </div>
        <div className="field">
          <label htmlFor="server">服务器</label>
          <select id="server" value={chosenServer} onChange={(e) => setServer(e.target.value)}>
            {servers.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
                {s.online ? "" : "（离线）"}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="field">
        <label>端口</label>
        <PortsEditor ports={ports} onChange={setPorts} />
        <span className="help">{kind === "image" ? "容器里监听的端口。宿主机端口自动分配，只绑定 127.0.0.1 和内网地址。" : "compose 里已经发布的宿主机端口。"}</span>
      </div>

      {kind === "image" && (
        <div className="field">
          <label htmlFor="env">环境变量</label>
          <textarea id="env" style={{ minHeight: 90 }} placeholder={"KEY=value\nTOKEN=[[MY_SECRET]]"} value={envText} onChange={(e) => setEnvText(e.target.value)} />
          <span className="help">
            一行一个。密钥用 <span className="mono">[[名称]]</span> 引用，值不会出现在配置里。
          </span>
        </div>
      )}

      <h2 className="section">Domain · 域名（可选）</h2>
      <div className="field">
        <input type="text" placeholder="例如 app.example.com，留空就只在内网访问" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        {suggestions.length > 0 && !hostname && (
          <div className="chips">
            {suggestions.map((s) => (
              <button className="chip" key={s} onClick={() => setHostname(s)}>
                {s}
              </button>
            ))}
          </div>
        )}
      </div>
      {hostname && gateways.length > 1 && (
        <div className="field">
          <label htmlFor="gw">经过哪个网关</label>
          <select id="gw" value={chosenGateway} onChange={(e) => setGateway(e.target.value)}>
            {gateways.map((g) => (
              <option key={g.name} value={g.name}>
                {g.name}（{g.spec.server}）{g.spec.default ? " · 默认" : ""}
              </option>
            ))}
          </select>
        </div>
      )}
      {hostname && gateways.length === 0 && <div className="note">还没有网关，先在「网关」页新建一个。</div>}
    </Drawer>
  );
}
