import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStatus } from "../App";
import { Light, PageHead, imageOf, liveTone } from "../components/ui";
import { NewService } from "./NewService";

export function Services() {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [creating, setCreating] = useState(false);
  const routesOf = (name: string) => status?.routes.filter((r) => r.spec.service === name) ?? [];

  return (
    <>
      <PageHead
        en="Services"
        zh="服务"
        sub="每个服务是一组容器，跑在一台服务器上。"
        action={
          <button className="btn primary" onClick={() => setCreating(true)}>
            ＋ 新建服务
          </button>
        }
      />
      {!status ? (
        <p>载入中…</p>
      ) : status.services.length === 0 ? (
        <div className="empty">还没有服务。点右上角新建一个。</div>
      ) : (
        <table className="manifest">
          <thead>
            <tr>
              <th>服务</th>
              <th>状态</th>
              <th>服务器</th>
              <th>来源</th>
              <th>域名</th>
              <th>内网地址</th>
            </tr>
          </thead>
          <tbody>
            {status.services.map((s) => {
              const { tone, text } = liveTone(s.live);
              return (
                <tr className="link" key={s.name} onClick={() => nav(`/services/${s.name}`)}>
                  <td style={{ fontFamily: "var(--display)", fontSize: 18, fontWeight: 700 }}>{s.name}</td>
                  <td>
                    <span className="row" style={{ gap: 8 }}>
                      <Light tone={tone} />
                      <span style={{ flex: "none" }}>{text}</span>
                    </span>
                  </td>
                  <td className="mono">{s.spec.server}</td>
                  <td className="mono" style={{ color: "var(--ink-2)" }}>
                    {imageOf(s)}
                  </td>
                  <td className="mono">
                    {routesOf(s.name).map((r) => (
                      <div key={r.id}>{r.spec.hostname}</div>
                    ))}
                    {routesOf(s.name).length === 0 && <span style={{ color: "var(--ink-3)" }}>-</span>}
                  </td>
                  <td className="mono" style={{ color: "var(--ink-2)" }}>
                    {Object.values(s.addresses).join(" ")}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {creating && (
        <NewService
          onClose={() => {
            setCreating(false);
            refresh();
          }}
        />
      )}
    </>
  );
}
