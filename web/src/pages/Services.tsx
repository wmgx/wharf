import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStatus } from "../App";
import { Badge, PageHead, imageOf, liveTone } from "../components/ui";
import { NewService } from "./NewService";

export function Services() {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [creating, setCreating] = useState(false);
  const routesOf = (name: string) => status?.routes.filter((r) => r.spec.service === name) ?? [];

  return (
    <>
      <PageHead
        title="服务"
        sub="每个服务是一组容器，跑在一台服务器上。"
        action={
          <button className="btn primary" onClick={() => setCreating(true)}>
            新建服务
          </button>
        }
      />
      {!status ? (
        <p>载入中…</p>
      ) : status.services.length === 0 ? (
        <div className="empty">还没有服务。点右上角新建一个。</div>
      ) : (
        <div className="table-wrap">
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
                  <td className="strong">{s.name}</td>
                  <td>
                    <Badge tone={tone}>{text}</Badge>
                  </td>
                  <td>
                    <span className="tag">{s.spec.server}</span>
                  </td>
                  <td className="mono muted">
                    {imageOf(s)}
                  </td>
                  <td className="mono">
                    {routesOf(s.name).map((r) => (
                      <div key={r.id}>{r.spec.hostname}</div>
                    ))}
                    {routesOf(s.name).length === 0 && <span className="muted">-</span>}
                  </td>
                  <td className="mono muted">
                    {Object.values(s.addresses).join(" ")}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
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
