import { useState } from "react";
import { Link } from "react-router-dom";
import { useStatus } from "../App";
import { Light, Mark, PageHead, crateClass, liveTone } from "../components/ui";
import { NewService } from "./NewService";

/** 首页导航：每条路由一张卡片，直接点开；没有域名的服务给内网地址。 */
export function Home() {
  const { status, refresh } = useStatus();
  const [creating, setCreating] = useState(false);
  if (!status) return <PageHead en="Harbor" zh="港口" sub="载入中…" />;

  const byService = new Map(status.services.map((s) => [s.name, s]));
  const routed = new Set(status.routes.map((r) => r.spec.service));
  const internal = status.services.filter((s) => !routed.has(s.name));

  return (
    <>
      <PageHead
        en="Harbor"
        zh="港口"
        sub={`${status.servers.length} 台服务器 · ${status.services.length} 个服务 · ${status.routes.length} 个域名`}
        action={
          <button className="btn primary" onClick={() => setCreating(true)}>
            ＋ 新建服务
          </button>
        }
      />

      <h2 className="section">Routes · 域名</h2>
      <div className="yard">
        {status.routes.map((r, i) => {
          const svc = byService.get(r.spec.service);
          const { tone, text } = liveTone(svc?.live);
          return (
            <a className={`crate ${crateClass(tone)}`} key={r.id} href={r.url} target="_blank" rel="noreferrer" style={{ ["--i" as string]: i }}>
              <span className="tag">{svc?.spec.server ?? "-"}</span>
              <div className="head">
                <Mark name={r.spec.service} url={r.url} />
                <div>
                  <div className="name">{r.spec.service}</div>
                  <div className="meta">
                    <Light tone={tone} />
                    {text}
                  </div>
                </div>
              </div>
              <div className="addr">{r.url.replace(/^https?:\/\//, "")}</div>
              <div className="foot">
                <span>经 {r.gateway ?? "-"}</span>
                <span>打开 ↗</span>
              </div>
            </a>
          );
        })}
        {status.routes.length === 0 && <div className="empty">还没有域名。新建服务时可以顺手加一个。</div>}
      </div>

      {internal.length > 0 && (
        <>
          <h2 className="section">Internal · 只在内网</h2>
          <div className="yard">
            {internal.map((s, i) => {
              const { tone, text } = liveTone(s.live);
              return (
                <Link className={`crate ${crateClass(tone)}`} key={s.name} to={`/services/${s.name}`} style={{ ["--i" as string]: i }}>
                  <span className="tag">{s.spec.server}</span>
                  <div className="head">
                    <Mark name={s.name} />
                    <div>
                      <div className="name">{s.name}</div>
                      <div className="meta">
                        <Light tone={tone} />
                        {text}
                      </div>
                    </div>
                  </div>
                  {Object.entries(s.addresses).map(([port, addr]) => (
                    <div className="addr" key={port}>
                      {port} → {addr}
                    </div>
                  ))}
                </Link>
              );
            })}
          </div>
        </>
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
