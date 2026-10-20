import { createContext, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { getToken, setToken, setUnauthorizedHandler, usePoll } from "./api";
import { Light } from "./components/ui";
import { Gateways } from "./pages/Gateways";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { ServiceDetail } from "./pages/ServiceDetail";
import { Services } from "./pages/Services";
import { Topology } from "./pages/Topology";
import type { Status } from "./types";

interface StatusCtx {
  status: Status | null;
  refresh: () => void;
}

const Ctx = createContext<StatusCtx>({ status: null, refresh: () => {} });

/** 全局状态：每 5 秒拉一次 /api/status，各页面共用。 */
export const useStatus = () => useContext(Ctx);

export function App() {
  const [authed, setAuthed] = useState(() => !!getToken());

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setAuthed(false);
    });
  }, []);

  if (!authed) return <Login onDone={() => setAuthed(true)} />;
  return (
    <Shell
      onLogout={() => {
        setToken(null);
        setAuthed(false);
      }}
    />
  );
}

const NAV = [
  { to: "/", idx: "01", label: "港口" },
  { to: "/services", idx: "02", label: "服务" },
  { to: "/gateways", idx: "03", label: "网关" },
  { to: "/topology", idx: "04", label: "拓扑" },
];

function Shell({ onLogout }: { onLogout: () => void }) {
  const { data: status, refresh } = usePoll<Status>("/api/status", 5000);
  return (
    <Ctx.Provider value={{ status, refresh }}>
      <div className="shell">
        <nav className="rail">
          <div className="brand">
            Wharf <small>v0.1</small>
          </div>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}>
              <span className="idx">{n.idx}</span>
              {n.label}
            </NavLink>
          ))}
          <div className="spacer" />
          <button className="logout" onClick={onLogout}>
            退出登录
          </button>
        </nav>
        <main>
          <HarborBar status={status} />
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/services" element={<Services />} />
            <Route path="/services/:name" element={<ServiceDetail />} />
            <Route path="/gateways" element={<Gateways />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </Ctx.Provider>
  );
}

/** 顶部信号条：每台服务器一盏灯。 */
function HarborBar({ status }: { status: Status | null }) {
  const problems = status?.problems ?? [];
  return (
    <div className="harbor-bar">
      <span className="label">Berths</span>
      {!status && <span className="berth">载入中…</span>}
      {status?.servers.map((s) => (
        <span className="berth" key={s.name} title={s.private_addr ? `内网 ${s.private_addr.ip}（${s.private_addr.network}）` : "没有内网地址"}>
          <Light tone={!s.joined ? "fog" : s.online ? "go" : "stop"} />
          <b>{s.name}</b>
          {s.online ? (s.rtt_ms != null ? `${s.rtt_ms}ms` : "在线") : s.joined ? "离线" : "未加入"}
        </span>
      ))}
      {problems.length > 0 && (
        <span className="problems" title={problems.join("\n")}>
          ⚑ {problems.length} 项需要注意
        </span>
      )}
    </div>
  );
}
