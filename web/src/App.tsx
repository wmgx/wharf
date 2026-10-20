import { createContext, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { getToken, setToken, setUnauthorizedHandler, usePoll } from "./api";
import { Boundary } from "./components/Boundary";
import { Light } from "./components/ui";
import { Gateways } from "./pages/Gateways";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { ServiceDetail } from "./pages/ServiceDetail";
import { Services } from "./pages/Services";
import { Topology } from "./pages/Topology";
import type { Status } from "./types";

type Theme = "light" | "dark";

interface StatusCtx {
  status: Status | null;
  refresh: () => void;
  theme: Theme;
}

const Ctx = createContext<StatusCtx>({ status: null, refresh: () => {}, theme: "light" });

/** 全局状态：每 5 秒拉一次 /api/status，各页面共用。 */
export const useStatus = () => useContext(Ctx);

const THEME_KEY = "wharf.theme";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // 读不到就跟随系统。
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const toggle = () =>
    setTheme((t) => {
      const next = t === "light" ? "dark" : "light";
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch {
        // 只在本次页面里生效。
      }
      return next;
    });
  return [theme, toggle];
}

export function App() {
  const [authed, setAuthed] = useState(() => !!getToken());
  const [theme, toggleTheme] = useTheme();

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setAuthed(false);
    });
  }, []);

  if (!authed) return <Login onDone={() => setAuthed(true)} />;
  return (
    <Shell
      theme={theme}
      toggleTheme={toggleTheme}
      onLogout={() => {
        setToken(null);
        setAuthed(false);
      }}
    />
  );
}

const NAV = [
  { to: "/", label: "港口" },
  { to: "/services", label: "服务" },
  { to: "/gateways", label: "网关" },
  { to: "/topology", label: "拓扑" },
];

export function Logo() {
  return (
    <span className="logo">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden>
        <path d="M2 10h12l-2 4H4z" />
        <path d="M7 2h1.5v7H7z" />
        <path d="M8.5 3l4.5 5H8.5z" opacity="0.7" />
      </svg>
    </span>
  );
}

function Shell({ theme, toggleTheme, onLogout }: { theme: Theme; toggleTheme: () => void; onLogout: () => void }) {
  const { data: status, refresh } = usePoll<Status>("/api/status", 5000);
  return (
    <Ctx.Provider value={{ status, refresh, theme }}>
      <header className="topbar">
        <div className="container inner">
          <NavLink to="/" className="brand">
            <Logo />
            Wharf
          </NavLink>
          <nav className="nav">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.to === "/"}>
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="right">
            <Servers status={status} />
            <button className="icon-btn" onClick={toggleTheme} title={theme === "light" ? "切换到深色" : "切换到浅色"}>
              {theme === "light" ? "☾" : "☀"}
            </button>
            <button className="btn small ghost" onClick={onLogout}>
              退出
            </button>
          </div>
        </div>
      </header>
      <main className="container">
        <Boundary>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/services" element={<Services />} />
            <Route path="/services/:name" element={<ServiceDetail />} />
            <Route path="/gateways" element={<Gateways />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Boundary>
      </main>
    </Ctx.Provider>
  );
}

/** 右上角：需要注意的问题，以及每台服务器的在线状态和延迟。 */
function Servers({ status }: { status: Status | null }) {
  const problems = status?.problems ?? [];
  return (
    <>
      {problems.length > 0 && (
        <span className="problems-link" title={problems.join("\n")}>
          {problems.length} 项需要注意
        </span>
      )}
      {status?.servers.map((s) => (
        <span
          className="server-pill"
          key={s.name}
          title={s.private_addr ? `内网 ${s.private_addr.ip}（${s.private_addr.network}）` : "没有内网地址"}
        >
          <Light tone={!s.joined ? "fog" : s.online ? "go" : "stop"} />
          <b>{s.name}</b>
          {s.online ? (s.rtt_ms != null ? `${s.rtt_ms} ms` : "在线") : s.joined ? "离线" : "未加入"}
        </span>
      ))}
    </>
  );
}
