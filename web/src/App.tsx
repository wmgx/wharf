import { useEffect, useState } from "react";
import * as vault from "@/lib/vault";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Activity } from "./pages/Activity";
import { Domains } from "./pages/Domains";
import { Servers } from "./pages/Servers";
import { api, setUnauthorizedHandler, usePoll, type Session } from "./api";
import { ActionsProvider } from "./components/actions";
import { AppSidebar } from "./components/app-sidebar";
import { Boundary } from "./components/Boundary";
import { CommandMenu } from "./components/command-menu";
import { NewMenu } from "./components/new-menu";
import { Problems } from "./components/problems";
import { Separator } from "./components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "./components/ui/sidebar";
import { Toaster } from "./components/ui/sonner";
import { announceUpgrade } from "./components/upgrade";
import { TooltipProvider } from "./components/ui/tooltip";
import { Settings } from "./pages/Settings";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { ServerDetail } from "./pages/ServerDetail";
import { HostTerminal } from "./pages/HostTerminal";
import { ServiceDetail } from "./pages/ServiceDetail";
import { EdgeDetail } from "./pages/EdgeDetail";
import { Services } from "./pages/Services";
import { StatusContext } from "./status";
import { ThemeProvider } from "./theme";
import type { Status } from "./types";


export function App() {
  // null：还在问控制面是否已登录。
  const [session, setSession] = useState<Session | null>(null);
  const load = () =>
    api
      .get<Session>("/api/session")
      .then(setSession)
      .catch(() => setSession({ setup_needed: false, setup_open: false }));

  useEffect(() => {
    load();
    setUnauthorizedHandler(() => setSession((s) => (s?.username ? { ...s, username: undefined } : s)));
  }, []);

  const logout = async () => {
    await api.post("/api/logout", {}).catch(() => {});
    vault.lock();
    load();
  };

  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={300}>
        {!session ? null : session.username ? (
          <Shell username={session.username} onLogout={logout} />
        ) : (
          <Login session={session} onDone={setSession} onRetry={load} />
        )}
        <Toaster position="bottom-right" />
      </TooltipProvider>
    </ThemeProvider>
  );
}

const TITLES: [string, string][] = [
  ["/services/", "服务详情"],
  ["/services", "服务"],
  ["/edge/", "服务详情"],
  ["/domains", "域名"],
  ["/servers", "服务器"],
  ["/activity", "活动"],
  ["/settings", "设置"],
  ["/", "首页"],
];

function Shell({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { data: status, refresh } = usePoll<Status>("/api/status", 5000);
  useEffect(announceUpgrade, []);
  const { pathname } = useLocation();
  const title = TITLES.find(([p]) => pathname.startsWith(p))?.[1] ?? "";

  return (
    <StatusContext.Provider value={{ status, refresh }}>
      <ActionsProvider>
        <SidebarProvider>
          <AppSidebar username={username} onLogout={onLogout} />
          <SidebarInset>
            <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
              <span className="hidden text-sm font-medium sm:inline">{title}</span>
              <div className="ml-auto flex min-w-0 flex-1 items-center justify-end gap-2">
                <Problems />
                <CommandMenu onLogout={onLogout} />
                <NewMenu />
              </div>
            </header>
            <div className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 md:px-8">
              <Boundary>
                <Routes>
                  <Route path="/" element={<Home />} />
                  <Route path="/services" element={<Services />} />
                  <Route path="/services/:name" element={<ServiceDetail />} />
                  <Route path="/edge/:name" element={<EdgeDetail />} />
                  <Route path="/servers/:name" element={<ServerDetail />} />
                  <Route path="/servers/:name/terminal" element={<HostTerminal />} />
                  <Route path="/servers" element={<Servers />} />
                  <Route path="/domains" element={<Domains />} />
                  <Route path="/activity" element={<Activity />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/data" element={<Moved to="/services" tab="data" />} />
                  <Route path="/gateways" element={<Moved to="/domains" tab="entries" />} />
                  <Route path="/network" element={<Moved to="/servers" tab="network" />} />
                  <Route path="/accounts" element={<Moved to="/settings" />} />
                  <Route path="/topology" element={<Moved to="/servers" tab="topology" />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Boundary>
            </div>
          </SidebarInset>
        </SidebarProvider>
      </ActionsProvider>
    </StatusContext.Provider>
  );
}

/** 旧地址跳到新位置，保留查询参数（例如 `/gateways?open=x`）。 */
function Moved({ to, tab }: { to: string; tab?: string }) {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  if (tab) params.set("tab", tab);
  const q = params.toString();
  return <Navigate to={q ? `${to}?${q}` : to} replace />;
}
