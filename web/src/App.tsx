import { useEffect, useState } from "react";
import * as vault from "@/lib/vault";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Activity } from "./pages/Activity";
import { Servers } from "./pages/Servers";
import { api, clearPollCache, setUnauthorizedHandler, usePoll, type Session } from "./api";
import { ActionsProvider } from "./components/actions";
import { AppSidebar } from "./components/app-sidebar";
import { Boundary } from "./components/Boundary";
import { CommandMenu } from "./components/command-menu";
import { NewMenu } from "./components/new-menu";
import { Problems } from "./components/problems";
import { Running } from "./components/running";
import { Separator } from "./components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "./components/ui/sidebar";
import { Toaster } from "./components/ui/sonner";
import { announceUpgrade } from "./components/upgrade";
import { TooltipProvider } from "./components/ui/tooltip";
import { Settings } from "./pages/Settings";
import { AlertsPage } from "./pages/alerts";
import { Home } from "./pages/Home";
import { ServicesPage } from "./pages/services";
import { Login } from "./pages/Login";
import { HostTerminal } from "./pages/HostTerminal";
import { ServiceDetail } from "./pages/ServiceDetail";
import { EdgeDetail } from "./pages/EdgeDetail";
import { DataPage, Entries, NetworkPage } from "./pages/Panels";
import { TasksPage } from "./pages/tasks";
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
    clearPollCache();
    load();
  };

  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={300}>
        {!session ? null : session.username ? (
          <Shell username={session.username} onLogout={logout} />
        ) : (
          <Login session={session} onDone={setSession} />
        )}
        <Toaster position="bottom-right" />
      </TooltipProvider>
    </ThemeProvider>
  );
}

function Shell({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { data: status, refresh } = usePoll<Status>("/api/status", 5000);
  useEffect(announceUpgrade, []);
  const { pathname } = useLocation();

  return (
    <StatusContext.Provider value={{ status, refresh }}>
      <ActionsProvider>
        <SidebarProvider>
          <AppSidebar username={username} onLogout={onLogout} />
          <SidebarInset>
            <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
              <div className="min-w-0 flex-1 max-w-sm"><CommandMenu onLogout={onLogout} /></div>
              <div className="ml-auto flex items-center justify-end gap-2">
                <Running />
                <Problems />
                <NewMenu />
              </div>
            </header>
            <div className={pathname.startsWith("/servers") && !pathname.endsWith("/terminal") ? "flex flex-1" : "mx-auto w-full max-w-6xl flex-1 px-4 py-8 md:px-8"}>
              <Boundary>
                <Routes>
                  <Route path="/" element={<HomeRoute />} />
                  <Route path="/services" element={<ServicesRoute />} />
                  <Route path="/services/:name" element={<ServiceDetail />} />
                  <Route path="/edge/:name" element={<EdgeDetail />} />
                  <Route path="/servers/:name" element={<Servers />} />
                  <Route path="/servers/:name/terminal" element={<HostTerminal />} />
                  <Route path="/servers" element={<Servers />} />
                  <Route path="/entries" element={<Entries />} />
                  <Route path="/domains" element={<Moved to="/entries" />} />
                  <Route path="/activity" element={<Activity />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/alerts" element={<AlertsPage />} />
                  <Route path="/tasks" element={<TasksPage />} />
                  <Route path="/data" element={<DataPage />} />
                  <Route path="/gateways" element={<Moved to="/entries" />} />
                  <Route path="/network" element={<NetworkPage />} />
                  <Route path="/accounts" element={<Moved to="/settings" />} />
                  <Route path="/topology" element={<Moved to="/network" />} />
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

function HomeRoute() {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  return ["new", "import", "edge"].some((key) => params.get(key) === "1")
    ? <Navigate to={`/services${search}`} replace /> : <Home />;
}

function ServicesRoute() {
  const { search } = useLocation();
  return new URLSearchParams(search).get("tab") === "data" ? <Moved to="/data" /> : <ServicesPage />;
}

/** 旧地址跳到新位置，保留查询参数（例如 `/gateways?open=x`）。 */
function Moved({ to }: { to: string }) {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  params.delete("tab");
  const q = params.toString();
  return <Navigate to={q ? `${to}?${q}` : to} replace />;
}
