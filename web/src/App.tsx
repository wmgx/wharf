import { Suspense, lazy, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, setUnauthorizedHandler, usePoll, type Session } from "./api";
import { ActionsProvider } from "./components/actions";
import { AppSidebar } from "./components/app-sidebar";
import { Boundary } from "./components/Boundary";
import { CommandMenu } from "./components/command-menu";
import { Problems } from "./components/problems";
import { Separator } from "./components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "./components/ui/sidebar";
import { Skeleton } from "./components/ui/skeleton";
import { Toaster } from "./components/ui/sonner";
import { TooltipProvider } from "./components/ui/tooltip";
import { Gateways } from "./pages/Gateways";
import { Network } from "./pages/Network";
import { Accounts } from "./pages/Accounts";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { ServerDetail } from "./pages/ServerDetail";
import { ServiceDetail } from "./pages/ServiceDetail";
import { EdgeDetail } from "./pages/EdgeDetail";
import { Services } from "./pages/Services";
import { StatusContext } from "./status";
import { ThemeProvider } from "./theme";
import type { Status } from "./types";

// 拓扑图依赖的 @xyflow/react 比较大，只在打开拓扑页时加载。
const Topology = lazy(() => import("./pages/Topology").then((m) => ({ default: m.Topology })));

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
  ["/servers/", "服务器"],
  ["/gateways", "网关"],
  ["/network", "组网"],
  ["/topology", "拓扑"],
  ["/", "港口"],
];

function Shell({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { data: status, refresh } = usePoll<Status>("/api/status", 5000);
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
              <span className="text-sm font-medium">{title}</span>
              <div className="ml-auto flex flex-1 items-center justify-end gap-2">
                <Problems />
                <CommandMenu onLogout={onLogout} />
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
                  <Route path="/gateways" element={<Gateways />} />
                  <Route path="/network" element={<Network />} />
                  <Route path="/accounts" element={<Accounts />} />
                  <Route path="/topology" element={<Suspense fallback={<Skeleton className="h-[480px] rounded-xl" />}><Topology /></Suspense>} />
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
