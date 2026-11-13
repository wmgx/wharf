import { InboxIcon, AnchorIcon, BoxIcon, DatabaseIcon, NetworkIcon, GlobeIcon, ChevronsUpDownIcon, HistoryIcon, LogOutIcon, TimerIcon, MoonIcon, ServerIcon, SettingsIcon, SunIcon } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import { usePoll } from "@/api";
import { useStatus } from "@/status";
import { issueCount, useIssues } from "@/components/issues";
import type { VersionView } from "./upgrade";
import { useTheme } from "@/theme";

export function Logo({ className = "size-8" }: { className?: string }) {
  return (
    <span className={`grid shrink-0 place-items-center rounded-lg bg-foreground text-background ${className}`}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden>
        <path d="M2 10h12l-2 4H4z" />
        <path d="M7 2h1.5v7H7z" />
        <path d="M8.5 3l4.5 5H8.5z" opacity="0.7" />
      </svg>
    </span>
  );
}

export function AppSidebar({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { status } = useStatus();
  const { pathname } = useLocation();
  const { theme, toggle } = useTheme();

  const issues = useIssues();
  const version = usePoll<VersionView>("/api/version", 600000).data;
  const groups = [
    { label: "", items: [{ to: "/", label: "首页", icon: AnchorIcon }] },
    { label: "应用", items: [
      { to: "/services", label: "服务", icon: BoxIcon, count: status ? status.services.length + (status.edge_apps?.length ?? 0) : undefined },
      { to: "/domains", label: "域名", icon: GlobeIcon, count: status?.routes.length },
      { to: "/tasks", label: "任务", icon: TimerIcon },
    ] },
    { label: "机器", items: [
      { to: "/servers", label: "服务器", icon: ServerIcon, count: status?.servers.length },
      { to: "/network", label: "网络", icon: NetworkIcon },
    ] },
    { label: "保障", items: [
      { to: "/inbox", label: "待处理", icon: InboxIcon, count: issueCount(issues) || undefined },
      { to: "/data", label: "数据与备份", icon: DatabaseIcon },
      { to: "/activity", label: "活动", icon: HistoryIcon },
    ] },
    { label: "", items: [{ to: "/settings", label: "设置", icon: SettingsIcon, dot: !!version?.newer }] },
  ];
  const active = (to: string) => to === "/" ? pathname === "/" : to === "/services" ? pathname.startsWith("/services") || pathname.startsWith("/edge/") : pathname.startsWith(to);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <NavLink to="/">
                <Logo />
                <div className="grid leading-tight">
                  <span className="font-semibold">Wharf</span>
                </div>
              </NavLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {groups.map((g, gi) => (
          <SidebarGroup key={gi} className={gi === groups.length - 1 ? "mt-auto" : undefined}>
            {g.label && <SidebarGroupLabel>{g.label}</SidebarGroupLabel>}
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((it) => (
                  <SidebarMenuItem key={it.to}>
                    <SidebarMenuButton asChild isActive={active(it.to)} tooltip={it.label}>
                      <NavLink to={it.to === "/settings" && "dot" in it && it.dot ? "/settings?tab=core" : it.to}>
                        <it.icon />
                        <span>{it.label}</span>
                        {"dot" in it && it.dot && <span className="ml-auto size-2 rounded-full bg-primary" aria-label="有新版本" />}
                      </NavLink>
                    </SidebarMenuButton>
                    {"count" in it && it.count != null && <SidebarMenuBadge>{it.count}</SidebarMenuBadge>}
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}

      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu modal={false}>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent">
                  <span className="grid size-8 shrink-0 place-items-center rounded-lg border bg-background text-xs font-medium uppercase">{username.slice(0, 1)}</span>
                  <div className="grid min-w-0 leading-tight">
                    <span className="truncate text-sm font-medium">{username}</span>
                    <span className="text-xs text-muted-foreground">管理员</span>
                  </div>
                  <ChevronsUpDownIcon className="ml-auto" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-(--radix-dropdown-menu-trigger-width) min-w-52">
                <DropdownMenuItem onSelect={toggle}>
                  {theme === "light" ? <MoonIcon /> : <SunIcon />}
                  {theme === "light" ? "切换到深色" : "切换到浅色"}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={onLogout}>
                  <LogOutIcon />
                  退出登录
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
