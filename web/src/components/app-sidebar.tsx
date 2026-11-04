import { AnchorIcon, ChevronsUpDownIcon, HistoryIcon, LogOutIcon, MoonIcon, ServerIcon, SettingsIcon, SunIcon } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar";
import { useStatus } from "@/status";
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

  const groups = [
    {
      label: "",
      items: [
        { to: "/", label: "首页", icon: AnchorIcon, count: status ? status.services.length + (status.edge_apps?.length ?? 0) : undefined },
        { to: "/servers", label: "服务器", icon: ServerIcon, count: status?.servers.length },
        { to: "/activity", label: "活动", icon: HistoryIcon },
      ],
    },
    {
      label: "",
      items: [{ to: "/settings", label: "设置", icon: SettingsIcon }],
    },
  ];
  // 服务详情从首页点进去，算在首页下面。
  const active = (to: string) => (to === "/" ? pathname === "/" || pathname.startsWith("/services/") || pathname.startsWith("/edge/") : pathname.startsWith(to));

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
                  <span className="text-xs text-muted-foreground">多服务器管理</span>
                </div>
              </NavLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {groups.map((g, gi) => (
          <SidebarGroup key={gi} className={gi === groups.length - 1 ? "mt-auto" : undefined}>
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((it) => (
                  <SidebarMenuItem key={it.to}>
                    <SidebarMenuButton asChild isActive={active(it.to)} tooltip={it.label}>
                      <NavLink to={it.to}>
                        <it.icon />
                        <span>{it.label}</span>
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
