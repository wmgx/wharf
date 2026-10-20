import { AnchorIcon, BoxesIcon, ChevronsUpDownIcon, KeyRoundIcon, LogOutIcon, MoonIcon, NetworkIcon, SunIcon, WaypointsIcon } from "lucide-react";
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
  SidebarMenuSkeleton,
  SidebarRail,
} from "@/components/ui/sidebar";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import { useActions } from "./actions";
import { Dot, serverText, serverTone } from "./common";

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

export function AppSidebar({ onLogout }: { onLogout: () => void }) {
  const { status } = useStatus();
  const { pathname } = useLocation();
  const { theme, toggle } = useTheme();
  const actions = useActions();

  const groups = [
    {
      label: "概览",
      items: [
        { to: "/", label: "港口", icon: AnchorIcon },
        { to: "/topology", label: "拓扑", icon: NetworkIcon },
      ],
    },
    {
      label: "资源",
      items: [
        { to: "/services", label: "服务", icon: BoxesIcon, count: status?.services.length },
        { to: "/gateways", label: "网关", icon: WaypointsIcon, count: status?.gateways.length },
      ],
    },
  ];
  const active = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));

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
        {groups.map((g) => (
          <SidebarGroup key={g.label}>
            <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
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

        <SidebarGroup className="mt-auto">
          <SidebarGroupLabel>服务器</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {!status && <SidebarMenuSkeleton showIcon />}
              {status?.servers.map((s) => (
                <SidebarMenuItem key={s.name}>
                  <SidebarMenuButton
                    className="cursor-default"
                    tooltip={`${s.name} · ${serverText(s)}${s.private_addr ? ` · 内网 ${s.private_addr.ip}` : ""}`}
                  >
                    <span className="grid size-4 place-items-center">
                      <Dot tone={serverTone(s)} />
                    </span>
                    <span className="group-data-[collapsible=icon]:hidden">{s.name}</span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">{serverText(s)}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent">
                  <span className="grid size-8 shrink-0 place-items-center rounded-lg border bg-background text-xs font-medium">管</span>
                  <div className="grid leading-tight">
                    <span className="text-sm font-medium">管理员</span>
                    <span className="text-xs text-muted-foreground">API token 登录</span>
                  </div>
                  <ChevronsUpDownIcon className="ml-auto" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-(--radix-dropdown-menu-trigger-width) min-w-52">
                <DropdownMenuItem onSelect={toggle}>
                  {theme === "light" ? <MoonIcon /> : <SunIcon />}
                  {theme === "light" ? "切换到深色" : "切换到浅色"}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={actions.basicAuth}>
                  <KeyRoundIcon />
                  登录保护账号
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
