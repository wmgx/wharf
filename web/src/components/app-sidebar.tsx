import { AnchorIcon, CableIcon, PlusIcon, BoxesIcon, CloudIcon, ChevronsUpDownIcon, KeyRoundIcon, LogOutIcon, MoonIcon, NetworkIcon, SunIcon, ArrowUpCircleIcon, WaypointsIcon, HardDriveIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSkeleton,
  SidebarRail,
} from "@/components/ui/sidebar";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import { useActions } from "./actions";
import { AddServer } from "./add-server";
import { diskText, Dot, serverText, serverTone } from "./common";

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
  const actions = useActions();
  const [adding, setAdding] = useState(false);

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
        { to: "/network", label: "组网", icon: CableIcon },
      ],
    },
    {
      label: "设置",
      items: [{ to: "/accounts", label: "厂商账号", icon: CloudIcon }],
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
          <SidebarGroupAction title="加服务器" onClick={() => setAdding(true)}>
            <PlusIcon />
          </SidebarGroupAction>
          <SidebarGroupContent>
            <SidebarMenu>
              {!status && <SidebarMenuSkeleton showIcon />}
              {status?.servers.map((s) => {
                const disk = diskText(s);
                return (
                  <SidebarMenuItem key={s.name}>
                    <DropdownMenu modal={false}>
                      <DropdownMenuTrigger asChild>
                        <SidebarMenuButton
                          className={s.agent_outdated ? "pr-8" : undefined}
                          tooltip={`${s.name} · ${serverText(s)}${s.private_addr ? ` · 内网 ${s.private_addr.ip}` : ""}${disk ? ` · 磁盘剩 ${disk.text}` : ""}`}
                        >
                          <span className="grid size-4 place-items-center">
                            <Dot tone={serverTone(s)} />
                          </span>
                          <span className="group-data-[collapsible=icon]:hidden">{s.name}</span>
                          {disk?.low && <HardDriveIcon className="text-warning group-data-[collapsible=icon]:hidden" />}
                          <span className="ml-auto font-mono text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">{serverText(s)}</span>
                        </SidebarMenuButton>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent side="right" align="start" className="min-w-52">
                        {disk && (
                          <div className={`px-2 py-1.5 text-xs ${disk.low ? "text-warning" : "text-muted-foreground"}`}>磁盘剩 {disk.text}</div>
                        )}
                        <DropdownMenuItem disabled={!s.online} onSelect={() => actions.prune(s.name)}>
                          <Trash2Icon />
                          清理没在用的镜像
                        </DropdownMenuItem>
                        {s.agent_outdated && (
                          <DropdownMenuItem onSelect={() => actions.upgradeAgent(s.name)}>
                            <ArrowUpCircleIcon />
                            升级 agent
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                    {s.agent_outdated && (
                      <SidebarMenuAction title="升级 agent" onClick={() => actions.upgradeAgent(s.name)}>
                        <ArrowUpCircleIcon className="text-warning" />
                      </SidebarMenuAction>
                    )}
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <AddServer open={adding} onClose={() => setAdding(false)} />
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
