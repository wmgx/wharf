import { AnchorIcon, ArrowRightLeftIcon, ArrowUpCircleIcon, BoxIcon, BoxesIcon, CableIcon, CloudIcon, DownloadIcon, GlobeIcon, HammerIcon, HardDriveIcon, HistoryIcon, KeyRoundIcon, LockIcon, LogOutIcon, MoonIcon, NetworkIcon, PencilIcon, PlayIcon, PlusIcon, RefreshCwIcon, RotateCwIcon, ScrollTextIcon, SearchIcon, ServerIcon, SettingsIcon, SquareIcon, SunIcon, TerminalIcon, Trash2Icon, WaypointsIcon, WrenchIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { Kbd } from "@/components/ui/kbd";
import { useStatus } from "@/status";
import { useTheme } from "@/theme";
import { useActions } from "./actions";
import { Dot, serviceTone } from "./common";

const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

/** 顶栏上的搜索入口，点击或按 ⌘K / Ctrl+K 打开命令面板。 */
export function CommandMenu({ onLogout }: { onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const { status } = useStatus();
  const { theme, toggle } = useTheme();
  const actions = useActions();
  const nav = useNavigate();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) setSearch("");
  }, [open]);

  const run = (fn: () => void) => {
    setOpen(false);
    fn();
  };
  const services = status?.services ?? [];
  const op = (key: string, value: string, icon: ReactNode, label: string, fn: () => void) => (
    <CommandItem key={key} value={value} onSelect={() => run(fn)}>
      {icon}
      {label}
    </CommandItem>
  );
  // 针对每个服务的操作比较多，输入了内容再列出来，默认界面保持简洁。
  const showOps = search.trim().length > 0;

  return (
    <>
      <Button variant="outline" className="h-8 w-full min-w-0 max-w-64 justify-start gap-2 px-2.5 font-normal text-muted-foreground" onClick={() => setOpen(true)}>
        <SearchIcon />
        <span className="flex-1 truncate text-left">搜索或执行操作…</span>
        <Kbd>{isMac ? "⌘" : "Ctrl"} K</Kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen} title="命令面板" description="搜索服务、网关，或直接执行操作">
        <CommandInput placeholder="输入服务名、页面或操作，例如「回滚 hello」" value={search} onValueChange={setSearch} />
        <CommandList>
          <CommandEmpty>没有匹配的结果</CommandEmpty>
          <CommandGroup heading="页面">
            <CommandItem value="首页 港口 home" onSelect={() => run(() => nav("/"))}>
              <AnchorIcon />
              首页
            </CommandItem>
            <CommandItem value="服务 services" onSelect={() => run(() => nav("/services"))}>
              <BoxesIcon />
              服务
            </CommandItem>
            <CommandItem value="域名 domains route" onSelect={() => run(() => nav("/domains"))}>
              <GlobeIcon />
              域名
            </CommandItem>
            <CommandItem value="入口 网关 gateway" onSelect={() => run(() => nav("/domains?tab=entries"))}>
              <WaypointsIcon />
              入口
            </CommandItem>
            <CommandItem value="服务器 servers" onSelect={() => run(() => nav("/servers"))}>
              <ServerIcon />
              服务器
            </CommandItem>
            <CommandItem value="组网 network tailscale" onSelect={() => run(() => nav("/servers?tab=network"))}>
              <CableIcon />
              组网
            </CommandItem>
            <CommandItem value="活动 执行记录 审计 runs" onSelect={() => run(() => nav("/activity"))}>
              <HistoryIcon />
              活动
            </CommandItem>
            <CommandItem value="设置 账号 密钥 token cli 备份 settings" onSelect={() => run(() => nav("/settings"))}>
              <SettingsIcon />
              设置
            </CommandItem>
            <CommandItem value="拓扑 topology" onSelect={() => run(() => nav("/servers?tab=topology"))}>
              <NetworkIcon />
              拓扑
            </CommandItem>
            <CommandItem value="数据 备份 data" onSelect={() => run(() => nav("/services?tab=data"))}>
              <HardDriveIcon />
              数据
            </CommandItem>
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="服务">
            {services.map((s) => (
              <CommandItem key={s.name} value={`服务 ${s.name} ${s.spec.server}`} onSelect={() => run(() => nav(`/services/${s.name}`))}>
                <BoxIcon />
                {s.name}
                <span className="text-xs text-muted-foreground">{s.spec.server}</span>
                <CommandShortcut>
                  <Dot tone={serviceTone(s).tone} />
                </CommandShortcut>
              </CommandItem>
            ))}
            {status?.servers.map((s) => (
              <CommandItem key={`server-${s.name}`} value={`服务器 ${s.name}`} onSelect={() => run(() => nav(`/servers/${s.name}`))}>
                <ServerIcon />
                {s.name}
                <span className="text-xs text-muted-foreground">服务器</span>
              </CommandItem>
            ))}
            {status?.gateways.map((g) => (
              <CommandItem key={g.name} value={`网关 ${g.name} ${g.spec.server}`} onSelect={() => run(() => nav(`/domains?tab=entries&open=${g.name}`))}>
                <WaypointsIcon />
                {g.name}
                <span className="text-xs text-muted-foreground">网关 · {g.spec.server}</span>
              </CommandItem>
            ))}
          </CommandGroup>
          {showOps && (
            <>
              <CommandSeparator />
              <CommandGroup heading="服务操作">
                {services.flatMap((s) => {
                  const go = (tab: string) => run(() => nav(`/services/${s.name}?tab=${tab}`));
                  const built = "build" in s.spec.source;
                  const updatable = "image" in s.spec.source || ("build" in s.spec.source && !!s.spec.source.build.git);
                  return [
                    op(`logs-${s.name}`, `日志 看 logs ${s.name}`, <ScrollTextIcon />, `看 ${s.name} 的日志`, () => go("logs")),
                    op(`cfg-${s.name}`, `修改配置 环境变量 端口 config edit ${s.name}`, <PencilIcon />, `修改 ${s.name} 的配置`, () => go("config")),
                    op(`dom-${s.name}`, `加域名 域名 domain route ${s.name}`, <GlobeIcon />, `${s.name} 的域名`, () => go("domains")),
                    op(`data-${s.name}`, `数据 备份 恢复 backup ${s.name}`, <HardDriveIcon />, `${s.name} 的数据与备份`, () => go("data")),
                    op(`term-${s.name}`, `终端 容器 shell terminal ${s.name}`, <TerminalIcon />, `进入 ${s.name} 的容器终端`, () => go("terminal")),
                    s.spec.stopped
                      ? op(`start-${s.name}`, `启动 start ${s.name}`, <PlayIcon />, `启动 ${s.name}`, () => actions.setStopped(s, false))
                      : op(`restart-${s.name}`, `重启 restart ${s.name}`, <RotateCwIcon />, `重启 ${s.name}`, () => actions.restart(s.name)),
                    !s.spec.stopped && op(`stop-${s.name}`, `停止 stop ${s.name}`, <SquareIcon />, `停止 ${s.name}`, () => actions.setStopped(s, true)),
                    updatable && op(`upd-${s.name}`, `检查更新 新版本 update ${s.name}`, <RefreshCwIcon />, `检查 ${s.name} 的更新`, () => actions.plan({ title: `检查 ${s.name} 的更新`, changes: [{ op: "refresh_images", name: s.name }] })),
                    built && op(`rebuild-${s.name}`, `重新构建 rebuild ${s.name}`, <HammerIcon />, `重新构建 ${s.name}`, () => actions.rebuild(s.name)),
                    op(`fix-${s.name}`, `检查并修复 重新部署 redeploy ${s.name}`, <WrenchIcon />, `检查并修复 ${s.name}`, () => actions.redeploy(s)),
                    op(`rollback-${s.name}`, `回滚 版本 rollback ${s.name}`, <HistoryIcon />, `${s.name} 回到上一个版本`, () => actions.rollback(s.name)),
                    op(`move-${s.name}`, `迁移 move ${s.name}`, <ArrowRightLeftIcon />, `迁移 ${s.name} 到其他服务器`, () => actions.move(s)),
                    op(`rm-${s.name}`, `删除 remove ${s.name}`, <Trash2Icon />, `删除 ${s.name}`, () => actions.remove(s.name)),
                  ].filter(Boolean);
                })}
              </CommandGroup>
              <CommandGroup heading="服务器操作">
                {(status?.servers ?? []).flatMap((v) => {
                  const go = (tab: string) => run(() => nav(`/servers/${encodeURIComponent(v.name)}?tab=${tab}`));
                  return [
                    op(`hterm-${v.name}`, `宿主机终端 terminal ${v.name}`, <TerminalIcon />, `打开 ${v.name} 的宿主机终端`, () => run(() => nav(`/servers/${encodeURIComponent(v.name)}/terminal`))),
                    op(`sys-${v.name}`, `系统 更新 apt 磁盘 system ${v.name}`, <HardDriveIcon />, `${v.name} 的系统和磁盘`, () => go("system")),
                    op(`set-${v.name}`, `服务器设置 镜像源 代理 settings ${v.name}`, <SettingsIcon />, `${v.name} 的设置`, () => go("settings")),
                    v.online && op(`prune-${v.name}`, `清理镜像 磁盘 prune ${v.name}`, <Trash2Icon />, `清理 ${v.name} 上没在用的镜像`, () => actions.prune(v.name)),
                    v.agent_outdated && op(`agent-${v.name}`, `升级 agent upgrade ${v.name}`, <ArrowUpCircleIcon />, `升级 ${v.name} 的 agent`, () => actions.upgradeAgent(v.name)),
                  ].filter(Boolean);
                })}
              </CommandGroup>
            </>
          )}
          <CommandSeparator />
          <CommandGroup heading="新建">
            {op("n-svc", "部署服务 新建服务 new deploy", <PlusIcon />, "部署服务", () => nav("/services?new=1"))}
            {op("n-imp", "导入已有容器 import", <DownloadIcon />, "导入服务器上已有的容器", () => nav("/services?import=1"))}
            {op("n-edge", "导入 Workers Pages cloudflare edge", <CloudIcon />, "导入 Cloudflare Workers / Pages", () => nav("/services?edge=1"))}
            {op("n-gw", "新建入口 网关 new gateway", <WaypointsIcon />, "新建入口", () => nav("/domains?tab=entries&new=1"))}
            {op("n-acc", "加 Cloudflare 账号 account", <KeyRoundIcon />, "加 Cloudflare 账号", () => nav("/settings?add=account"))}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="其他">
            {op("o-auth", "登录保护账号 basic auth 密码", <LockIcon />, "登录保护账号", actions.basicAuth)}
            {op("o-up", "升级 Wharf upgrade 控制面 agent", <ArrowUpCircleIcon />, "升级 Wharf", actions.upgrade)}
            {op("o-theme", "切换主题 深色 浅色 theme", theme === "light" ? <MoonIcon /> : <SunIcon />, theme === "light" ? "切换到深色" : "切换到浅色", toggle)}
            {op("o-out", "退出登录 logout", <LogOutIcon />, "退出登录", onLogout)}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
