import {
  AnchorIcon, ArrowUpCircleIcon, InboxIcon, BoxIcon, CloudIcon, DownloadIcon, GlobeIcon, HardDriveIcon,
  HistoryIcon, KeyRoundIcon, LogOutIcon, MoonIcon, NetworkIcon, PlusIcon, SearchIcon, ServerIcon,
  SettingsIcon, SunIcon, TimerIcon, WaypointsIcon,
} from "lucide-react";
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
import { usePoll } from "@/api";
import { useStatus } from "@/status";
import type { SecretView, TaskView } from "@/types";
import { useTheme } from "@/theme";
import { useActions } from "./actions";
import { serverOps, serviceOps, useOpCtx } from "./ops";
import { Dot, serviceTone } from "./common";

const isMac =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.platform);

/** 顶栏上的搜索入口，点击或按 ⌘K / Ctrl+K 打开命令面板。 */
export function CommandMenu({ onLogout }: { onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const { status } = useStatus();
  const { theme, toggle } = useTheme();
  const actions = useActions();
  const opCtx = useOpCtx();
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
  // 打开面板时才拉，平时不轮询。
  const tasks = usePoll<TaskView[]>(open ? "/api/tasks" : null, 60000);
  const secrets = usePoll<SecretView[]>(open ? "/api/secrets" : null, 60000);
  const op = (
    key: string,
    value: string,
    icon: ReactNode,
    label: string,
    fn: () => void,
  ) => (
    <CommandItem key={key} value={value} onSelect={() => run(fn)}>
      {icon}
      {label}
    </CommandItem>
  );
  // 针对每个服务的操作比较多，输入了内容再列出来，默认界面保持简洁。
  const showOps = search.trim().length > 0;

  return (
    <>
      <Button
        variant="outline"
        className="h-8 w-full min-w-0 max-w-sm justify-start gap-2 px-2.5 font-normal text-muted-foreground"
        onClick={() => setOpen(true)}
      >
        <SearchIcon />
        <span className="flex-1 truncate text-left">搜索或执行操作…</span>
        <Kbd>{isMac ? "⌘" : "Ctrl"} K</Kbd>
      </Button>
      <CommandDialog
        open={open}
        onOpenChange={setOpen}
        title="命令面板"
        description="搜索服务、入口，或直接执行操作"
      >
        <CommandInput
          placeholder="找服务、页面，或输入操作，例如「重启 halo」"
          value={search}
          onValueChange={setSearch}
        />
        <CommandList>
          <CommandEmpty>没有匹配的结果</CommandEmpty>
          <CommandGroup heading="页面">
            {([
              ["首页", "/", AnchorIcon], ["服务", "/services", BoxIcon], ["入口", "/entries", WaypointsIcon],
              ["定时任务", "/tasks", TimerIcon], ["服务器", "/servers", ServerIcon], ["网络", "/network", NetworkIcon],
              ["待处理", "/inbox", InboxIcon], ["数据与备份", "/data", HardDriveIcon], ["活动", "/activity", HistoryIcon],
              ["设置", "/settings", SettingsIcon],
            ] as const).map(([label, path, Icon]) => <CommandItem key={path} value={label} onSelect={() => run(() => nav(path))}><Icon />{label}</CommandItem>)}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="服务">
            {services.map((s) => (
              <CommandItem
                key={s.name}
                value={`服务 ${s.name} ${s.spec.server}`}
                onSelect={() => run(() => nav(`/services/${s.name}`))}
              >
                <BoxIcon />
                {s.name}
                <span className="text-xs text-muted-foreground">
                  {s.spec.server}
                </span>
                <CommandShortcut>
                  <Dot tone={serviceTone(s).tone} />
                </CommandShortcut>
              </CommandItem>
            ))}
            {status?.servers.map((s) => (
              <CommandItem
                key={`server-${s.name}`}
                value={`服务器 ${s.name}`}
                onSelect={() => run(() => nav(`/servers/${s.name}`))}
              >
                <ServerIcon />
                {s.name}
                <span className="text-xs text-muted-foreground">服务器</span>
              </CommandItem>
            ))}
            {status?.gateways.map((g) => (
              <CommandItem
                key={g.name}
                value={`网关 ${g.name} ${g.spec.server}`}
                onSelect={() => run(() => nav(`/entries?open=${g.name}`))}
              >
                <WaypointsIcon />
                {g.name}
                <span className="text-xs text-muted-foreground">
                  入口 · {g.spec.server}
                </span>
              </CommandItem>
            ))}
            {(status?.routes ?? []).map((r) => (
              <CommandItem
                key={`route-${r.spec.hostname}`}
                value={`域名 ${r.spec.hostname} ${r.spec.service ?? ""}`}
                onSelect={() =>
                  run(() =>
                    r.spec.service
                      ? nav(`/services/${r.spec.service}?tab=domains`)
                      : nav("/entries"),
                  )
                }
              >
                <GlobeIcon />
                <span className="truncate">{r.spec.hostname}</span>
                <span className="text-xs text-muted-foreground">
                  {r.spec.service ? `域名 · ${r.spec.service}` : "域名"}
                </span>
              </CommandItem>
            ))}
            {(status?.edge_apps ?? []).map((e) => (
              <CommandItem
                key={`edge-${e.name}`}
                value={`边缘 workers pages ${e.name}`}
                onSelect={() => run(() => nav(`/edge/${e.name}`))}
              >
                <CloudIcon />
                {e.name}
                <span className="text-xs text-muted-foreground">Cloudflare 应用</span>
              </CommandItem>
            ))}
            {showOps &&
              (tasks.data ?? []).map((t) => (
                <CommandItem
                  key={`task-${t.name}`}
                  value={`定时任务 task cron ${t.name} ${t.spec.server}`}
                  onSelect={() =>
                    run(() =>
                      nav(
                        `/tasks?server=${encodeURIComponent(t.spec.server)}`,
                      ),
                    )
                  }
                >
                  <TimerIcon />
                  {t.name}
                  <span className="text-xs text-muted-foreground">
                    定时任务 · {t.spec.server}
                  </span>
                </CommandItem>
              ))}
            {showOps &&
              (secrets.data ?? []).map((s) => (
                <CommandItem
                  key={`secret-${s.name}`}
                  value={`密钥 secret ${s.name}`}
                  onSelect={() => run(() => nav("/settings?tab=secrets"))}
                >
                  <KeyRoundIcon />
                  <span className="font-mono text-xs">{s.name}</span>
                  <span className="text-xs text-muted-foreground">密钥</span>
                </CommandItem>
              ))}
          </CommandGroup>
          {showOps && (
            <>
              <CommandSeparator />
              <CommandGroup heading="服务操作">
                {services.flatMap((svc) => serviceOps.filter((item) => !item.show || item.show(svc, opCtx)).map((item) =>
                  op(`${item.id}-${svc.name}`, `${item.label} ${svc.name} ${item.keywords ?? ""}`, <item.icon />, `${item.label} ${svc.name}`, () => item.run(svc, opCtx)),
                ))}
              </CommandGroup>
              <CommandGroup heading="服务器操作">
                {(status?.servers ?? []).flatMap((server) => serverOps.filter((item) => !item.show || item.show(server, opCtx)).map((item) =>
                  op(`${item.id}-${server.name}`, `${item.label} ${server.name} ${item.keywords ?? ""}`, <item.icon />, `${item.label} ${server.name}`, () => item.run(server, opCtx)),
                ))}
              </CommandGroup>
            </>
          )}
          <CommandSeparator />
          <CommandGroup heading="新建">
            {op(
              "n-svc",
              "部署服务 新建服务 new deploy",
              <PlusIcon />,
              "部署服务",
              () => nav("/services?new=1"),
            )}
            {op(
              "n-imp",
              "导入已有容器 import",
              <DownloadIcon />,
              "导入服务器上已有的容器",
              () => nav("/services?import=1"),
            )}
            {op(
              "n-edge",
              "导入 Workers Pages cloudflare edge",
              <CloudIcon />,
              "导入 Cloudflare Workers / Pages",
              () => nav("/services?edge=1"),
            )}
            {op(
              "n-gw",
              "新建入口 网关 new gateway",
              <WaypointsIcon />,
              "新建入口",
              () => nav("/entries?new=1"),
            )}
            {op(
              "n-acc",
              "加 Cloudflare 账号 account",
              <KeyRoundIcon />,
              "加 Cloudflare 账号",
              () => nav("/settings?add=account"),
            )}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="其他">
            {op(
              "o-up",
              "升级 Wharf upgrade 控制面 agent",
              <ArrowUpCircleIcon />,
              "升级 Wharf",
              actions.upgrade,
            )}
            {op(
              "o-theme",
              "切换主题 深色 浅色 theme",
              theme === "light" ? <MoonIcon /> : <SunIcon />,
              theme === "light" ? "切换到深色" : "切换到浅色",
              toggle,
            )}
            {op(
              "o-out",
              "退出登录 logout",
              <LogOutIcon />,
              "退出登录",
              onLogout,
            )}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
