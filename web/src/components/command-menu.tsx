import { AnchorIcon, ArrowRightLeftIcon, BoxIcon, BoxesIcon, CloudIcon, HistoryIcon, LogOutIcon, MoonIcon, NetworkIcon, PlusIcon, RefreshCwIcon, ScrollTextIcon, SearchIcon, SunIcon, Trash2Icon, WaypointsIcon } from "lucide-react";
import { useEffect, useState } from "react";
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
import { Dot, liveTone } from "./common";

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
  // 针对每个服务的操作比较多，输入了内容再列出来，默认界面保持简洁。
  const showOps = search.trim().length > 0;

  return (
    <>
      <Button variant="outline" className="h-8 w-full max-w-64 justify-start gap-2 px-2.5 font-normal text-muted-foreground" onClick={() => setOpen(true)}>
        <SearchIcon />
        <span className="flex-1 text-left">搜索或执行操作…</span>
        <Kbd>{isMac ? "⌘" : "Ctrl"} K</Kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen} title="命令面板" description="搜索服务、网关，或直接执行操作">
        <CommandInput placeholder="输入服务名、页面或操作，例如「回滚 hello」" value={search} onValueChange={setSearch} />
        <CommandList>
          <CommandEmpty>没有匹配的结果</CommandEmpty>
          <CommandGroup heading="页面">
            <CommandItem onSelect={() => run(() => nav("/"))}>
              <AnchorIcon />
              港口
            </CommandItem>
            <CommandItem onSelect={() => run(() => nav("/services"))}>
              <BoxesIcon />
              服务
            </CommandItem>
            <CommandItem onSelect={() => run(() => nav("/gateways"))}>
              <WaypointsIcon />
              网关
            </CommandItem>
            <CommandItem value="厂商账号 accounts cloudflare" onSelect={() => run(() => nav("/accounts"))}>
              <CloudIcon />
              厂商账号
            </CommandItem>
            <CommandItem onSelect={() => run(() => nav("/topology"))}>
              <NetworkIcon />
              拓扑
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
                  <Dot tone={liveTone(s.live).tone} />
                </CommandShortcut>
              </CommandItem>
            ))}
            {status?.gateways.map((g) => (
              <CommandItem key={g.name} value={`网关 ${g.name} ${g.spec.server}`} onSelect={() => run(() => nav(`/gateways?open=${g.name}`))}>
                <WaypointsIcon />
                {g.name}
                <span className="text-xs text-muted-foreground">网关 · {g.spec.server}</span>
              </CommandItem>
            ))}
          </CommandGroup>
          {showOps && (
            <>
              <CommandSeparator />
              <CommandGroup heading="操作">
                {services.flatMap((s) => [
                  <CommandItem key={`logs-${s.name}`} value={`日志 看 logs ${s.name}`} onSelect={() => run(() => nav(`/services/${s.name}?tab=logs`))}>
                    <ScrollTextIcon />
                    看 {s.name} 的日志
                  </CommandItem>,
                  <CommandItem key={`redeploy-${s.name}`} value={`重新部署 修复 deploy ${s.name}`} onSelect={() => run(() => actions.redeploy(s))}>
                    <RefreshCwIcon />
                    重新部署 {s.name}
                  </CommandItem>,
                  <CommandItem key={`rollback-${s.name}`} value={`回滚 rollback ${s.name}`} onSelect={() => run(() => actions.rollback(s.name))}>
                    <HistoryIcon />
                    回滚 {s.name} 到上一个版本
                  </CommandItem>,
                  <CommandItem key={`move-${s.name}`} value={`迁移 move ${s.name}`} onSelect={() => run(() => actions.move(s))}>
                    <ArrowRightLeftIcon />
                    迁移 {s.name} 到其他服务器
                  </CommandItem>,
                  <CommandItem key={`rm-${s.name}`} value={`删除 remove ${s.name}`} onSelect={() => run(() => actions.remove(s.name))}>
                    <Trash2Icon />
                    删除 {s.name}
                  </CommandItem>,
                ])}
              </CommandGroup>
            </>
          )}
          <CommandSeparator />
          <CommandGroup heading="其他">
            <CommandItem value="新建服务 部署 new" onSelect={() => run(() => nav("/services?new=1"))}>
              <PlusIcon />
              新建服务
            </CommandItem>
            <CommandItem value="新建网关 new gateway" onSelect={() => run(() => nav("/gateways?new=1"))}>
              <PlusIcon />
              新建网关
            </CommandItem>
            <CommandItem value="切换主题 深色 浅色 theme" onSelect={() => run(toggle)}>
              {theme === "light" ? <MoonIcon /> : <SunIcon />}
              {theme === "light" ? "切换到深色" : "切换到浅色"}
            </CommandItem>
            <CommandItem value="退出登录 logout" onSelect={() => run(onLogout)}>
              <LogOutIcon />
              退出登录
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}
