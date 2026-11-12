import {
  ArrowRightLeftIcon, ArrowUpCircleIcon, EllipsisIcon, HammerIcon, HistoryIcon, PackageIcon,
  PlayIcon, RefreshCwIcon, RotateCwIcon, ScrollTextIcon, SquareIcon, TerminalIcon, Trash2Icon,
  WrenchIcon, type LucideIcon,
} from "lucide-react";
import { useNavigate, type NavigateFunction } from "react-router-dom";
import { Tip } from "@/components/kit";
import { useActions, type Actions } from "@/components/actions";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useStatus } from "@/status";
import type { ServerView, ServiceView, Status } from "@/types";

export interface OpCtx {
  actions: Actions;
  nav: NavigateFunction;
  status: Status | null;
}

export interface Op<T> {
  id: string;
  label: string;
  icon: LucideIcon;
  keywords?: string;
  group: "main" | "more" | "danger";
  show?: (t: T, ctx: OpCtx) => boolean;
  run: (t: T, ctx: OpCtx) => void;
}

export function useOpCtx(): OpCtx {
  return { actions: useActions(), nav: useNavigate(), status: useStatus().status };
}

export const serviceOps: Op<ServiceView>[] = [
  { id: "update", label: "更新", icon: ArrowUpCircleIcon, keywords: "更新 升级 update", group: "main", show: (s, c) => !!c.status?.updates?.services[s.name]?.newer, run: (s, c) => c.actions.plan({ title: `更新 ${s.name}`, changes: [{ op: "refresh_images", name: s.name }] }) },
  { id: "start", label: "启动", icon: PlayIcon, keywords: "启动 start", group: "main", show: (s) => !!s.spec.stopped, run: (s, c) => c.actions.setStopped(s, false) },
  { id: "restart", label: "重启", icon: RotateCwIcon, keywords: "重启 restart", group: "main", show: (s) => !s.spec.stopped, run: (s, c) => c.actions.restart(s.name) },
  { id: "logs", label: "看日志", icon: ScrollTextIcon, keywords: "日志 logs", group: "more", run: (s, c) => c.nav(`/services/${encodeURIComponent(s.name)}?tab=logs`) },
  { id: "check-update", label: "检查更新", icon: RefreshCwIcon, keywords: "更新 升级 update", group: "more", show: (s, c) => !c.status?.updates?.services[s.name]?.newer && ("image" in s.spec.source || ("build" in s.spec.source && !!s.spec.source.build.git)), run: (s, c) => c.actions.plan({ title: `检查 ${s.name} 的更新`, changes: [{ op: "refresh_images", name: s.name }] }) },
  { id: "repack", label: "更新代码包", icon: PackageIcon, keywords: "代码包 上传", group: "more", show: (s) => "build" in s.spec.source && !s.spec.source.build.git, run: (s, c) => c.nav(`/services/${encodeURIComponent(s.name)}?repack=1`) },
  { id: "rebuild", label: "重新构建", icon: HammerIcon, keywords: "构建 build", group: "more", show: (s) => "build" in s.spec.source, run: (s, c) => c.actions.rebuild(s.name) },
  { id: "redeploy", label: "重新部署", icon: WrenchIcon, keywords: "重新部署 修复 redeploy", group: "more", run: (s, c) => c.actions.redeploy(s) },
  { id: "rollback", label: "回到上一个版本", icon: HistoryIcon, keywords: "回滚 回退 rollback", group: "more", run: (s, c) => c.actions.rollback(s.name) },
  { id: "stop", label: "停止", icon: SquareIcon, keywords: "停止 stop", group: "more", show: (s) => !s.spec.stopped, run: (s, c) => c.actions.setStopped(s, true) },
  { id: "move", label: "迁移到其他服务器", icon: ArrowRightLeftIcon, keywords: "迁移 move", group: "more", run: (s, c) => c.actions.move(s) },
  { id: "remove", label: "删除服务", icon: Trash2Icon, keywords: "删除 remove rm", group: "danger", run: (s, c) => c.actions.remove(s.name) },
];

export const serverOps: Op<ServerView>[] = [
  { id: "upgrade-agent", label: "升级 agent", icon: ArrowUpCircleIcon, group: "main", show: (s) => !!s.agent_outdated, run: (s, c) => c.actions.upgradeAgent(s.name) },
  { id: "terminal", label: "打开终端", icon: TerminalIcon, group: "more", show: (s) => !!s.settings.host_terminal && s.online, run: (s, c) => c.nav(`/servers/${encodeURIComponent(s.name)}?tab=terminal`) },
  { id: "prune", label: "清理没在用的镜像", icon: Trash2Icon, group: "more", show: (s) => s.online, run: (s, c) => c.actions.prune(s.name) },
];

export function OpMenu<T>({ ops, target, label, size = "icon" }: { ops: Op<T>[]; target: T; label: string; size?: "icon" | "icon-sm" }) {
  const ctx = useOpCtx();
  const visible = ops.filter((op) => !op.show || op.show(target, ctx));
  const regular = visible.filter((op) => op.group !== "danger");
  const danger = visible.filter((op) => op.group === "danger");
  if (!visible.length) return null;
  return (
    <DropdownMenu modal={false}>
      <Tip text={label}><DropdownMenuTrigger asChild><Button variant="outline" size={size} aria-label={label}><EllipsisIcon /></Button></DropdownMenuTrigger></Tip>
      <DropdownMenuContent align="end">
        {regular.map((op) => <DropdownMenuItem key={op.id} onSelect={() => op.run(target, ctx)}><op.icon />{op.label}</DropdownMenuItem>)}
        {regular.length > 0 && danger.length > 0 && <DropdownMenuSeparator />}
        {danger.map((op) => <DropdownMenuItem key={op.id} variant="destructive" onSelect={() => op.run(target, ctx)}><op.icon />{op.label}</DropdownMenuItem>)}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function OpBar<T>({ ops, target, label }: { ops: Op<T>[]; target: T; label: string }) {
  const ctx = useOpCtx();
  const main = ops.filter((op) => op.group === "main" && (!op.show || op.show(target, ctx)));
  return (
    <>
      {main.map((op, i) => <Button key={op.id} variant={i === 0 ? "default" : "outline"} onClick={() => op.run(target, ctx)}><op.icon />{op.label}</Button>)}
      <OpMenu ops={ops.filter((op) => op.group !== "main")} target={target} label={label} />
    </>
  );
}
