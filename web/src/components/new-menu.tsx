import { TimerIcon, CornerDownRightIcon, BoxIcon, CloudIcon, DownloadIcon, GlobeIcon, KeyRoundIcon, PlusIcon, ServerIcon, WaypointsIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useStatus } from "@/status";

export const NEW_ITEMS = [
  { label: "部署服务", path: "/services?new=1", icon: BoxIcon },
  { label: "导入服务器上已有的容器", path: "/services?import=1", icon: DownloadIcon },
  { label: "导入 Cloudflare Workers / Pages", path: "/services?edge=1", icon: CloudIcon },
  { label: "加域名", path: "/domains?add=1", icon: GlobeIcon, needsService: true },
  { label: "加跳转", path: "/domains?redirect=1", icon: CornerDownRightIcon },
  { label: "新建入口", path: "/domains?tab=entries&new=1", icon: WaypointsIcon },
  { label: "新建任务", path: "/tasks?new=1", icon: TimerIcon },
  { label: "加服务器", path: "/servers?add=1", icon: ServerIcon },
  { label: "加 Cloudflare 账号", path: "/settings?add=account", icon: KeyRoundIcon },
];

/** 顶栏的"新建"：按"我要做什么"列出所有新建入口，任何页面都能直接开始。 */
export function NewMenu() {
  const nav = useNavigate();
  const { status } = useStatus();
  return <DropdownMenu modal={false}>
    <DropdownMenuTrigger asChild><Button size="sm" className="h-8"><PlusIcon /><span className="hidden sm:inline">新建</span></Button></DropdownMenuTrigger>
    <DropdownMenuContent align="end" className="w-60">
      {NEW_ITEMS.map((item) => <DropdownMenuItem key={item.path} disabled={item.needsService && !status?.services.length} onSelect={() => nav(item.path)}><item.icon />{item.label}</DropdownMenuItem>)}
    </DropdownMenuContent>
  </DropdownMenu>;
}
