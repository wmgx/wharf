import { BoxIcon, CloudIcon, DownloadIcon, GlobeIcon, KeyRoundIcon, PlusIcon, ServerIcon, WaypointsIcon } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AddRoute } from "@/components/add-route";
import { AddServer } from "@/components/add-server";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useStatus } from "@/status";

/** 顶栏的"新建"：按"我要做什么"列出所有新建入口，任何页面都能直接开始。 */
export function NewMenu() {
  const nav = useNavigate();
  const { status } = useStatus();
  const [route, setRoute] = useState(false);
  const [server, setServer] = useState(false);
  const hasServices = !!status?.services.length;

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button size="sm" className="h-8">
            <PlusIcon />
            <span className="hidden sm:inline">新建</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuLabel className="text-xs text-muted-foreground">放东西上去</DropdownMenuLabel>
          <DropdownMenuItem onSelect={() => nav("/?new=1")}>
            <BoxIcon />
            部署服务
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => nav("/?import=1")}>
            <DownloadIcon />
            导入服务器上已有的容器
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => nav("/?edge=1")}>
            <CloudIcon />
            导入 Cloudflare Workers / Pages
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-xs text-muted-foreground">让人能打开</DropdownMenuLabel>
          <DropdownMenuItem disabled={!hasServices} onSelect={() => setRoute(true)}>
            <GlobeIcon />
            加域名
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => nav("/servers?tab=entries&new=1")}>
            <WaypointsIcon />
            新建入口
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-xs text-muted-foreground">基础设施</DropdownMenuLabel>
          <DropdownMenuItem onSelect={() => setServer(true)}>
            <ServerIcon />
            加服务器
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => nav("/settings?add=account")}>
            <KeyRoundIcon />
            加 Cloudflare 账号
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <AddRoute open={route} onClose={() => setRoute(false)} />
      <AddServer open={server} onClose={() => setServer(false)} />
    </>
  );
}
