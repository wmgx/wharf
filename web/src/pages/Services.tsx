import { ArrowRightLeftIcon, EllipsisIcon, HistoryIcon, PlusIcon, RefreshCwIcon, ScrollTextIcon, Trash2Icon } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useActions } from "@/components/actions";
import { Empty, PageHeader, ServerTag, StatusBadge, imageOf, liveTone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { ServiceView } from "@/types";
import { UnmanagedList } from "./containers";
import { EdgeList } from "./edge";
import { NewService } from "./NewService";

export function Services() {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const creating = params.get("new") === "1";
  const routesOf = (name: string) => status?.routes.filter((r) => r.spec.service === name) ?? [];

  return (
    <>
      <PageHeader
        title="服务"
        actions={
          <Button onClick={() => setParams({ new: "1" })}>
            <PlusIcon />
            新建服务
          </Button>
        }
      />
      {!status ? (
        <Skeleton className="h-48 rounded-xl" />
      ) : status.services.length === 0 ? (
        !status.edge_apps?.length && <Empty>还没有服务</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
          <Table>
            <TableHeader className="bg-muted/50">
              <TableRow>
                <TableHead className="pl-4">服务</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>服务器</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>域名</TableHead>
                <TableHead>内网地址</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {status.services.map((s) => {
                const { tone, text } = liveTone(s.live);
                const routes = routesOf(s.name);
                return (
                  <TableRow key={s.name} className="cursor-pointer" onClick={() => nav(`/services/${s.name}`)}>
                    <TableCell className="pl-4 font-medium">{s.name}</TableCell>
                    <TableCell>
                      <StatusBadge tone={tone}>{text}</StatusBadge>
                    </TableCell>
                    <TableCell>
                      <ServerTag name={s.spec.server} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{imageOf(s)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {routes.map((r) => (
                        <div key={r.id}>{r.spec.hostname}</div>
                      ))}
                      {routes.length === 0 && <span className="text-muted-foreground">-</span>}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{Object.values(s.addresses).join(" ")}</TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <RowMenu svc={s} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      <UnmanagedList />
      <EdgeList />
      <NewService
        open={creating}
        onClose={() => {
          setParams({});
          refresh();
        }}
      />
    </>
  );
}

function RowMenu({ svc }: { svc: ServiceView }) {
  const actions = useActions();
  const nav = useNavigate();
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={`${svc.name} 的操作`}>
          <EllipsisIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuItem onSelect={() => nav(`/services/${svc.name}?tab=logs`)}>
          <ScrollTextIcon />
          看日志
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => actions.redeploy(svc)}>
          <RefreshCwIcon />
          重新部署
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => actions.rollback(svc.name)}>
          <HistoryIcon />
          回滚到上一个版本
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => actions.move(svc)}>
          <ArrowRightLeftIcon />
          迁移到其他服务器
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onSelect={() => actions.remove(svc.name)}>
          <Trash2Icon />
          删除
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
