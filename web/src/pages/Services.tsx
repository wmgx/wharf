import { ArrowRightLeftIcon, CloudIcon, EllipsisIcon, HardDriveIcon, NetworkIcon, HistoryIcon, PlayIcon, PlusIcon, RefreshCwIcon, RotateCwIcon, ScrollTextIcon, SquareIcon, Trash2Icon } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useActions } from "@/components/actions";
import { Empty, PageHeader, ServerTag, StatusBadge, imageOf, serviceTone, type Tone } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { ServiceView, Status } from "@/types";
import { UnmanagedList } from "./containers";
import { EdgeList, KIND_NAME, edgeSourceLabel, edgeTone } from "./edge";
import { NewService } from "./NewService";

/** 列表里的一行：服务器上的服务和 Cloudflare 上的边缘应用放在一起。 */
interface Row {
  name: string;
  to: string;
  kind: string;
  where: string;
  source: string;
  domains: string[];
  tone: Tone;
  text: string;
  svc?: ServiceView;
}

function rowsOf(status: Status): Row[] {
  const routes = (name: string) => status.routes.filter((r) => r.spec.service === name).map((r) => r.spec.hostname);
  const services: Row[] = status.services.map((s) => {
    const { tone, text } = serviceTone(s);
    return { name: s.name, to: `/services/${s.name}`, kind: "服务器", where: s.spec.server, source: imageOf(s), domains: routes(s.name), tone, text, svc: s };
  });
  const edge: Row[] = (status.edge_apps ?? []).map((a) => {
    const { tone, text } = edgeTone(a.live, a.drift);
    const domains = a.spec.domains?.length ? a.spec.domains : a.live?.url ? [a.live.url.replace(/^https:\/\//, "")] : [];
    return { name: a.name, to: `/edge/${a.name}`, kind: "Cloudflare", where: KIND_NAME[a.spec.kind], source: edgeSourceLabel(a.spec.source), domains, tone, text };
  });
  return [...services, ...edge].sort((x, y) => x.name.localeCompare(y.name));
}

export function Services() {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const creating = params.get("new") === "1";
  const rows = status ? rowsOf(status) : [];

  return (
    <>
      <PageHeader
        title="服务"
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => nav("/topology")}>
              <NetworkIcon />
              拓扑
            </Button>
            <Button variant="ghost" size="sm" onClick={() => nav("/data")}>
              <HardDriveIcon />
              数据
            </Button>
            <Button onClick={() => setParams({ new: "1" })}>
              <PlusIcon />
              新建服务
            </Button>
          </>
        }
      />
      {!status ? (
        <Skeleton className="h-40 rounded-xl" />
      ) : rows.length === 0 ? (
        <Empty>还没有服务。点右上角"新建服务"，从镜像、git 仓库或 compose 部署第一个。</Empty>
      ) : (
        <>
          <div className="hidden overflow-hidden rounded-xl border bg-card shadow-xs md:block">
            <Table>
              <TableHeader className="bg-muted/50">
                <TableRow>
                  <TableHead className="pl-4">服务</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>运行在</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>域名</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.to} className="cursor-pointer" onClick={() => nav(r.to)}>
                    <TableCell className="pl-4 font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        {!r.svc && <CloudIcon className="size-3.5 text-muted-foreground" />}
                        {r.name}
                      </span>
                    </TableCell>
                    <TableCell>
                      <StatusBadge tone={r.tone}>{r.text}</StatusBadge>
                    </TableCell>
                    <TableCell>{r.svc ? <ServerTag name={r.where} /> : <Badge variant="secondary">{`Cloudflare ${r.where}`}</Badge>}</TableCell>
                    <TableCell className="max-w-64 truncate font-mono text-xs text-muted-foreground">{r.source}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.domains.map((d) => (
                        <div key={d}>{d}</div>
                      ))}
                      {r.domains.length === 0 && <span className="text-muted-foreground">-</span>}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>{r.svc && <RowMenu svc={r.svc} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="grid gap-2 md:hidden">
            {rows.map((r) => (
              <div key={r.to} className="flex items-start gap-2 rounded-xl border bg-card p-3 shadow-xs" onClick={() => nav(r.to)}>
                <div className="grid min-w-0 flex-1 gap-1.5">
                  <div className="flex items-center gap-1.5 font-medium">
                    {!r.svc && <CloudIcon className="size-3.5 text-muted-foreground" />}
                    {r.name}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                    <StatusBadge tone={r.tone}>{r.text}</StatusBadge>
                    {r.svc ? <ServerTag name={r.where} /> : <span>{`Cloudflare ${r.where}`}</span>}
                  </div>
                  {r.domains.length > 0 && <div className="truncate font-mono text-xs text-muted-foreground">{r.domains.join(" · ")}</div>}
                </div>
                <div onClick={(e) => e.stopPropagation()}>{r.svc && <RowMenu svc={r.svc} />}</div>
              </div>
            ))}
          </div>
        </>
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
        {svc.spec.stopped ? (
          <DropdownMenuItem onSelect={() => actions.setStopped(svc, false)}>
            <PlayIcon />
            启动
          </DropdownMenuItem>
        ) : (
          <>
            <DropdownMenuItem onSelect={() => actions.restart(svc.name)}>
              <RotateCwIcon />
              重启
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => actions.setStopped(svc, true)}>
              <SquareIcon />
              停止
            </DropdownMenuItem>
          </>
        )}
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
