import { PackageIcon, WrenchIcon, ArrowRightIcon, ArrowRightLeftIcon, ArrowLeftIcon, ArrowUpRightIcon, EllipsisIcon, HammerIcon, HistoryIcon, LockIcon, LockOpenIcon, PencilIcon, PlayIcon, PlusIcon, RefreshCwIcon, RotateCwIcon, SquareIcon, Trash2Icon, XIcon } from "lucide-react";
import { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { ComposeField, MirrorHint, composePorts, parseCompose } from "@/components/compose";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { BuildEditor, type BuildHow, cleanHow, howOf, howReady } from "@/components/build-editor";
import { CodeBlock, CopyButton, Dot, Empty, ErrorNote, Notice, OpenLink, PageHeader, ServerTag, StatusBadge, ago, sourceLabel } from "@/components/common";
import { Field, PortsEditor, formatEnv, parseEnv, portsFor } from "@/components/fields";
import { LogStream } from "@/components/LogStream";
import { MetricsPanel } from "@/components/metrics";
import { Backups } from "./service-backups";
import { Files } from "./service-files";
import { ServiceNote } from "./service-note";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CodeEditor, highlight } from "@/components/code-editor";
import { useStatus } from "@/status";
import { AddRoute } from "@/components/add-route";
import { CodePackageField, type CodePackage } from "@/components/code-package";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { serviceTruth } from "@/components/health";
import type { DataKind, DeploymentView, RouteView, ImportRecord, PortSpec, ServiceStatus, ServiceView } from "@/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const Terminal = lazy(() => import("@/components/Terminal"));

export function ServiceDetail() {
  const { name = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "overview";
  const { status } = useStatus();
  const actions = useActions();
  const { data: svc, error } = usePoll<ServiceView>(`/api/services/${encodeURIComponent(name)}`, 5000);
  const [editing, setEditing] = useState(false);
  const [addingRoute, setAddingRoute] = useState(false);
  const [repacking, setRepacking] = useState(false);

  const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];
  const back = (
    <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground" to="/">
      <ArrowLeftIcon className="size-3.5" />
      首页
    </Link>
  );

  if (error && !svc) {
    return (
      <>
        {back}
        <ErrorNote error={error} />
      </>
    );
  }
  if (!svc) {
    return (
      <>
        {back}
        <Skeleton className="mb-6 h-12 w-64" />
        <div className="grid gap-3 md:grid-cols-[1.4fr_1fr]">
          <Skeleton className="h-44 rounded-xl" />
          <Skeleton className="h-44 rounded-xl" />
        </div>
      </>
    );
  }

  const { tone, text, detail } = serviceTruth(svc, status);
  const source = sourceLabel(svc.spec.source);
  const built = "build" in svc.spec.source;

  return (
    <>
      {back}
      <PageHeader
        title={
          <>
            {svc.name}
            <Tooltip>
              <TooltipTrigger>
                <StatusBadge tone={tone}>{text}</StatusBadge>
              </TooltipTrigger>
              {svc.status && (
                <TooltipContent className="grid gap-0.5">
                  {detail && <div className="font-medium">{detail}</div>}
                  {statusLayers(svc.status).map((l) => (
                    <div key={l}>{l}</div>
                  ))}
                </TooltipContent>
              )}
            </Tooltip>
          </>
        }
        description={
          <div className="grid justify-items-start">
            <span className="flex items-center gap-1.5">
              <span className="font-mono text-xs">{source}</span>· 在 <ServerTag name={svc.spec.server} />
            </span>
            <ServiceNote svc={svc} />
            {status?.updates?.services[name]?.newer && (
              <button type="button" className="text-xs text-primary underline underline-offset-2" onClick={() => actions.plan({ title: `更新 ${name}`, changes: [{ op: "refresh_images", name }] })}>
                有新版本
              </button>
            )}
          </div>
        }
        actions={
          <>
            <Button variant="outline" onClick={() => setEditing(true)}>
              <PencilIcon />
              修改配置
            </Button>
            {svc.spec.stopped ? (
              <Button variant="outline" onClick={() => actions.setStopped(svc, false)}>
                <PlayIcon />
                启动
              </Button>
            ) : (
              <Button variant="outline" onClick={() => actions.restart(name)}>
                <RotateCwIcon />
                重启
              </Button>
            )}
            <DropdownMenu modal={false}>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" aria-label="更多操作">
                  <EllipsisIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                {("image" in svc.spec.source || ("build" in svc.spec.source && !!svc.spec.source.build.git)) && (
                  <DropdownMenuItem onSelect={() => actions.plan({ title: `检查 ${name} 的更新`, changes: [{ op: "refresh_images", name }] })}>
                    <RefreshCwIcon />
                    检查更新
                  </DropdownMenuItem>
                )}
                {"build" in svc.spec.source && !svc.spec.source.build.git && (
                  <DropdownMenuItem onSelect={() => setRepacking(true)}>
                    <PackageIcon />
                    更新代码包
                  </DropdownMenuItem>
                )}
                {built && (
                  <DropdownMenuItem onSelect={() => actions.rebuild(name)}>
                    <HammerIcon />
                    重新构建
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={() => actions.redeploy(svc)}>
                  <WrenchIcon />
                  检查并修复
                </DropdownMenuItem>
                {!svc.spec.stopped && (
                  <DropdownMenuItem onSelect={() => actions.setStopped(svc, true)}>
                    <SquareIcon />
                    停止
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={() => actions.rollback(name)}>
                  <HistoryIcon />
                  回到上一个版本
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => actions.move(svc)}>
                  <ArrowRightLeftIcon />
                  迁移到其他服务器
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => actions.remove(name)}>
                  <Trash2Icon />
                  删除服务
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      <Tabs value={tab} onValueChange={(t) => setParams(t === "overview" ? {} : { tab: t }, { replace: true })}>
        <div className="-mx-1 overflow-x-auto px-1">
          <TabsList>
            <TabsTrigger value="overview">概览</TabsTrigger>
            <TabsTrigger value="domains">域名{routes.length > 0 && <span className="ml-1 text-muted-foreground">{routes.length}</span>}</TabsTrigger>
            <TabsTrigger value="config">配置</TabsTrigger>
            <TabsTrigger value="logs">日志</TabsTrigger>
            <TabsTrigger value="metrics">资源</TabsTrigger>
            <TabsTrigger value="history">版本</TabsTrigger>
            <TabsTrigger value="data">数据与备份</TabsTrigger>
            <TabsTrigger value="files">文件</TabsTrigger>
            <TabsTrigger value="terminal">终端</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="overview" className="mt-4">
          <Overview svc={svc} routes={routes} onTab={(t) => setParams({ tab: t }, { replace: true })} />
        </TabsContent>
        <TabsContent value="domains" className="mt-4">
          <DomainsTab routes={routes} onAdd={() => setAddingRoute(true)} />
        </TabsContent>
        <TabsContent value="config" className="mt-4">
          <ConfigTab svc={svc} onEdit={() => setEditing(true)} />
        </TabsContent>
        <TabsContent value="logs" className="mt-4">
          <LogStream path={`/api/services/${encodeURIComponent(name)}/logs/stream`} />
        </TabsContent>
        <TabsContent value="metrics" className="mt-4">
          <MetricsPanel subject={name} kind="svc" title="" />
        </TabsContent>
        <TabsContent value="history" className="mt-4">
          <History name={name} />
        </TabsContent>
        <TabsContent value="data" className="mt-4">
          <DataTab svc={svc} />
        </TabsContent>
        <TabsContent value="files" className="mt-4">
          <Files name={name} />
        </TabsContent>
        <TabsContent value="terminal" className="mt-4">
          <TerminalTab svc={svc} />
        </TabsContent>
      </Tabs>

      <EditService svc={svc} open={editing} onClose={() => setEditing(false)} />
      {repacking && <Repack svc={svc} onClose={() => setRepacking(false)} />}
      <AddRoute service={name} open={addingRoute} onClose={() => setAddingRoute(false)} />
    </>
  );
}

/** 概览：能不能打开、跑在哪、容器怎么样。细节去各标签。 */
function Overview({ svc, routes, onTab }: { svc: ServiceView; routes: RouteView[]; onTab: (t: string) => void }) {
  const hints: { text: string; action: string; tab: string }[] = [];
  if (routes.length === 0) hints.push({ text: "还没有域名，现在只能从内网访问。", action: "加域名", tab: "domains" });
  if (svc.data?.some((m) => m.kind === "managed") && !svc.spec.backup) hints.push({ text: "有数据，但还没开备份。", action: "开备份", tab: "data" });
  return (
    <div className="grid gap-3">
    {hints.map((h) => (
      <div key={h.tab} className="flex items-center gap-3 rounded-xl border border-dashed px-4 py-2.5 text-sm">
        <span className="flex-1 text-muted-foreground">{h.text}</span>
        <Button size="xs" variant="outline" onClick={() => onTab(h.tab)}>
          {h.action}
          <ArrowRightIcon />
        </Button>
      </div>
    ))}
    <div className="grid gap-3 md:grid-cols-[1.4fr_1fr]">
      <Card className="gap-4 py-5 shadow-xs">
        <CardHeader className="px-5">
          <CardTitle className="text-sm font-medium text-muted-foreground">访问</CardTitle>
        </CardHeader>
        <CardContent className="px-5">
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
            <dt className="text-muted-foreground">域名</dt>
            <dd className="grid min-w-0 gap-1">
              {routes.map((r) => (
                <div key={r.id} className="flex min-w-0 items-center gap-0.5">
                  <a className="inline-flex min-w-0 items-center gap-1 font-mono text-[13px] text-primary hover:underline" href={r.url} target="_blank" rel="noreferrer">
                    {r.spec.auth && <LockIcon className="size-3.5 shrink-0 text-muted-foreground" />}
                    <span className="truncate">{r.url}</span>
                    <ArrowUpRightIcon className="size-3.5 shrink-0" />
                  </a>
                  <CopyButton text={r.url} />
                </div>
              ))}
              {routes.length === 0 && (
                <button type="button" className="w-fit text-left text-muted-foreground hover:text-foreground" onClick={() => onTab("domains")}>
                  只在内网访问 · <span className="text-primary">加域名</span>
                </button>
              )}
            </dd>
            <dt className="text-muted-foreground">内网地址</dt>
            <dd className="font-mono text-[13px]">
              {Object.entries(svc.addresses).map(([p, a]) => (
                <div key={p} className="flex flex-wrap items-center gap-x-3 gap-y-0.5">
                  <span className="text-muted-foreground">{p}</span>
                  <OpenLink value={a} />
                  {(svc.lan_addresses?.[p] ?? []).map((l) => (
                    <span key={l} className="inline-flex items-center gap-1">
                      <span className="font-sans text-xs text-muted-foreground">局域网</span>
                      <OpenLink value={l} />
                    </span>
                  ))}
                </div>
              ))}
              {Object.keys(svc.addresses).length === 0 && "-"}
            </dd>
            <dt className="text-muted-foreground">数据</dt>
            <dd>
              <button type="button" className="text-left hover:underline" onClick={() => onTab("data")}>
                {dataSummary(svc)}
              </button>
            </dd>
          </dl>
        </CardContent>
      </Card>
      <Card className="gap-4 py-5 shadow-xs">
        <CardHeader className="px-5">
          <CardTitle className="text-sm font-medium text-muted-foreground">容器</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2.5 px-5 text-sm">
          {svc.containers?.map((c) => (
            <div key={c.name} className="flex items-center gap-3">
              <span className="w-24 truncate text-muted-foreground">{c.service}</span>
              <Dot tone={c.state === "running" ? "ok" : "bad"} />
              <span>{c.status || c.state}</span>
            </div>
          ))}
          {!svc.containers?.length && <span className="text-muted-foreground">{svc.status?.error ?? "没有容器"}</span>}
        </CardContent>
      </Card>
    </div>
    </div>
  );
}

function dataSummary(svc: ServiceView): string {
  const data = svc.data ?? [];
  if (data.length === 0) return "没有数据卷";
  const outside = data.filter((m) => m.kind !== "managed").length;
  return outside ? `${data.length} 处挂载，${outside} 处不在备份范围` : `${data.length} 处挂载`;
}

function DomainsTab({ routes, onAdd }: { routes: RouteView[]; onAdd: () => void }) {
  const actions = useActions();
  return (
    <div className="grid gap-3">
      {routes.length === 0 ? (
        <Empty>还没有域名，现在只能从内网访问。</Empty>
      ) : (
        <div className="divide-y overflow-hidden rounded-xl border bg-card shadow-xs">
          {routes.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <a className="inline-flex min-w-0 flex-1 items-center gap-1 font-mono text-sm text-primary hover:underline" href={r.url} target="_blank" rel="noreferrer">
                <span className="truncate">{r.url}</span>
                <ArrowUpRightIcon className="size-3.5 shrink-0" />
              </a>
              <span className="text-xs text-muted-foreground">{r.gateway ? `经 ${r.gateway}` : ""}{r.spec.link === "tunnel" ? " · 反向隧道" : ""}</span>
              <Button
                variant="ghost"
                size="xs"
                onClick={() =>
                  actions.plan({
                    title: `${r.spec.auth ? "关闭" : "开启"} ${r.spec.hostname} 的登录保护`,
                    changes: [{ op: "upsert_route", spec: { ...r.spec, auth: !r.spec.auth } }],
                  })
                }
              >
                {r.spec.auth ? <LockIcon /> : <LockOpenIcon />}
                {r.spec.auth ? "已开登录保护" : "开启登录保护"}
              </Button>
              <Button
                variant="ghost"
                size="xs"
                onClick={() => actions.plan({ title: `移除 ${r.spec.hostname}`, changes: [{ op: "remove_route", hostname: r.spec.hostname }] })}
              >
                <XIcon />
                移除
              </Button>
            </div>
          ))}
        </div>
      )}
      <Button variant="outline" className="w-fit" onClick={onAdd}>
        <PlusIcon />
        加域名
      </Button>
    </div>
  );
}

/** 配置：人看得懂的样子；原始 JSON 折叠在下面。 */
function ConfigTab({ svc, onEdit }: { svc: ServiceView; onEdit: () => void }) {
  const env = Object.entries(svc.spec.env ?? {});
  return (
    <div className="grid gap-4">
      <Card className="gap-4 py-5 shadow-xs">
        <CardContent className="px-5">
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
            <dt className="text-muted-foreground">来源</dt>
            <dd className="font-mono text-[13px] break-all">{sourceLabel(svc.spec.source)}</dd>
            <dt className="text-muted-foreground">服务器</dt>
            <dd>
              <ServerTag name={svc.spec.server} />
            </dd>
            <dt className="text-muted-foreground">端口</dt>
            <dd className="font-mono text-[13px]">
              {(svc.spec.ports ?? []).map((p) => (
                <div key={p.name}>
                  {p.name}：{p.container != null ? `容器 ${p.container} → ` : ""}宿主机 {svc.host_ports[p.name] ?? p.host ?? "自动"}
                </div>
              ))}
              {!svc.spec.ports?.length && "-"}
            </dd>
            <dt className="text-muted-foreground">环境变量</dt>
            <dd className="min-w-0 font-mono text-[13px] break-all whitespace-pre-wrap">
              {env.length ? highlight(env.map(([k, v]) => `${k}=${/\[\[.+\]\]/.test(v) ? v : "••••"}`).join("\n"), "env") : "-"}
            </dd>
            {svc.import && (
              <>
                <dt className="text-muted-foreground">导入</dt>
                <dd className="text-xs">{importText(svc.import)}</dd>
              </>
            )}
          </dl>
        </CardContent>
      </Card>
      <Button variant="outline" className="w-fit" onClick={onEdit}>
        <PencilIcon />
        修改配置
      </Button>
      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground">原始配置（JSON）</summary>
        <CodeBlock className="mt-2">{JSON.stringify(svc.spec, null, 2)}</CodeBlock>
      </details>
    </div>
  );
}

function DataTab({ svc }: { svc: ServiceView }) {
  return (
    <div className="grid gap-6">
      <div>
        <h3 className="mb-2 text-sm font-medium text-muted-foreground">挂载</h3>
        {!svc.data?.length ? (
          <Empty>这个服务没有数据卷</Empty>
        ) : (
          <div className="divide-y overflow-hidden rounded-xl border bg-card shadow-xs">
            {svc.data.map((m, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 px-4 py-2.5 font-mono text-xs">
                <span>{m.source || "匿名卷"}</span>
                <span className="text-muted-foreground">→ {m.target}</span>
                <Badge variant={m.kind === "managed" ? "secondary" : "outline"} className={m.kind === "managed" ? "ml-auto font-normal" : "ml-auto border-warning/50 font-normal text-warning"}>
                  {DATA_KIND[m.kind]}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </div>
      <div>
        <h3 className="mb-2 text-sm font-medium text-muted-foreground">备份</h3>
        <Backups svc={svc} />
      </div>
    </div>
  );
}

/** 代码包来源的服务：重新打包服务器目录（记得上次的目录），或上传新的 zip，然后预览改动。 */
function Repack({ svc, onClose }: { svc: ServiceView; onClose: () => void }) {
  const actions = useActions();
  // undefined：还在读；null：没有记录（之前是上传的 zip 或 CLI 部署的）。
  const [origin, setOrigin] = useState<{ server: string; path: string } | null | undefined>(undefined);
  useEffect(() => {
    api
      .get<{ server: string; path: string } | null>(`/api/services/${encodeURIComponent(svc.name)}/origin`)
      .then(setOrigin)
      .catch(() => setOrigin(null));
  }, [svc.name]);
  const [pkg, setPkg] = useState<CodePackage | null>(null);
  const loaded = origin !== undefined;
  const submit = () => {
    if (!pkg || !("build" in svc.spec.source)) return;
    onClose();
    actions.plan({
      title: `更新 ${svc.name} 的代码`,
      changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, source: { build: { ...svc.spec.source.build, upload: pkg.sha256 } } } }],
    });
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>更新 {svc.name} 的代码包</DialogTitle>
        </DialogHeader>
        {loaded ? <CodePackageField value={pkg} onChange={setPkg} service={svc.name} initial={origin} /> : <Skeleton className="h-32 rounded-lg" />}
        {pkg && "build" in svc.spec.source && pkg.sha256 === svc.spec.source.build.upload && <Notice>代码没有变化。</Notice>}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!pkg || ("build" in svc.spec.source && pkg.sha256 === svc.spec.source.build.upload)} onClick={submit}>
            预览改动
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function History({ name }: { name: string }) {
  const { data } = usePoll<DeploymentView[]>(`/api/services/${encodeURIComponent(name)}/deployments`, 15000);
  const actions = useActions();
  if (!data) return <Skeleton className="h-40 rounded-xl" />;
  if (data.length === 0) return <Empty>没有部署记录</Empty>;
  return (
    <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
      <Table>
        <TableHeader className="bg-muted/50">
          <TableRow>
            <TableHead className="pl-4">#</TableHead>
            <TableHead>时间</TableHead>
            <TableHead>服务器</TableHead>
            <TableHead>版本</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((d, i) => (
            <TableRow key={d.id}>
              <TableCell className="pl-4 font-mono text-xs">#{d.id}</TableCell>
              <TableCell>
                <span title={new Date(d.created_at).toLocaleString("zh-CN")}>{ago(d.created_at)}</span>
              </TableCell>
              <TableCell>
                <ServerTag name={d.server} />
              </TableCell>
              <TableCell className="max-w-md truncate font-mono text-xs text-muted-foreground" title={[d.commit, ...d.images.map((im) => im.digest ?? im.image)].filter(Boolean).join(" ")}>
                {d.commit && <span className="mr-2 text-foreground">{d.commit.slice(0, 12)}</span>}
                {d.images.map((im) => im.digest ?? im.image).join(" ")}
              </TableCell>
              <TableCell className="pr-4 text-right">
                {i === 0 ? (
                  <Badge variant="secondary">当前版本</Badge>
                ) : d.hash === data[0].hash ? (
                  <span className="text-xs text-muted-foreground">和当前相同</span>
                ) : (
                  <Button variant="outline" size="xs" disabled={!d.spec} title={d.spec ? "" : "这条记录太早，没有保存当时的配置"} onClick={() => actions.rollback(name, d.id)}>
                    <HistoryIcon />
                    回滚到这里
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function EditService({ svc, open, onClose }: { svc: ServiceView; open: boolean; onClose: () => void }) {
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        <SheetHeader className="border-b">
          <SheetTitle>修改 {svc.name}</SheetTitle>
        </SheetHeader>
        {open && <EditForm svc={svc} onClose={onClose} />}
      </SheetContent>
    </Sheet>
  );
}

const ACTUAL: Record<ServiceStatus["actual"], string> = { running: "运行中", partial: "部分运行", stopped: "已停止", missing: "没有容器", offline: "服务器离线", unknown: "查不到" };
const HEALTH: Record<ServiceStatus["health"], string> = { healthy: "健康", unhealthy: "不健康", starting: "启动中", none: "没配健康检查" };
const OP: Record<NonNullable<ServiceStatus["last_op"]>["status"], string> = { running: "进行中", succeeded: "成功", failed: "失败" };

/** 悬停时显示每一层。 */
function statusLayers(s: ServiceStatus): string[] {
  const short = (h?: string) => h?.slice(0, 8) ?? "-";
  const op = s.last_op;
  return [
    `期望：${s.want_running ? "运行" : "停止"} · ${short(s.desired_hash)}`,
    `已应用：${s.applied ? `${short(s.applied.hash)} · ${ago(s.applied.at)}` : "没有部署记录"}`,
    `实际：${ACTUAL[s.actual]}${s.actual_hash ? ` · ${short(s.actual_hash)}` : ""}${s.observed_at ? ` · ${ago(s.observed_at)}看到` : ""}`,
    `健康：${HEALTH[s.health]}`,
    `执行：${op ? `${op.action}${OP[op.status]} · ${ago(op.at)}${op.error ? ` · ${op.error}` : ""}` : "-"}`,
  ];
}

function importText(r: ImportRecord): string {
  const from = [r.project && `compose 项目 ${r.project}`, ...(r.containers ?? []).map((c) => `容器 ${c}`)].filter(Boolean).join("、") || "同名 compose 项目";
  if (!r.done_at) return `${from} · 第一次部署时接管`;
  const retired = r.retired?.length ? ` · 旧容器 ${r.retired.join("、")} 已停止` : "";
  return `${from} · ${ago(r.done_at)}${retired}`;
}

const DATA_KIND: Record<DataKind, string> = { managed: "Wharf 管理", external_dir: "外部目录", named_volume: "docker 卷" };

function EditForm({ svc, onClose }: { svc: ServiceView; onClose: () => void }) {
  const actions = useActions();
  const src = svc.spec.source;
  const isImage = "image" in src;
  const isCompose = "compose" in src;
  const build = "build" in src ? src.build : null;
  const [image, setImage] = useState(isImage ? src.image : "");
  const [compose, setCompose] = useState("compose" in src ? (src.compose.content ?? "") : "");
  const [repo, setRepo] = useState(build?.git?.repo ?? "");
  const [gitRef, setGitRef] = useState(build?.git?.ref ?? "");
  const [how, setHow] = useState<BuildHow>(howOf(build));
  const composeInfo = useMemo(() => parseCompose(compose), [compose]);
  // 原来没填端口的 compose 服务，按 compose 内容自动填；手动改过端口后不再覆盖。
  const [portsTouched, setPortsTouched] = useState(!!svc.spec.ports?.length);
  const [ports, setPorts] = useState<PortSpec[]>(() => (isCompose && !svc.spec.ports?.length ? composePorts(parseCompose(compose)) : (svc.spec.ports ?? [])));
  const { status } = useStatus();
  const onCompose = (text: string) => {
    setCompose(text);
    if (!portsTouched) setPorts(composePorts(parseCompose(text)));
  };
  const [envText, setEnvText] = useState(formatEnv(svc.spec.env));
  const submit = () => {
    const spec = {
      ...svc.spec,
      source: isImage
        ? { image: image.trim() }
        : build
          ? {
              build: {
                upload: build.upload,
                git: build.git ? { ...build.git, repo: repo.trim(), ref: gitRef.trim() } : undefined,
                path: build.path,
                ...cleanHow(how),
              },
            }
          : { compose: { content: compose } },
      ports: portsFor(ports, isCompose),
      env: isImage || build ? parseEnv(envText) : svc.spec.env,
    };
    onClose();
    actions.plan({ title: `修改 ${svc.name}`, changes: [{ op: "upsert_service", name: svc.name, spec }] });
  };
  return (
    <>
      <div className="grid flex-1 content-start gap-5 overflow-auto p-4">
        {build ? (
          build.git ? (
            <div className="grid grid-cols-[minmax(0,1fr)_8rem] gap-3">
              <Field label="仓库" htmlFor="repo">
                <Input id="repo" value={repo} onChange={(e) => setRepo(e.target.value)} />
              </Field>
              <Field label="分支 / 标签" htmlFor="ref">
                <Input id="ref" value={gitRef} onChange={(e) => setGitRef(e.target.value)} />
              </Field>
            </div>
          ) : (
            <Notice kind="info">代码来自本机目录</Notice>
          )
        ) : isImage ? (
          <Field label="镜像" htmlFor="image">
            <Input id="image" value={image} onChange={(e) => setImage(e.target.value)} />
          </Field>
        ) : (
          <Field label="compose.yaml" htmlFor="compose">
            <ComposeField id="compose" value={compose} onChange={onCompose} info={composeInfo} />
          </Field>
        )}
        {(isImage || isCompose) && (
          <MirrorHint server={status?.servers.find((s) => s.name === svc.spec.server)} images={isImage ? [image] : composeInfo.images} />
        )}
        {build && <BuildEditor value={how} onChange={setHow} />}
        <Field label="端口">
          <PortsEditor
            ports={ports}
            onChange={(p) => {
              setPortsTouched(true);
              setPorts(p);
            }}
            compose={isCompose}
          />
        </Field>
        {(isImage || build) && (
          <Field label="环境变量" htmlFor="env">
            <CodeEditor id="env" lang="env" secrets className="min-h-32" placeholder={"KEY=value\nTOKEN=[[MY_SECRET]]"} value={envText} onChange={setEnvText} />
          </Field>
        )}
      </div>
      <SheetFooter className="flex-row justify-end border-t">
        <Button variant="ghost" onClick={onClose}>
          取消
        </Button>
        <Button disabled={!howReady(how)} onClick={submit}>
          生成计划
        </Button>
      </SheetFooter>
    </>
  );
}

/** 只有打开这个标签时才连接；多个容器时可以选。 */
function TerminalTab({ svc }: { svc: ServiceView }) {
  const running = [...new Set((svc.containers ?? []).filter((c) => c.state === "running").map((c) => c.service))];
  const [service, setService] = useState<string | undefined>(undefined);
  if (running.length === 0) return <Empty>没有在运行的容器</Empty>;
  const current = service && running.includes(service) ? service : running[0];
  return (
    <div className="grid gap-2">
      {running.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {running.map((s) => (
            <Button key={s} size="xs" variant={s === current ? "secondary" : "ghost"} onClick={() => setService(s)}>
              {s}
            </Button>
          ))}
        </div>
      )}
      <Suspense fallback={<Skeleton className="h-80 rounded-xl" />}>
        <Terminal name={svc.name} service={current} />
      </Suspense>
    </div>
  );
}
