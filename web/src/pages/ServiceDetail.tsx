import { ArrowRightLeftIcon, ArrowLeftIcon, ArrowUpRightIcon, EllipsisIcon, HammerIcon, HistoryIcon, LockIcon, LockOpenIcon, PencilIcon, PlayIcon, PlusIcon, RefreshCwIcon, RotateCwIcon, SquareIcon, Trash2Icon, XIcon } from "lucide-react";
import { Suspense, lazy, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { useBasicAuthSetAt } from "@/components/basic-auth";
import { BuildEditor, type BuildHow, cleanHow, howOf, howReady } from "@/components/build-editor";
import { Checkbox } from "@/components/ui/checkbox";
import { CodeBlock, Dot, Empty, ErrorNote, Notice, PageHeader, ServerTag, StatusBadge, ago, serviceTone, sourceLabel } from "@/components/common";
import { EntryField, useEntry } from "@/components/entry";
import { DomainChips, Field, PortsEditor, formatEnv, parseEnv, portsFor } from "@/components/fields";
import { LogStream } from "@/components/LogStream";
import { MetricsPanel } from "@/components/metrics";
import { Backups } from "./service-backups";
import { Files } from "./service-files";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { DataKind, DeploymentView, ImportRecord, PortSpec, ServiceStatus, ServiceView } from "@/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const Terminal = lazy(() => import("@/components/Terminal"));

export function ServiceDetail() {
  const { name = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "logs";
  const { status } = useStatus();
  const actions = useActions();
  const { data: svc, error } = usePoll<ServiceView>(`/api/services/${encodeURIComponent(name)}`, 5000);
  const [editing, setEditing] = useState(false);
  const [addingRoute, setAddingRoute] = useState(false);

  const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];
  const back = (
    <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground" to="/services">
      <ArrowLeftIcon className="size-3.5" />
      服务
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

  const { tone, text } = serviceTone(svc);
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
              {svc.status && <TooltipContent className="grid gap-0.5">{statusLayers(svc.status).map((l) => <div key={l}>{l}</div>)}</TooltipContent>}
            </Tooltip>
          </>
        }
        description={
          <span className="flex items-center gap-1.5">
            <span className="font-mono text-xs">{source}</span>· 在 <ServerTag name={svc.spec.server} />
          </span>
        }
        actions={
          <>
            <Button variant="outline" onClick={() => setEditing(true)}>
              <PencilIcon />
              修改配置
            </Button>
            {("image" in svc.spec.source || ("build" in svc.spec.source && !!svc.spec.source.build.git)) && (
              <Button variant="outline" onClick={() => actions.plan({ title: `检查 ${name} 的更新`, changes: [{ op: "refresh_images", name }] })}>
                <RefreshCwIcon />
                检查更新
              </Button>
            )}
            {built && (
              <Button variant="outline" onClick={() => actions.rebuild(name)}>
                    <HammerIcon />
                    重新构建
                  </Button>
            )}
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
            <Button variant="outline" onClick={() => actions.redeploy(svc)}>
              <RefreshCwIcon />
              检查并修复
            </Button>
            <DropdownMenu modal={false}>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" aria-label="更多操作">
                  <EllipsisIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                {!svc.spec.stopped && (
                  <DropdownMenuItem onSelect={() => actions.setStopped(svc, true)}>
                    <SquareIcon />
                    停止
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={() => actions.rollback(name)}>
                  <HistoryIcon />
                  回滚到上一个版本
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

      <div className="grid gap-3 md:grid-cols-[1.4fr_1fr]">
        <Card className="gap-4 py-5 shadow-xs">
          <CardHeader className="px-5">
            <CardTitle className="text-sm font-medium text-muted-foreground">访问</CardTitle>
          </CardHeader>
          <CardContent className="px-5">
            <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
              <dt className="text-muted-foreground">域名</dt>
              <dd className="grid min-w-0 grid-cols-1 gap-1">
                {routes.map((r) => (
                  <div key={r.id} className="flex items-center justify-between gap-2">
                    <a className="inline-flex min-w-0 items-center gap-1 font-mono text-[13px] text-primary hover:underline" href={r.url} target="_blank" rel="noreferrer">
                      <span className="truncate">{r.url}</span>
                      <ArrowUpRightIcon className="size-3.5 shrink-0" />
                    </a>
                    <span className="flex shrink-0 items-center">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label={r.spec.auth ? `关闭 ${r.spec.hostname} 的登录保护` : `给 ${r.spec.hostname} 开启登录保护`}
                          className={r.spec.auth ? "text-primary" : "text-muted-foreground"}
                          onClick={() =>
                            actions.plan({
                              title: `${r.spec.auth ? "关闭" : "开启"} ${r.spec.hostname} 的登录保护`,
                              changes: [{ op: "upsert_route", spec: { ...r.spec, auth: !r.spec.auth } }],
                            })
                          }
                        >
                          {r.spec.auth ? <LockIcon /> : <LockOpenIcon />}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>{r.spec.auth ? "关闭登录保护" : "开启登录保护"}</TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          aria-label={`移除 ${r.spec.hostname}`}
                          onClick={() => actions.plan({ title: `移除 ${r.spec.hostname}`, changes: [{ op: "remove_route", hostname: r.spec.hostname }] })}
                        >
                          <XIcon />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>移除</TooltipContent>
                    </Tooltip>
                    </span>
                  </div>
                ))}
                <Button variant="outline" size="xs" className="w-fit" onClick={() => setAddingRoute(true)}>
                  <PlusIcon />
                  加域名
                </Button>
              </dd>
              <dt className="text-muted-foreground">内网地址</dt>
              <dd className="font-mono text-[13px]">
                {Object.entries(svc.addresses).map(([p, a]) => (
                  <div key={p}>
                    {p} → {a}
                  </div>
                ))}
                {Object.keys(svc.addresses).length === 0 && "-"}
              </dd>
              <dt className="text-muted-foreground">环境变量</dt>
              <dd className="flex flex-wrap gap-1">
                {Object.keys(svc.spec.env ?? {}).map((k) => (
                  <Badge key={k} variant="secondary" className="font-mono font-normal">
                    {k}
                  </Badge>
                ))}
                {!Object.keys(svc.spec.env ?? {}).length && "-"}
              </dd>
              {svc.import && (
                <>
                  <dt className="text-muted-foreground">导入</dt>
                  <dd className="text-xs">{importText(svc.import)}</dd>
                </>
              )}
              {!!svc.data?.length && (
                <>
                  <dt className="text-muted-foreground">数据</dt>
                  <dd className="grid gap-1">
                    {svc.data.map((m, i) => (
                      <div key={i} className="flex flex-wrap items-center gap-2 font-mono text-xs">
                        <span>{m.source || "匿名卷"}</span>
                        <span className="text-muted-foreground">→ {m.target}</span>
                        <Badge variant={m.kind === "managed" ? "secondary" : "outline"} className={m.kind === "managed" ? "font-normal" : "border-warning/50 font-normal text-warning"}>
                          {DATA_KIND[m.kind]}
                        </Badge>
                      </div>
                    ))}
                  </dd>
                </>
              )}
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

      <Tabs value={tab} onValueChange={(t) => setParams({ tab: t }, { replace: true })} className="mt-8">
        <TabsList>
          <TabsTrigger value="logs">日志</TabsTrigger>
          <TabsTrigger value="metrics">资源</TabsTrigger>
          <TabsTrigger value="terminal">终端</TabsTrigger>
          <TabsTrigger value="history">部署历史</TabsTrigger>
          <TabsTrigger value="files">文件</TabsTrigger>
          <TabsTrigger value="backups">备份</TabsTrigger>
          <TabsTrigger value="config">配置</TabsTrigger>
        </TabsList>
        <TabsContent value="logs" className="mt-3">
          <LogStream path={`/api/services/${encodeURIComponent(name)}/logs/stream`} />
        </TabsContent>
        <TabsContent value="metrics" className="mt-3">
          <MetricsPanel subject={name} kind="svc" title="" />
        </TabsContent>
        <TabsContent value="terminal" className="mt-3">
          <TerminalTab svc={svc} />
        </TabsContent>
        <TabsContent value="history" className="mt-3">
          <History name={name} />
        </TabsContent>
        <TabsContent value="files" className="mt-3">
          <Files name={name} />
        </TabsContent>
        <TabsContent value="backups" className="mt-3">
          <Backups svc={svc} />
        </TabsContent>
        <TabsContent value="config" className="mt-3">
          <CodeBlock>{JSON.stringify(svc.spec, null, 2)}</CodeBlock>
        </TabsContent>
      </Tabs>

      <EditService svc={svc} open={editing} onClose={() => setEditing(false)} />
      <AddRoute service={name} open={addingRoute} onClose={() => setAddingRoute(false)} />
    </>
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
            <TableHead>镜像</TableHead>
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
              <TableCell className="max-w-md truncate font-mono text-xs text-muted-foreground" title={d.images.map((im) => im.digest ?? im.image).join(" ")}>
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
    `实际：${ACTUAL[s.actual]}${s.actual_hash ? ` · ${short(s.actual_hash)}` : ""}`,
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
  const [ports, setPorts] = useState<PortSpec[]>(svc.spec.ports ?? []);
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
            <Textarea id="compose" className="min-h-48 font-mono text-xs" value={compose} onChange={(e) => setCompose(e.target.value)} />
          </Field>
        )}
        {build && <BuildEditor value={how} onChange={setHow} />}
        <Field label="端口">
          <PortsEditor ports={ports} onChange={setPorts} compose={isCompose} />
        </Field>
        {(isImage || build) && (
          <Field label="环境变量" htmlFor="env">
            <Textarea id="env" className="min-h-32 font-mono text-xs" value={envText} onChange={(e) => setEnvText(e.target.value)} />
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

function AddRoute({ service, open, onClose }: { service: string; open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const [hostname, setHostname] = useState("");
  const server = status?.services.find((s) => s.name === service)?.spec.server ?? "";
  const entry = useEntry(server);
  const [authWanted, setAuth] = useState(false);
  const [tunnel, setTunnel] = useState(false);
  const auth = authWanted && !entry.tunnel;
  const authSetAt = useBasicAuthSetAt(open ? 1 : 0);
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  const submit = () => {
    onClose();
    setHostname("");
    setAuth(false);
    setTunnel(false);
    const { gateway, changes } = entry.resolve();
    actions.plan({
      title: "加域名",
      changes: [...changes, { op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service, gateway, auth: auth || undefined, link: tunnel ? "tunnel" : undefined } }],
    });
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>给 {service} 加域名</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <Field label="域名" htmlFor="hostname">
            <Input id="hostname" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="app.example.com" />
            {!hostname && <DomainChips suggestions={suffixes.map((s) => `${service}.${s}`)} onPick={setHostname} />}
          </Field>
          <EntryField entry={entry} />
          <label className={`flex items-center gap-2.5 text-sm ${entry.tunnel ? "text-muted-foreground" : "cursor-pointer"}`}>
            <Checkbox checked={auth} disabled={entry.tunnel} onCheckedChange={(v) => setAuth(v === true)} />
            登录保护
            <span className="text-xs text-muted-foreground">{entry.tunnel ? "隧道入口暂不支持" : "访问时要输入账号密码"}</span>
          </label>
          <label className="flex cursor-pointer items-center gap-2.5 text-sm">
            <Checkbox checked={tunnel} onCheckedChange={(v) => setTunnel(v === true)} />
            总是走反向隧道
            <span className="text-xs text-muted-foreground">默认自动：能直连就直连</span>
          </label>
          {auth && authSetAt === null && (
            <Notice kind="warn">
              还没有设置登录保护账号。{" "}
              <button type="button" className="font-medium underline underline-offset-2" onClick={actions.basicAuth}>
                现在设置
              </button>
            </Notice>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!hostname.trim() || !entry.ready || (auth && authSetAt === null)} onClick={submit}>
            生成计划
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
