import { ArrowRightLeftIcon, ArrowLeftIcon, ArrowUpRightIcon, EllipsisIcon, HammerIcon, HistoryIcon, LockIcon, LockOpenIcon, PencilIcon, PlusIcon, RefreshCwIcon, Trash2Icon, XIcon } from "lucide-react";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { useBasicAuthSetAt } from "@/components/basic-auth";
import { Checkbox } from "@/components/ui/checkbox";
import { CodeBlock, Dot, Empty, ErrorNote, Notice, PageHeader, ServerTag, StatusBadge, ago, liveTone, sourceLabel } from "@/components/common";
import { EntryField, useEntry } from "@/components/entry";
import { DomainChips, Field, PortsEditor, formatEnv, parseEnv } from "@/components/fields";
import { LogStream } from "@/components/LogStream";
import { Backups } from "./service-backups";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useStatus } from "@/status";
import type { DeploymentView, PortSpec, ServiceView } from "@/types";

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

  const { tone, text } = liveTone(svc.live);
  const source = sourceLabel(svc.spec.source);
  const built = "build" in svc.spec.source;

  return (
    <>
      {back}
      <PageHeader
        title={
          <>
            {svc.name}
            <StatusBadge tone={tone}>{text}</StatusBadge>
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
            {built && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" onClick={() => actions.rebuild(name)}>
                    <HammerIcon />
                    重新构建
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{"build" in svc.spec.source && svc.spec.source.build.git ? "拉分支上的最新代码，构建后替换运行中的容器" : "用最近一次上传的代码重新构建"}</TooltipContent>
              </Tooltip>
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
                      <TooltipContent>{r.spec.auth ? "已开启登录保护，点击关闭" : "未开启登录保护，点击开启"}</TooltipContent>
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
                      <TooltipContent>移除这个域名</TooltipContent>
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
            </dl>
          </CardContent>
        </Card>
        <Card className="gap-4 py-5 shadow-xs">
          <CardHeader className="px-5">
            <CardTitle className="text-sm font-medium text-muted-foreground">容器</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2.5 px-5 text-sm">
            {svc.live?.containers?.map((c) => (
              <div key={c.name} className="flex items-center gap-3">
                <span className="w-24 truncate text-muted-foreground">{c.service}</span>
                <Dot tone={c.state === "running" ? "ok" : "bad"} />
                <span>{c.status || c.state}</span>
              </div>
            ))}
            {!svc.live?.containers?.length && <span className="text-muted-foreground">{svc.live?.error ?? "没有容器"}</span>}
          </CardContent>
        </Card>
      </div>

      <Tabs value={tab} onValueChange={(t) => setParams({ tab: t }, { replace: true })} className="mt-8">
        <TabsList>
          <TabsTrigger value="logs">日志</TabsTrigger>
          <TabsTrigger value="history">部署历史</TabsTrigger>
          <TabsTrigger value="backups">备份</TabsTrigger>
          <TabsTrigger value="config">配置</TabsTrigger>
        </TabsList>
        <TabsContent value="logs" className="mt-3">
          <LogStream path={`/api/services/${encodeURIComponent(name)}/logs/stream`} />
        </TabsContent>
        <TabsContent value="history" className="mt-3">
          <History name={name} />
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
  if (data.length === 0) return <Empty>还没有部署记录。</Empty>;
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
      <SheetContent className="w-full gap-0 sm:max-w-xl">
        <SheetHeader className="border-b">
          <SheetTitle>修改 {svc.name}</SheetTitle>
          <SheetDescription>改完生成计划，确认后重新部署。</SheetDescription>
        </SheetHeader>
        {open && <EditForm svc={svc} onClose={onClose} />}
      </SheetContent>
    </Sheet>
  );
}

function EditForm({ svc, onClose }: { svc: ServiceView; onClose: () => void }) {
  const actions = useActions();
  const src = svc.spec.source;
  const isImage = "image" in src;
  const build = "build" in src ? src.build : null;
  const [image, setImage] = useState(isImage ? src.image : "");
  const [compose, setCompose] = useState("compose" in src ? (src.compose.content ?? "") : "");
  const [repo, setRepo] = useState(build?.git?.repo ?? "");
  const [gitRef, setGitRef] = useState(build?.git?.ref ?? "");
  const [ports, setPorts] = useState<PortSpec[]>(svc.spec.ports ?? []);
  const [envText, setEnvText] = useState(formatEnv(svc.spec.env));
  const submit = () => {
    const spec = {
      ...svc.spec,
      source: isImage
        ? { image: image.trim() }
        : build
          ? { build: build.git ? { ...build, git: { ...build.git, repo: repo.trim(), ref: gitRef.trim() } } : build }
          : { compose: { content: compose } },
      ports,
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
            <Notice kind="info">
              代码来自本机目录。发布新版本在代码目录里执行 <code className="font-mono">wharf deploy</code>。
            </Notice>
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
        <Field label="端口">
          <PortsEditor ports={ports} onChange={setPorts} />
        </Field>
        {(isImage || build) && (
          <Field label="环境变量" htmlFor="env" help="一行一个 KEY=value。删掉一行就是删除这个变量。">
            <Textarea id="env" className="min-h-32 font-mono text-xs" value={envText} onChange={(e) => setEnvText(e.target.value)} />
          </Field>
        )}
      </div>
      <SheetFooter className="flex-row justify-end border-t">
        <Button variant="ghost" onClick={onClose}>
          取消
        </Button>
        <Button onClick={submit}>生成计划</Button>
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
  const auth = authWanted && !entry.tunnel;
  const authSetAt = useBasicAuthSetAt(open ? 1 : 0);
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  const submit = () => {
    onClose();
    setHostname("");
    setAuth(false);
    const { gateway, changes } = entry.resolve();
    actions.plan({
      title: "加域名",
      changes: [...changes, { op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service, gateway, auth: auth || undefined } }],
    });
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>给 {service} 加域名</DialogTitle>
          <DialogDescription>域名经过网关或 Cloudflare 隧道转发到这个服务。</DialogDescription>
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
