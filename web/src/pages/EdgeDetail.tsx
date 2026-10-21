import { ArrowLeftIcon, ArrowUpRightIcon, PlusIcon, RefreshCwIcon, RotateCwIcon, Trash2Icon, Undo2Icon, XIcon } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CodeBlock, Empty, ErrorNote, Notice, PageHeader, SectionTitle, StatusBadge, ago } from "@/components/common";
import { DomainChips, Field } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useStatus } from "@/status";
import type { Change, EdgeAppView, EdgeVersionView } from "@/types";
import { KIND_NAME, edgeSourceLabel, edgeTask, edgeTone, projectOf } from "./edge";

/** 边缘应用详情：访问地址、域名、Cloudflare 那边的版本（可以切换回旧版本）。 */
export function EdgeDetail() {
  const { name = "" } = useParams();
  const { status } = useStatus();
  const actions = useActions();
  const path = `/api/edge/${encodeURIComponent(name)}`;
  // 读控制面里存的同步结果；旧了控制面会在后台再同步。
  const { data: app, error, refresh } = usePoll<EdgeAppView>(path, 10000);
  const [addingRoute, setAddingRoute] = useState(false);
  const [syncing, setSyncing] = useState(false);
  // 同步、以线上为准之后让版本列表重新读。
  const [tick, setTick] = useState(0);
  const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];

  const back = (
    <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground" to="/services">
      <ArrowLeftIcon className="size-3.5" />
      服务
    </Link>
  );
  if (!app) {
    return (
      <>
        {back}
        <ErrorNote error={error} />
        {!error && <Skeleton className="h-44 rounded-xl" />}
      </>
    );
  }

  const { tone, text } = edgeTone(app.live, app.drift);
  const redeploy = async () => {
    const run = await edgeTask(`${path}/redeploy`, {}, `重新发布 ${name}`);
    if (run) actions.watch(run, `重新发布 ${name}`);
  };
  const sync = async () => {
    setSyncing(true);
    try {
      await api.get(`${path}?sync=1`);
      refresh();
      setTick((t) => t + 1);
    } catch (e) {
      toast.error(`同步 ${name} 失败`, { description: (e as Error).message });
    } finally {
      setSyncing(false);
    }
  };
  const accept = async () => {
    try {
      await api.post(`${path}/accept`, {});
      toast.success("已以线上版本为准");
      refresh();
      setTick((t) => t + 1);
    } catch (e) {
      toast.error("操作失败", { description: (e as Error).message });
    }
  };
  const remove = () =>
    actions.plan({
      title: `不再纳管 ${name}`,
      then: "/services",
      changes: [...routes.map((r) => ({ op: "remove_route", hostname: r.spec.hostname }) as Change), { op: "remove_edge_app", name }],
    });

  return (
    <>
      {back}
      <PageHeader
        title={
          <>
            {app.name}
            <StatusBadge tone={tone}>{text}</StatusBadge>
          </>
        }
        description={
          <span className="flex flex-wrap items-center gap-1.5">
            <Badge variant="secondary">{KIND_NAME[app.spec.kind]}</Badge>
            <span className="font-mono text-xs">{edgeSourceLabel(app.spec.source)}</span>
          </span>
        }
        actions={
          <>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" disabled={syncing} onClick={sync}>
                  <RotateCwIcon className={syncing ? "animate-spin" : undefined} />
                  同步
                </Button>
              </TooltipTrigger>
              <TooltipContent>{app.live ? `上次同步 ${ago(app.live.checked_at)}` : "未同步"}</TooltipContent>
            </Tooltip>
            {app.spec.source && (
              <Button variant="outline" onClick={redeploy}>
                <RefreshCwIcon />
                重新发布
              </Button>
            )}
            <Button variant="outline" className="text-destructive" onClick={remove}>
              <Trash2Icon />
              不再纳管
            </Button>
          </>
        }
      />

      {app.drift && (
        <Notice kind="warn" className="mb-3">
          {app.drift}
          {app.live?.exists && (
            <button type="button" className="ml-1 font-medium underline underline-offset-2" onClick={accept}>
              以线上为准
            </button>
          )}
        </Notice>
      )}
      {app.live?.error && (
        <Notice kind="warn" className="mb-3">
          同步失败：{app.live.error}
        </Notice>
      )}

      <Card className="py-5 shadow-xs">
        <CardContent className="px-5">
          <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
            <dt className="text-muted-foreground">地址</dt>
            <dd className="grid min-w-0 gap-1">
              {app.live?.url && <ExternalLink url={app.live.url} />}
              {routes.map((r) => (
                <div key={r.id} className="flex items-center justify-between gap-2">
                  <ExternalLink url={r.url} />
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label={`移除 ${r.spec.hostname}`}
                    onClick={() => actions.plan({ title: `移除 ${r.spec.hostname}`, changes: [{ op: "remove_route", hostname: r.spec.hostname }] })}
                  >
                    <XIcon />
                  </Button>
                </div>
              ))}
              <Button variant="outline" size="xs" className="w-fit" onClick={() => setAddingRoute(true)}>
                <PlusIcon />
                加域名
              </Button>
            </dd>
            <dt className="text-muted-foreground">Cloudflare</dt>
            <dd className="font-mono text-[13px]">
              {app.spec.account} / {projectOf(app)}
            </dd>
            <dt className="text-muted-foreground">同步于</dt>
            <dd className="text-muted-foreground">{app.live ? ago(app.live.checked_at) : "-"}</dd>
            <dt className="text-muted-foreground">最近发布</dt>
            <dd>
              {app.live?.deployed_at ? `${ago(app.live.deployed_at)}${app.live.deployed_by ? `（${app.live.deployed_by}）` : ""}` : "-"}
            </dd>
            {app.spec.builder && (
              <>
                <dt className="text-muted-foreground">执行 wrangler</dt>
                <dd>{app.spec.builder}</dd>
              </>
            )}
          </dl>
        </CardContent>
      </Card>

      <Versions key={tick} name={name} onChanged={refresh} />

      <SectionTitle>配置</SectionTitle>
      <CodeBlock>{JSON.stringify(app.spec, null, 2)}</CodeBlock>

      <AddEdgeRoute app={name} open={addingRoute} onClose={() => setAddingRoute(false)} />
    </>
  );
}

function ExternalLink({ url }: { url: string }) {
  return (
    <a className="inline-flex min-w-0 items-center gap-1 font-mono text-[13px] text-primary hover:underline" href={url} target="_blank" rel="noreferrer">
      <span className="truncate">{url}</span>
      <ArrowUpRightIcon className="size-3.5 shrink-0" />
    </a>
  );
}

function Versions({ name, onChanged }: { name: string; onChanged: () => void }) {
  const path = `/api/edge/${encodeURIComponent(name)}`;
  const { data, error } = usePoll<EdgeVersionView[]>(`${path}/versions`, 10000);
  const actions = useActions();
  const rollback = async (v: EdgeVersionView) => {
    const title = `${name} 切换到 ${v.id.slice(0, 8)}`;
    const run = await edgeTask(`${path}/rollback`, { version: v.id }, title);
    if (run) {
      actions.watch(run, title);
      onChanged();
    }
  };
  return (
    <>
      <SectionTitle count={data?.length}>版本</SectionTitle>
      <ErrorNote error={error} />
      {!data ? (
        !error && <Skeleton className="h-32 rounded-xl" />
      ) : data.length === 0 ? (
        <Empty>没有版本</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
          <Table>
            <TableHeader className="bg-muted/50">
              <TableRow>
                <TableHead className="pl-4">版本</TableHead>
                <TableHead>时间</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>说明</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.slice(0, 20).map((v) => (
                <TableRow key={v.id}>
                  <TableCell className="pl-4 font-mono text-xs">
                    {v.url ? (
                      <a className="text-primary hover:underline" href={v.url} target="_blank" rel="noreferrer">
                        {v.id.slice(0, 8)}
                      </a>
                    ) : (
                      v.id.slice(0, 8)
                    )}
                    {v.active && (
                      <Badge variant="secondary" className="ml-2">
                        线上
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{v.created_at ? ago(v.created_at) : "-"}</TableCell>
                  <TableCell className="text-muted-foreground">{v.source ?? "-"}</TableCell>
                  <TableCell className="max-w-64 truncate text-muted-foreground">{v.message ?? ""}</TableCell>
                  <TableCell className="pr-4 text-right">
                    {!v.active && (
                      <Button variant="ghost" size="xs" onClick={() => rollback(v)}>
                        <Undo2Icon />
                        切换到这个
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </>
  );
}

function AddEdgeRoute({ app, open, onClose }: { app: string; open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const [hostname, setHostname] = useState("");
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  const submit = () => {
    onClose();
    setHostname("");
    actions.plan({ title: "加域名", changes: [{ op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service: app } }] });
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>给 {app} 加域名</DialogTitle>
        </DialogHeader>
        <Field label="域名" htmlFor="edge-hostname">
          <Input id="edge-hostname" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="app.example.com" />
          {!hostname && <DomainChips suggestions={suffixes.map((s) => `${app}.${s}`)} onPick={setHostname} />}
        </Field>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!hostname.trim()} onClick={submit}>
            生成计划
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
