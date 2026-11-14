import { useSearchParams, Link } from "react-router-dom";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Dot, Empty, ErrorNote, PageHeader, ServerTag, StatusBadge, ago, useClickable, type Tone } from "@/components/common";
import { Segmented } from "@/components/fields";
import { Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { DataStatus, DataView } from "@/types";

const TEXT: Record<DataStatus, string> = { ok: "正常", stale: "过期", off: "没开", uncovered: "不在范围", none: "没有数据" };
const TONE: Record<DataStatus, Tone> = { ok: "ok", stale: "bad", off: "warn", uncovered: "warn", none: "idle" };
const ORDER: DataStatus[] = ["stale", "off", "uncovered", "ok", "none"];

export function Data() {
  const { data, error, refresh } = usePoll<DataView>("/api/data", 15000);
  const actions = useActions();
  const { status } = useStatus();
  const clickable = useClickable();
  const [params, setParams] = useSearchParams();
  const show = params.get("show") ?? "all";
  const server = params.get("server") ?? "";
  const services = data?.services ?? [];
  const stale = services.filter((s) => s.status === "stale").length;
  const problems = services.filter((s) => s.status === "off" || s.status === "uncovered").length;
  const withData = services.filter((s) => s.status !== "none").length;
  const tone = stale ? "bad" : problems ? "warn" : withData ? "ok" : "idle";
  const text = stale ? `${stale} 个服务的备份过期了` : problems ? `${problems} 个服务有数据但没备份` : withData ? `有数据的 ${withData} 个服务都在备份` : "没有服务有数据";
  const latest = services.map((s) => s.last_ok).filter((v): v is string => !!v).sort().at(-1);
  const servers = (status?.servers ?? []).map((s) => s.name);
  const rows = services.filter((s) => (!server || s.server === server) && (show === "problems" ? ["stale", "off", "uncovered"].includes(s.status) : show === "none" ? s.status === "none" : true)).sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));
  const set = (key: string, value: string, fallback: string) => { const next = new URLSearchParams(params); if (value === fallback) next.delete(key); else next.set(key, value); setParams(next); };
  const run = async (name: string) => {
    try { const { run_id } = await api.post<{ run_id: string }>(`/api/services/${encodeURIComponent(name)}/backups`, {}); actions.watch(run_id, `备份 ${name}`); setTimeout(refresh, 3000); }
    catch(e) { toast.error("不能开始备份", { description: (e as Error).message }); }
  };
  return <>
    <ErrorNote error={error} />
    {!data ? <Skeleton className="h-48 rounded-xl" /> : <>
      <Panel className="p-4">
        <div className="flex items-center gap-2 text-base font-medium">
          <Dot tone={tone} />
          {text}
        </div>
        {latest && <div className="mt-1 text-sm text-muted-foreground">最近一次备份 {ago(latest)}
        </div>}
      </Panel>
      <div className="my-4 flex flex-wrap gap-2">
        <div className="max-w-full overflow-x-auto">
          <Segmented value={show} options={[["all", "全部"], ...(stale || problems ? [["problems", "有问题的"] as [string, string]] : []), ["none", "没有数据的"]]} onChange={(v) => set("show", v, "all")} />
        </div>
        {servers.length > 1 && <div className="max-w-full overflow-x-auto">
          <Segmented value={server} options={[["", "全部"], ...servers.map((s): [string, string] => [s, s])]} onChange={(v) => set("server", v, "")} />
        </div>}
      </div>
      {!rows.length ? <Empty>
        {services.length ? "没有符合条件的服务" : "还没有服务"}
      </Empty> : <Panel>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>服务</TableHead>
              <TableHead>所在</TableHead>
              <TableHead>数据</TableHead>
              <TableHead>备份</TableHead>
              <TableHead>备份到</TableHead>
              <TableHead>上次</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((s) => {
              const outside = s.mounts.filter((m) => m.kind !== "managed").length;
              const summary = !s.mounts.length ? "没有数据卷" : outside ? `${s.mounts.length} 处挂载，${outside} 处不在备份范围` : `${s.mounts.length} 处挂载`;
              return <TableRow key={s.name} className="cursor-pointer" {...clickable({ to: `/services/${encodeURIComponent(s.name)}?tab=data` })}>
                <TableCell className="font-medium">
                  {s.name}
                </TableCell>
                <TableCell>
                  <ServerTag name={s.server} />
                </TableCell>
                <TableCell>
                  {summary}
                </TableCell>
                <TableCell>
                  <StatusBadge tone={TONE[s.status]}>
                    {TEXT[s.status]}
                  </StatusBadge>
                </TableCell>
                <TableCell>
                  {s.target ?? "-"}
                </TableCell>
                <TableCell>
                  {s.last_ok ? ago(s.last_ok) : "-"}
                </TableCell>
                <TableCell onClick={(e) => e.stopPropagation()}>
                  {s.status === "off" ? <Button variant="ghost" size="xs" asChild>
                    <Link to={`/services/${encodeURIComponent(s.name)}?tab=settings#backup`}>去开启</Link>
                  </Button> : (s.status === "ok" || s.status === "stale") && <Button variant="ghost" size="xs" onClick={() => run(s.name)}>立即备份</Button>}
                </TableCell>
              </TableRow>;
            })}
          </TableBody>
        </Table>
      </Panel>}
      <p className="mt-4 text-sm text-muted-foreground">
        <Link className="hover:underline" to="/settings?tab=core">控制面自己的备份在 设置 → 控制面</Link>
      </p>
    </>}
  </>;
}

export function DataPage() {
  return <>
    <PageHeader title="数据与备份" />
    <Data />
  </>;
}
