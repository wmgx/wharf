import { useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { ago, Empty, ErrorNote, PageHeader, ServerTag, StatusBadge, type Tone } from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { DataKind, DataStatus, DataView } from "@/types";

const TEXT: Record<DataStatus, string> = {
  ok: "正常",
  stale: "过期",
  off: "未备份",
  uncovered: "未覆盖",
  none: "没有数据",
};

const TONE: Record<DataStatus, Tone> = {
  ok: "ok",
  stale: "bad",
  off: "warn",
  uncovered: "warn",
  none: "idle",
};

/** 有问题的排在前面。 */
const ORDER: DataStatus[] = ["stale", "off", "uncovered", "ok", "none"];

const KIND: Record<DataKind, string> = {
  managed: "目录",
  external_dir: "外部目录",
  named_volume: "卷",
};

export function Data() {
  const { data, error } = usePoll<DataView>("/api/data", 15000);
  const nav = useNavigate();
  const services = [...(data?.services ?? [])].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));

  return (
    <>
      <PageHeader title="数据" />
      {error && <ErrorNote error={error} />}
      {!data ? (
        <Skeleton className="h-48 rounded-xl" />
      ) : services.length === 0 ? (
        <Empty>还没有服务</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
          <Table>
            <TableHeader className="bg-muted/50">
              <TableRow>
                <TableHead className="pl-4">服务</TableHead>
                <TableHead>服务器</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>备份目标</TableHead>
                <TableHead>最近成功</TableHead>
                <TableHead>挂载</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((s) => (
                <TableRow key={s.name} className="cursor-pointer" onClick={() => nav(`/services/${s.name}`)}>
                  <TableCell className="pl-4 font-medium">{s.name}</TableCell>
                  <TableCell>
                    <ServerTag name={s.server} />
                  </TableCell>
                  <TableCell>
                    <StatusBadge tone={TONE[s.status]}>{TEXT[s.status]}</StatusBadge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{s.target ?? "-"}</TableCell>
                  <TableCell className="text-muted-foreground">{s.last_ok ? ago(s.last_ok) : "-"}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {s.mounts.map((m) => (
                      <div key={`${m.kind}:${m.source}${m.target}`}>
                        {KIND[m.kind]} {m.source || m.target}
                      </div>
                    ))}
                    {s.mounts.length === 0 && <span className="text-muted-foreground">-</span>}
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
