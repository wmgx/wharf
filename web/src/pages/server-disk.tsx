import { Panel } from "@/components/kit";
import { RefreshCwIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, SectionTitle } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";

type Row = { name: string; shared: boolean; data: number; logs: number; vols: number; total: number; day?: number; week?: number; at: number };
type View = { rows: Row[]; measured_at?: number };

function size(b: number): string {
  const a = Math.abs(b);
  if (a < 1024) return `${b} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = a / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${b < 0 ? "-" : ""}${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

function Growth({ v }: { v?: number }) {
  if (v === undefined) return <span className="text-muted-foreground">-</span>;
  // 一天涨 1GB 以上标黄，10GB 以上标红。
  const tone = v >= 10 * 2 ** 30 ? "text-destructive" : v >= 2 ** 30 ? "text-warning" : v > 0 ? "" : "text-muted-foreground";
  return <span className={cn("tabular-nums", tone)}>{v > 0 ? "+" : ""}{size(v)}</span>;
}

/** 服务器"系统"标签：每个服务的数据目录、日志、数据卷占用和 1 天、7 天的增长。每天测一次。 */
export function ServerDisk({ server, online }: { server: string; online: boolean }) {
  const path = `/api/servers/${encodeURIComponent(server)}/disk`;
  const { data, refresh } = usePoll<View>(path, 300000);
  const [busy, setBusy] = useState(false);
  const measure = async () => {
    setBusy(true);
    try {
      await api.post(`${path}/measure`, {});
      refresh();
    } catch (e) {
      toast.error("测量失败", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mb-6">
      <SectionTitle action={<div className="flex flex-wrap items-center gap-2"><span className="text-xs text-muted-foreground">
          {data?.measured_at ? `${ago(new Date(data.measured_at).toISOString())}测量，每天一次` : "每天测量一次"}
        </span><Button variant="ghost" size="sm" className="ml-auto" disabled={busy || !online} onClick={measure}>
          <RefreshCwIcon className={busy ? "animate-spin" : undefined} />
          {busy ? "测量中，可能要几分钟…" : "立即测量"}
        </Button></div>}>占用增长</SectionTitle>
      {!data?.rows.length ? (
        <Empty>还没有测量过</Empty>
      ) : (
        <Panel className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>服务</TableHead>
                <TableHead className="text-right">数据目录</TableHead>
                <TableHead className="text-right">日志</TableHead>
                <TableHead className="text-right">数据卷</TableHead>
                <TableHead className="text-right">合计</TableHead>
                <TableHead className="text-right">1 天</TableHead>
                <TableHead className="text-right">7 天</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.rows.map((r) => (
                <TableRow key={`${r.shared}-${r.name}`}>
                  <TableCell className="font-medium">
                    {r.name}
                    {r.shared && <span className="ml-1.5 text-xs font-normal text-muted-foreground">共用卷</span>}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">{r.shared ? "-" : size(r.data)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{r.shared ? "-" : size(r.logs)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{size(r.vols)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{size(r.total)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    <Growth v={r.day} />
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    <Growth v={r.week} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </div>
  );
}
