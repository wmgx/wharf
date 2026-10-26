import { ArchiveRestoreIcon, DatabaseBackupIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ago, Empty, ErrorNote, Notice, ServerTag } from "@/components/common";
import { Field, Picker, serverOptions } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { BackupsView, ServiceView, Snapshot } from "@/types";

function size(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${bytes} B` : `${v.toFixed(1)} ${units[i]}`;
}

/** 服务详情的"备份"标签：开关自动备份、立即备份、看快照、恢复。 */
export function Backups({ svc }: { svc: ServiceView }) {
  const name = svc.name;
  const { data, error, refresh } = usePoll<BackupsView>(`/api/services/${encodeURIComponent(name)}/backups`, 30000);
  const actions = useActions();
  const [restoring, setRestoring] = useState<Snapshot | null>(null);
  const target = svc.spec.backup?.to;
  const hasData = !!svc.spec.volumes?.length || "compose" in svc.spec.source;

  const runNow = async () => {
    try {
      const { run_id } = await api.post<{ run_id: string }>(`/api/services/${encodeURIComponent(name)}/backups`, {});
      actions.watch(run_id, `备份 ${name}`);
      setTimeout(refresh, 3000);
    } catch (e) {
      toast.error("不能开始备份", { description: (e as Error).message });
    }
  };

  const restore = async (snap: Snapshot) => {
    setRestoring(null);
    try {
      const { run_id } = await api.post<{ run_id: string }>(`/api/services/${encodeURIComponent(name)}/restore`, {
        snapshot: snap.id,
        confirm: `service/${name}`,
      });
      actions.watch(run_id, `恢复 ${name} 到 ${snap.short_id}`);
    } catch (e) {
      toast.error("不能开始恢复", { description: (e as Error).message });
    }
  };

  if (!hasData) return <Empty>没有数据卷</Empty>;

  const last = data?.records[0];
  const uncovered = svc.data?.filter((m) => m.kind !== "managed") ?? [];
  return (
    <div className="grid gap-3">
      <Card className="gap-4 py-5 shadow-xs">
        <CardHeader className="flex flex-row items-center justify-between gap-3 px-5">
          <CardTitle className="text-sm font-medium text-muted-foreground">自动备份</CardTitle>
          {target && (
            <Button variant="outline" size="sm" onClick={runNow}>
              <DatabaseBackupIcon />
              立即备份
            </Button>
          )}
        </CardHeader>
        <CardContent className="grid gap-3 px-5 text-sm">
          {target ? (
            <>
              <p>
                每天把 <code className="font-mono text-[13px]">/srv/{name}/</code> 备份到 <ServerTag name={target} />
                ，备份时会先停服务、备份完再启动。保留最近 7 天、4 周、6 个月各一份。
              </p>
              {last && (
                <p className="text-muted-foreground">
                  上次备份 {ago(last.created_at)}：
                  {last.ok ? (
                    <span className="text-success">成功{last.summary && `，${last.summary.files} 个文件，新增 ${size(last.summary.added_bytes)}`}</span>
                  ) : (
                    <span className="text-destructive">失败，{last.error}</span>
                  )}
                </p>
              )}
              <div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-muted-foreground"
                  onClick={() => actions.plan({ title: `关闭 ${name} 的自动备份`, changes: [{ op: "upsert_service", name, spec: { ...svc.spec, backup: undefined } }] })}
                >
                  关闭自动备份
                </Button>
              </div>
            </>
          ) : (
            <EnableBackup svc={svc} />
          )}
        </CardContent>
      </Card>

      {uncovered.length > 0 && <Notice kind="warn">不在备份范围：{uncovered.map((m) => m.source || `匿名卷 ${m.target}`).join("、")}</Notice>}
      <ErrorNote error={error} />
      {data?.snapshots_error && <Notice kind="warn">读取快照失败：{data.snapshots_error}</Notice>}
      {!data ? (
        <Skeleton className="h-32 rounded-xl" />
      ) : data.snapshots.length === 0 ? (
        target && <Empty>还没有快照</Empty>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
          <Table>
            <TableHeader className="bg-muted/50">
              <TableRow>
                <TableHead className="pl-4">快照</TableHead>
                <TableHead>时间</TableHead>
                <TableHead>来自</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.snapshots.map((s, i) => (
                <TableRow key={s.id}>
                  <TableCell className="pl-4 font-mono text-xs">{s.short_id}</TableCell>
                  <TableCell>
                    <span title={new Date(s.time).toLocaleString("zh-CN")}>{ago(s.time)}</span>
                    {i === 0 && (
                      <Badge variant="secondary" className="ml-2">
                        最新
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <ServerTag name={s.hostname} />
                  </TableCell>
                  <TableCell className="pr-4 text-right">
                    <Button variant="outline" size="xs" onClick={() => setRestoring(s)}>
                      <ArchiveRestoreIcon />
                      恢复到这里
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <RestoreDialog name={name} snapshot={restoring} onCancel={() => setRestoring(null)} onConfirm={restore} />
    </div>
  );
}

function EnableBackup({ svc }: { svc: ServiceView }) {
  const { status } = useStatus();
  const actions = useActions();
  const [to, setTo] = useState("");
  const options = serverOptions((status?.servers ?? []).filter((s) => s.joined && s.name !== svc.spec.server));
  if (!options.length) return <p className="text-muted-foreground">需要另一台服务器存放备份，现在只有 {svc.spec.server}。</p>;
  return (
    <div className="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
      <Field label="备份到" htmlFor="backup-to">
        <Picker id="backup-to" value={to} options={options} onChange={setTo} placeholder="选择服务器…" />
      </Field>
      <Button
        disabled={!to}
        className="sm:mb-6"
        onClick={() => actions.plan({ title: `开启 ${svc.name} 的自动备份`, changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, backup: { to } } }] })}
      >
        开启自动备份
      </Button>
    </div>
  );
}

/** 恢复前输入 `service/名称` 确认，和 CLI 的 `--confirm` 一样。 */
function RestoreDialog({ name, snapshot, onCancel, onConfirm }: { name: string; snapshot: Snapshot | null; onCancel: () => void; onConfirm: (s: Snapshot) => void }) {
  const [typed, setTyped] = useState("");
  useEffect(() => setTyped(""), [snapshot]);
  const expect = `service/${name}`;
  return (
    <Dialog open={!!snapshot} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>恢复 {name} 到快照 {snapshot?.short_id}？</DialogTitle>
          <DialogDescription>
            停服后用 {snapshot && new Date(snapshot.time).toLocaleString("zh-CN")} 的快照替换 /srv/{name}/，原数据移到 /srv/.wharf-restore/。输入{" "}
            <code className="font-mono text-foreground">{expect}</code> 确认。
          </DialogDescription>
        </DialogHeader>
        <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={expect} className="font-mono" />
        <DialogFooter>
          <Button variant="ghost" onClick={onCancel}>
            取消
          </Button>
          <Button variant="destructive" disabled={typed.trim() !== expect} onClick={() => snapshot && onConfirm(snapshot)}>
            恢复
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
