import { BoxIcon, DownloadIcon, LayersIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { CodeBlock, Notice, SectionTitle, ServerTag, StatusBadge } from "@/components/common";
import { Field } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { ImportPreview, Unmanaged } from "@/types";

/** 各台在线服务器上没纳管的容器，30 秒刷新一次。 */
function useUnmanaged(): Unmanaged[] {
  const { status } = useStatus();
  const servers = (status?.servers ?? []).filter((s) => s.online).map((s) => s.name);
  const key = servers.join(",");
  const [items, setItems] = useState<Unmanaged[]>([]);
  const load = useCallback(async () => {
    if (!key) return;
    const results = await Promise.allSettled(key.split(",").map((s) => api.get<Unmanaged[]>(`/api/servers/${encodeURIComponent(s)}/unmanaged`)));
    setItems(results.flatMap((r) => (r.status === "fulfilled" ? r.value : [])));
  }, [key]);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);
  return items;
}

const target = (u: Unmanaged) => u.project ?? u.container ?? "";

export function UnmanagedList() {
  const items = useUnmanaged();
  const [importing, setImporting] = useState<Unmanaged | null>(null);
  if (items.length === 0) return null;
  return (
    <section>
      <SectionTitle count={items.length}>服务器上没纳管的容器</SectionTitle>
      <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="pl-4">名字</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>服务器</TableHead>
              <TableHead>镜像</TableHead>
              <TableHead>端口</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((u) => {
              const running = u.containers.filter((c) => c.state === "running").length;
              return (
                <TableRow key={`${u.server}/${target(u)}`} className="text-muted-foreground">
                  <TableCell className="pl-4">
                    <span className="inline-flex items-center gap-1.5">
                      {u.project ? <LayersIcon className="size-3.5" /> : <BoxIcon className="size-3.5" />}
                      {target(u)}
                      {u.project && <Badge variant="outline">compose · {u.containers.length}</Badge>}
                    </span>
                  </TableCell>
                  <TableCell>
                    <StatusBadge tone={running === u.containers.length ? "ok" : running ? "warn" : "idle"}>
                      {running === u.containers.length ? "运行中" : running ? `${running}/${u.containers.length} 运行` : "已停止"}
                    </StatusBadge>
                  </TableCell>
                  <TableCell>
                    <ServerTag name={u.server} />
                  </TableCell>
                  <TableCell className="max-w-64 truncate font-mono text-xs">{[...new Set(u.containers.map((c) => c.image))].join(" ")}</TableCell>
                  <TableCell className="max-w-48 truncate font-mono text-xs">{u.containers.flatMap((c) => c.ports ?? []).join(" ") || "-"}</TableCell>
                  <TableCell className="pr-4 text-right">
                    <Button variant="ghost" size="xs" onClick={() => setImporting(u)}>
                      <DownloadIcon />
                      导入
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {importing && <ImportDialog item={importing} onClose={() => setImporting(null)} />}
    </section>
  );
}

function ImportDialog({ item, onClose }: { item: Unmanaged; onClose: () => void }) {
  const actions = useActions();
  const [name, setName] = useState(item.name);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(
    async (n: string) => {
      setLoading(true);
      setError("");
      try {
        setPreview(await api.post<ImportPreview>("/api/import", { server: item.server, project: item.project, container: item.container, name: n }));
      } catch (e) {
        setPreview(null);
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [item],
  );
  useEffect(() => {
    load(item.name);
  }, [item, load]);

  const stale = preview?.name !== name;
  const compose = preview && "compose" in preview.spec.source ? preview.spec.source.compose.content : undefined;
  const submit = () => {
    if (!preview) return;
    onClose();
    actions.plan({ title: `导入 ${preview.name}`, changes: [{ op: "upsert_service", name: preview.name, spec: preview.spec }] });
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            导入 {target(item)}
            <span className="ml-2 text-sm font-normal text-muted-foreground">{item.server}</span>
          </DialogTitle>
        </DialogHeader>
        <Field label="服务名" htmlFor="import-name">
          <Input
            id="import-name"
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
            onBlur={() => name && stale && load(name)}
          />
        </Field>
        {error && <Notice kind="warn">{error}</Notice>}
        {loading && !preview && <Skeleton className="h-40 rounded-lg" />}
        {preview && (
          <>
            {preview.warnings?.map((w) => (
              <Notice key={w} kind="warn">
                {w}
              </Notice>
            ))}
            {preview.spec.ports && preview.spec.ports.length > 0 && (
              <div className="font-mono text-xs text-muted-foreground">端口 {preview.spec.ports.map((p) => `${p.name}=${p.port}`).join(" ")}</div>
            )}
            {compose && (
              <details>
                <summary className="cursor-pointer text-sm text-muted-foreground">compose</summary>
                <CodeBlock className="mt-2 max-h-72">{compose}</CodeBlock>
              </details>
            )}
          </>
        )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!preview || stale || loading} onClick={submit}>
            生成计划
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
