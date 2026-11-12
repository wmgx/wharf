import { ConfirmDialog, Tip } from "@/components/kit";
import { BoxIcon, DownloadIcon, LayersIcon, ServerIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";
import { Checkbox } from "@/components/ui/checkbox";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { CodeBlock, Notice, StatusBadge } from "@/components/common";
import { Field } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useStatus } from "@/status";
import type { ImportPreview, Unmanaged } from "@/types";

/** 各台在线服务器上没纳管的容器，30 秒刷新一次。 */
function useUnmanaged(): { items: Unmanaged[]; reload: () => void } {
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
  return { items, reload: load };
}

const target = (u: Unmanaged) => u.project ?? u.container ?? "";

/** 一行"还有多少没纳管"的提示，点开逐个导入。 */
export function HintRow({ icon, label, text, onClick }: { icon: ReactNode; label: string; text: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 rounded-lg border border-dashed px-4 py-2.5 text-left text-sm text-muted-foreground transition-colors hover:border-primary hover:text-foreground"
    >
      {icon}
      <span className="font-medium text-foreground">{label}</span>
      <span>· {text}</span>
      <span className="ml-auto inline-flex items-center gap-1 text-primary">
        <DownloadIcon className="size-3.5" />
        导入
      </span>
    </button>
  );
}

/** 每台服务器一行提示：有多少容器没纳管，点开逐个导入。 */
export function UnmanagedList() {
  const { items, reload } = useUnmanaged();
  const [removing, setRemoving] = useState<Unmanaged | null>(null);
  const [params, setParams] = useSearchParams();
  const [picked, setServer] = useState<string | null>(null);
  const [importing, setImporting] = useState<Unmanaged | null>(null);
  const byServer = new Map<string, Unmanaged[]>();
  for (const u of items) byServer.set(u.server, [...(byServer.get(u.server) ?? []), u]);
  // 从"新建 → 导入已有容器"进来（?import=1）：列出所有服务器上的。
  const all = params.get("import") === "1";
  const server = all ? "*" : picked;
  const close = () => (all ? setParams({}) : setServer(null));
  if (byServer.size === 0) return null;
  const list = server === "*" ? items : server ? (byServer.get(server) ?? []) : [];
  return (
    <div className="mt-3 grid gap-2">
      {[...byServer].map(([name, group]) => (
        <HintRow key={name} icon={<ServerIcon className="size-4" />} label={name} text={`${group.length} 个容器未纳管`} onClick={() => setServer(name)} />
      ))}
      <Dialog open={!!server && !importing} onOpenChange={(o) => !o && close()}>
        <DialogContent aria-describedby={undefined} className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{server === "*" ? "服务器上还没纳管的容器" : `${server} 上未纳管的容器`}</DialogTitle>
          </DialogHeader>
          <div className="grid max-h-[60vh] gap-1.5 overflow-y-auto">
            {list.map((u) => (
              <UnmanagedRow key={target(u)} item={u} onImport={() => setImporting(u)} onRemove={() => setRemoving(u)} />
            ))}
          </div>
        </DialogContent>
      </Dialog>
      {importing && <ImportDialog item={importing} onClose={() => setImporting(null)} />}
      {removing && (
        <RemoveDialog
          item={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            setRemoving(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function UnmanagedRow({ item, onImport, onRemove }: { item: Unmanaged; onImport: () => void; onRemove: () => void }) {
  const total = item.containers.length;
  const running = item.containers.filter((c) => c.state === "running").length;
  const ports = item.containers.flatMap((c) => c.ports ?? []);
  return (
    <div className="flex items-center gap-3 rounded-lg border px-3 py-2">
      {item.project ? <LayersIcon className="size-4 shrink-0 text-muted-foreground" /> : <BoxIcon className="size-4 shrink-0 text-muted-foreground" />}
      <div className="grid min-w-0 flex-1 gap-0.5">
        <div className="flex items-center gap-2 text-sm font-medium">
          {target(item)}
          {item.project && <Badge variant="outline">compose · {total}</Badge>}
          <StatusBadge tone={running === total ? "ok" : running ? "warn" : "idle"}>
            {running === total ? "运行中" : running ? `${running}/${total} 运行` : "已停止"}
          </StatusBadge>
        </div>
        <div className="truncate font-mono text-xs text-muted-foreground">
          {[...new Set(item.containers.map((c) => c.image))].join(" ")}
          {ports.length > 0 && ` · ${ports.join(" ")}`}
        </div>
      </div>
      <Button variant="outline" size="xs" onClick={onImport}>
        <DownloadIcon />
        导入
      </Button>
      <Tip text="删除"><Button aria-label="删除" variant="ghost" size="icon-xs" className="text-destructive" onClick={onRemove}>
        <Trash2Icon />
      </Button></Tip>
    </div>
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
    actions.plan({ title: `导入 ${preview.name}`, changes: [{ op: "upsert_service", name: preview.name, spec: preview.spec, adopt: preview.adopt }] });
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
              <div className="font-mono text-xs text-muted-foreground">端口 {preview.spec.ports.map((p) => `${p.name}=${p.host}`).join(" ")}</div>
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
            预览改动
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** 删除没纳管的容器或 compose 项目，可以勾选连同具名数据卷一起删。 */
function RemoveDialog({ item, onClose, onDone }: { item: Unmanaged; onClose: () => void; onDone: () => void }) {
  const [volumes, setVolumes] = useState(false);
  const [busy, setBusy] = useState(false);
  const vols = [...new Set(item.containers.flatMap((c) => c.volumes ?? []))];
  const remove = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ containers: string[]; volumes: string[]; kept_volumes: string[] }>(
        `/api/servers/${encodeURIComponent(item.server)}/unmanaged/remove`,
        { project: item.project, container: item.container, volumes },
      );
      toast.success(`已删除 ${target(item)}`, {
        description: [
          `${r.containers.length} 个容器`,
          r.volumes.length ? `数据卷 ${r.volumes.join("、")}` : "",
          r.kept_volumes.length ? `还在被别的容器使用、没删：${r.kept_volumes.join("、")}` : "",
        ]
          .filter(Boolean)
          .join("；"),
      });
      onDone();
    } catch (e) {
      toast.error(`没删掉 ${target(item)}`, { description: (e as Error).message });
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog open title={`删除 ${item.server} 上的 ${target(item)}？`} typed={target(item)} busy={busy} confirmText={volumes ? "删除容器和数据卷" : "删除容器"} onCancel={onClose} onConfirm={remove}>
        <div className="grid gap-3 text-sm">
          <p className="text-muted-foreground">
            {item.project ? `compose 项目里的 ${item.containers.length} 个容器` : "这个容器"}会被强制停止并删除（docker rm -f），镜像保留。
          </p>
          {vols.length > 0 ? (
            <label className="flex cursor-pointer items-start gap-2.5">
              <Checkbox className="mt-0.5" checked={volumes} onCheckedChange={(v) => setVolumes(v === true)} />
              <span>
                连同数据卷一起删除
                <span className="block font-mono text-xs text-muted-foreground">{vols.join("、")}</span>
                <span className="block text-xs text-destructive">数据卷里的数据会永久丢失；还被别的容器用着的会跳过。</span>
              </span>
            </label>
          ) : (
            <p className="text-xs text-muted-foreground">没有具名数据卷。挂载的宿主机目录不会删。</p>
          )}
        </div>
    </ConfirmDialog>
  );
}
