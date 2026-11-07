import { EyeIcon, EyeOffIcon, FileTextIcon, RefreshCwIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { CodeBlock, Empty, ErrorNote, StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";

type HostUnit = {
  unit: string;
  description?: string;
  command?: string;
  working_dir?: string;
  user?: string;
  unit_file?: string;
  env_files?: string[];
  configs?: string[];
  state: string;
  since?: string;
  memory?: number;
  listens?: string[];
  domains?: string[];
  gateway?: boolean;
  watched: boolean;
};

const mb = (b?: number) => (b ? `${Math.round(b / 2 ** 20)} MB` : undefined);

/** 服务器"宿主机程序"标签：systemd 跑的、自己装的程序，只读。接管后停了会提醒。 */
export function ServerHostUnits({ server, online }: { server: string; online: boolean }) {
  const base = `/api/servers/${encodeURIComponent(server)}/host-units`;
  const [data, setData] = useState<HostUnit[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<{ unit: string; text: string | null } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.get<HostUnit[]>(base));
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [base]);
  useEffect(() => {
    if (online) load();
  }, [load, online]);

  const watch = async (u: HostUnit) => {
    try {
      await api.put(`${base}/${encodeURIComponent(u.unit)}/watch`, { watch: !u.watched });
      toast.success(u.watched ? `不再盯着 ${u.unit}` : `已接管 ${u.unit}：停了会提醒`);
      load();
    } catch (e) {
      toast.error("没改成", { description: (e as Error).message });
    }
  };
  const openLogs = async (unit: string) => {
    setLogs({ unit, text: null });
    try {
      const text = await api.get<string>(`${base}/${encodeURIComponent(unit)}/logs?lines=300`);
      setLogs({ unit, text: text || "（没有日志）" });
    } catch (e) {
      setLogs({ unit, text: `读取失败：${(e as Error).message}` });
    }
  };

  if (!online) return <Empty>服务器离线，读不到宿主机程序</Empty>;
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <p className="flex-1 text-sm text-muted-foreground">
          宿主机上 systemd 跑的、自己装的程序（unit 文件在 /etc/systemd/system），以及从 Caddy、nginx、cloudflared 配置反查到的域名。只读；"接管"后停了会进需要注意并推送。
        </p>
        <Button variant="ghost" size="sm" disabled={loading} onClick={load}>
          <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
          重新读取
        </Button>
      </div>
      <ErrorNote error={error} />
      {!data ? (
        loading && <Skeleton className="h-40 rounded-xl" />
      ) : data.length === 0 ? (
        <Empty>没有发现自己装的 systemd 程序</Empty>
      ) : (
        <div className="grid gap-3">
          {data.map((u) => (
            <div key={u.unit} className="rounded-xl border bg-card p-4 shadow-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold">{u.unit.replace(/\.service$/, "")}</span>
                <StatusBadge tone={u.state === "running" ? "ok" : u.state === "failed" ? "bad" : "warn"}>
                  {u.state === "running" ? "运行中" : u.state}
                </StatusBadge>
                {u.gateway && <Badge variant="outline">网关</Badge>}
                {u.watched && <Badge variant="secondary">已接管</Badge>}
                <span className="truncate text-xs text-muted-foreground">{u.description}</span>
                <span className="ml-auto flex gap-1">
                  <Button variant="ghost" size="xs" onClick={() => openLogs(u.unit)}>
                    <FileTextIcon />
                    日志
                  </Button>
                  <Button variant={u.watched ? "ghost" : "outline"} size="xs" onClick={() => watch(u)}>
                    {u.watched ? <EyeOffIcon /> : <EyeIcon />}
                    {u.watched ? "取消接管" : "接管"}
                  </Button>
                </span>
              </div>
              <dl className="mt-3 grid grid-cols-[72px_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                {u.command && <Item k="启动命令" v={u.command} mono />}
                {u.working_dir && <Item k="工作目录" v={u.working_dir} mono />}
                {(u.user || u.memory) && <Item k="运行" v={[u.user && `用户 ${u.user}`, mb(u.memory) && `内存 ${mb(u.memory)}`, u.since && `自 ${u.since}`].filter(Boolean).join(" · ")} />}
                {!!u.listens?.length && <Item k="监听" v={u.listens.join("  ")} mono />}
                {!!u.domains?.length && (
                  <>
                    <dt className="text-muted-foreground">域名</dt>
                    <dd className="flex flex-wrap gap-x-3 gap-y-0.5 font-mono">
                      {u.domains.map((d) => (
                        <a key={d} href={`https://${d}`} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                          {d}
                        </a>
                      ))}
                    </dd>
                  </>
                )}
                {u.unit_file && <Item k="unit 文件" v={u.unit_file} mono />}
                {!!u.configs?.length && <Item k="配置" v={u.configs.join("  ")} mono />}
              </dl>
            </div>
          ))}
        </div>
      )}
      <Dialog open={!!logs} onOpenChange={(o) => !o && setLogs(null)}>
        <DialogContent aria-describedby={undefined} className="sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{logs?.unit} 的日志</DialogTitle>
          </DialogHeader>
          <div className="max-h-[70vh] overflow-auto">{logs?.text === null ? <Skeleton className="h-60" /> : <CodeBlock>{logs?.text ?? ""}</CodeBlock>}</div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function Item({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className={mono ? "break-all font-mono" : undefined}>{v}</dd>
    </>
  );
}
