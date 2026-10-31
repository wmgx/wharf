import { ArrowLeftIcon, ArrowUpCircleIcon, RefreshCwIcon, SettingsIcon, TerminalIcon, Trash2Icon } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { MetricsPanel } from "@/components/metrics";
import { Dot, Empty, ErrorNote, Notice, PageHeader, SectionTitle, StatusBadge, ago, serverText, serverTone, serviceTone } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { HostInfo, ServerView } from "@/types";

const DOCKER_KIND: Record<string, string> = {
  Images: "镜像",
  Containers: "容器",
  "Local Volumes": "数据卷",
  "Build Cache": "构建缓存",
};

function size(bytes?: number): string {
  if (bytes == null) return "-";
  const units = ["B", "K", "M", "G", "T"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)}${units[i]}`;
}

function uptime(secs: number): string {
  const days = Math.floor(secs / 86400);
  if (days > 0) return `${days} 天`;
  const hours = Math.floor(secs / 3600);
  return hours > 0 ? `${hours} 小时` : `${Math.floor(secs / 60)} 分钟`;
}

/** 宿主机信息每次打开现查（要起一个临时容器），不轮询。 */
function useHostInfo(name: string, online: boolean) {
  const [data, setData] = useState<HostInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await api.get<HostInfo>(`/api/servers/${encodeURIComponent(name)}/host`));
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [name]);
  useEffect(() => {
    setData(null);
    if (online) load();
  }, [load, online]);
  return { data, error, loading, load };
}

/** 服务器详情：系统、资源、待装更新、磁盘占用、上面跑的服务。 */
export function ServerDetail() {
  const { name = "" } = useParams();
  const { status } = useStatus();
  const actions = useActions();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const server = status?.servers.find((s) => s.name === name);
  const host = useHostInfo(name, !!server?.online);

  const back = (
    <Link className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground" to="/">
      <ArrowLeftIcon className="size-3.5" />
      港口
    </Link>
  );
  if (!server) {
    return (
      <>
        {back}
        {status ? <Empty>没有服务器 {name}</Empty> : <Skeleton className="h-44 rounded-xl" />}
      </>
    );
  }

  const r = server.report;
  const disk = r?.disk;
  const info = host.data;
  const services = status?.services.filter((s) => s.spec.server === name) ?? [];
  const gateways = status?.gateways.filter((g) => g.spec.server === name) ?? [];
  const terminalStatus = !server.settings.host_terminal ? "未开启" : !server.online ? "离线" : !server.host_shell ? "待升级" : undefined;

  return (
    <>
      {back}
      <PageHeader
        title={
          <>
            {name}
            <StatusBadge tone={serverTone(server)}>{serverText(server)}</StatusBadge>
          </>
        }
        description={!server.online && server.last_seen ? `最后在线 ${ago(server.last_seen)}` : undefined}
        actions={
          <>
            {terminalStatus ? (
              <Button variant="outline" size="sm" disabled>
                <TerminalIcon />
                {terminalStatus}
              </Button>
            ) : (
              <Button asChild variant="outline" size="sm">
                <Link to={`/servers/${encodeURIComponent(name)}/terminal`}>
                  <TerminalIcon />
                  终端
                </Link>
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => setSettingsOpen(true)}>
              <SettingsIcon />
              设置
            </Button>
            {server.agent_outdated && (
              <Button variant="outline" size="sm" onClick={() => actions.upgradeAgent(name)}>
                <ArrowUpCircleIcon />
                升级 agent
              </Button>
            )}
            <Button variant="outline" size="sm" disabled={!server.online} onClick={() => actions.prune(name)}>
              <Trash2Icon />
              清理镜像
            </Button>
            <Button variant="ghost" size="sm" disabled={!server.online || host.loading} onClick={host.load}>
              <RefreshCwIcon className={host.loading ? "animate-spin" : undefined} />
              刷新
            </Button>
          </>
        }
      />

      <ServerSettingsDialog server={server} open={settingsOpen} onOpenChange={setSettingsOpen} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="系统" value={info?.os ?? r?.os} sub={info ? `内核 ${info.kernel}` : r?.arch} loading={!info && host.loading} />
        <Stat
          label="负载"
          value={info ? info.load.map((l) => l.toFixed(2)).join(" ") : undefined}
          sub={info ? `${info.cpus} 核 · 已运行 ${uptime(info.uptime_secs)}` : undefined}
          loading={!info && host.loading}
        />
        <Stat
          label="内存"
          value={info ? `可用 ${size(info.mem_available)}` : undefined}
          sub={info ? `共 ${size(info.mem_total)}` : undefined}
          used={info ? 1 - info.mem_available / info.mem_total : undefined}
          loading={!info && host.loading}
        />
        <Stat
          label="磁盘"
          value={disk ? `剩 ${size(disk.free)}` : undefined}
          sub={disk ? `共 ${size(disk.total)}` : undefined}
          used={disk ? 1 - disk.free / disk.total : undefined}
        />
      </div>

      <dl className="mt-4 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
        <Row k="公网 IP" v={server.public_ip} />
        <Row k="内网地址" v={server.private_addr?.ip} />
        <Row k="docker" v={r?.docker_version && `${r.docker_version}${r.compose_version ? ` · compose ${r.compose_version}` : ""}`} />
        <Row k="agent" v={r && `${r.version}${r.build ? ` · ${r.build}` : ""}`} />
      </dl>

      <MetricsPanel subject={name} kind="host" />

      <ErrorNote error={host.error} />

      {info && (
        <>
          <SectionTitle count={info.updates?.length}>待装更新</SectionTitle>
          {info.reboot_required && <Notice kind="warn" className="mb-3">需要重启</Notice>}
          {!info.updates ? (
            <Empty>不是 apt 系统</Empty>
          ) : info.updates.length === 0 ? (
            <Empty>没有</Empty>
          ) : (
            <div className="rounded-xl border bg-card">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>包</TableHead>
                    <TableHead>当前</TableHead>
                    <TableHead>新版本</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {[...info.updates]
                    .sort((a, b) => Number(b.security) - Number(a.security))
                    .map((u) => (
                      <TableRow key={u.name}>
                        <TableCell className="font-mono text-xs">
                          {u.name}
                          {u.security && (
                            <Badge variant="destructive" className="ml-2">
                              安全
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{u.from || "新装"}</TableCell>
                        <TableCell className="font-mono text-xs">{u.to}</TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </div>
          )}

          <SectionTitle>磁盘占用</SectionTitle>
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead className="text-right">数量</TableHead>
                  <TableHead className="text-right">占用</TableHead>
                  <TableHead className="text-right">可回收</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {info.docker.map((d) => (
                  <TableRow key={d.kind}>
                    <TableCell>{DOCKER_KIND[d.kind] ?? d.kind}</TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {d.total}
                      <span className="text-muted-foreground"> / {d.active} 在用</span>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">{d.size}</TableCell>
                    <TableCell className="text-right font-mono text-xs text-muted-foreground">{d.reclaimable}</TableCell>
                  </TableRow>
                ))}
                <LogRow label="容器日志" bytes={info.container_logs} />
                <LogRow label="journal" bytes={info.journal} />
                <LogRow label="/var/log" bytes={info.var_log} />
              </TableBody>
            </Table>
          </div>
        </>
      )}

      <SectionTitle count={services.length + gateways.length}>在这台机器上</SectionTitle>
      {services.length + gateways.length === 0 ? (
        <Empty>没有服务</Empty>
      ) : (
        <div className="flex flex-wrap gap-2">
          {gateways.map((g) => (
            <Link key={g.name} to={`/gateways?open=${g.name}`} className="rounded-lg border bg-card px-3 py-1.5 text-sm hover:bg-accent">
              {g.name}
              <span className="ml-2 text-xs text-muted-foreground">网关</span>
            </Link>
          ))}
          {services.map((s) => (
            <Link key={s.name} to={`/services/${s.name}`} className="flex items-center gap-2 rounded-lg border bg-card px-3 py-1.5 text-sm hover:bg-accent">
              <Dot tone={serviceTone(s).tone} />
              {s.name}
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function ServerSettingsDialog({ server, open, onOpenChange }: { server: ServerView; open: boolean; onOpenChange: (open: boolean) => void }) {
  const actions = useActions();
  const [hostTerminal, setHostTerminal] = useState(server.settings.host_terminal);
  const [hostExec, setHostExec] = useState(server.settings.host_exec);
  useEffect(() => {
    if (!open) return;
    setHostTerminal(server.settings.host_terminal);
    setHostExec(server.settings.host_exec);
  }, [open, server.settings.host_exec, server.settings.host_terminal]);
  const changed = hostTerminal !== server.settings.host_terminal || hostExec !== server.settings.host_exec;
  const save = () => {
    onOpenChange(false);
    actions.plan({
      title: `设置 ${server.name}`,
      changes: [{ op: "update_server", name: server.name, settings: { ...server.settings, host_terminal: hostTerminal, host_exec: hostExec } }],
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>设置</DialogTitle>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="flex items-center gap-3 rounded-lg border p-3">
            <Checkbox id="host-terminal" checked={hostTerminal} onCheckedChange={(value) => setHostTerminal(value === true)} />
            <Label htmlFor="host-terminal" className="cursor-pointer">宿主机终端</Label>
            <span className="ml-auto text-sm text-muted-foreground">{hostTerminal ? "已开启" : "未开启"}</span>
          </div>
          <div className="flex items-center gap-3 rounded-lg border p-3">
            <Checkbox id="host-exec" checked={hostExec} onCheckedChange={(value) => setHostExec(value === true)} />
            <Label htmlFor="host-exec" className="cursor-pointer">命令执行</Label>
            <span className="ml-auto text-sm text-muted-foreground">{hostExec ? "已开启" : "未开启"}</span>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button disabled={!changed} onClick={save}>
            生成计划
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Stat({ label, value, sub, used, loading }: { label: string; value?: ReactNode; sub?: ReactNode; used?: number; loading?: boolean }) {
  return (
    <Card className="py-4">
      <CardContent className="px-4">
        <div className="text-xs text-muted-foreground">{label}</div>
        {loading ? (
          <Skeleton className="mt-2 h-5 w-24" />
        ) : (
          <div className="mt-1 truncate font-medium">{value ?? "-"}</div>
        )}
        {sub && <div className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</div>}
        {used != null && (
          <div className="mt-2 h-1 overflow-hidden rounded-full bg-muted">
            <div className={`h-full rounded-full ${used > 0.9 ? "bg-destructive" : used > 0.75 ? "bg-warning" : "bg-primary/60"}`} style={{ width: `${Math.min(100, used * 100)}%` }} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Row({ k, v }: { k: string; v?: string | null | false }) {
  if (!v) return null;
  return (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="font-mono text-xs leading-5">{v}</dd>
    </>
  );
}

function LogRow({ label, bytes }: { label: string; bytes?: number }) {
  return (
    <TableRow>
      <TableCell>{label}</TableCell>
      <TableCell />
      <TableCell className="text-right font-mono text-xs">{size(bytes)}</TableCell>
      <TableCell />
    </TableRow>
  );
}
