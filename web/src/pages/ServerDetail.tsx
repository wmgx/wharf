import {
  ArrowLeftIcon,
  ArrowUpCircleIcon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { toast } from "sonner";
import { CodeEditor } from "@/components/code-editor";
import { Field, formatEnv, parseEnv } from "@/components/fields";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { MetricsPanel } from "@/components/metrics";
import { ServerLinks } from "./server-links";
import { ServerBaseline } from "./server-baseline";
import { ServiceUsage } from "@/components/usage";
import {
  Dot,
  Empty,
  ErrorNote,
  Notice,
  PageHeader,
  SectionTitle,
  StatusBadge,
  ago,
  serverText,
  serverTone,
  serviceTone,
} from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { EgressFields } from "./server-egress";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AptUpgrade } from "@/components/apt-upgrade";
import { HostSessions } from "@/components/host-sessions";
import { useStatus } from "@/status";
import type { EgressSpec, HostInfo, ServerView } from "@/types";

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
      setData(
        await api.get<HostInfo>(
          `/api/servers/${encodeURIComponent(name)}/host`,
        ),
      );
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

interface Traffic {
  since: string;
  rx: number;
  tx: number;
  quota?: number;
}

/** 本周期流量：控制面按上报的网速累加，打开时读一次。 */
function useTraffic(name: string) {
  const [data, setData] = useState<Traffic | null>(null);
  useEffect(() => {
    setData(null);
    api
      .get<Traffic>(`/api/servers/${encodeURIComponent(name)}/traffic`)
      .then(setData)
      .catch(() => setData(null));
  }, [name]);
  return data;
}

function trafficText(t: Traffic | null): string | undefined {
  if (!t) return undefined;
  const used = t.rx + t.tx;
  const quota = t.quota
    ? ` · 额度 ${size(t.quota)}，已用 ${Math.round((used / t.quota) * 100)}%`
    : "";
  return `收 ${size(t.rx)} · 发 ${size(t.tx)}（${t.since.slice(5)} 起）${quota}`;
}

/** 服务器详情：系统、资源、待装更新、磁盘占用、上面跑的服务。 */
export function ServerDetail() {
  const { name = "" } = useParams();
  const { status } = useStatus();
  const actions = useActions();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "overview";
  const server = status?.servers.find((s) => s.name === name);
  const host = useHostInfo(name, !!server?.online);
  const traffic = useTraffic(name);

  const back = (
    <Link
      className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground md:hidden"
      to="/servers"
    >
      <ArrowLeftIcon className="size-3.5" />
      服务器
    </Link>
  );
  if (!server) {
    return (
      <>
        {back}
        {status ? (
          <Empty>没有服务器 {name}</Empty>
        ) : (
          <Skeleton className="h-44 rounded-xl" />
        )}
      </>
    );
  }

  const r = server.report;
  const disk = r?.disk;
  const info = host.data;
  const services = status?.services.filter((s) => s.spec.server === name) ?? [];
  const gateways = status?.gateways.filter((g) => g.spec.server === name) ?? [];
  // 不指向服务、直接指向这台机器某个端口的域名（例如 Wharf 控制面自己）。
  const ips = [server.public_ip, server.private_addr?.ip].filter(Boolean);
  const direct =
    status?.routes.filter(
      (r) =>
        !r.spec.service &&
        ips.some((ip) => r.spec.upstream?.split(":")[0] === ip),
    ) ?? [];
  const terminalStatus = !server.settings.host_terminal
    ? "未开启"
    : !server.online
      ? "离线"
      : !server.host_shell
        ? "待升级"
        : undefined;

  return (
    <>
      {back}
      <PageHeader
        title={
          <>
            {name}
            <StatusBadge tone={serverTone(server)}>
              {serverText(server)}
            </StatusBadge>
          </>
        }
        description={
          !server.online && server.last_seen
            ? `最后在线 ${ago(server.last_seen)}`
            : r
              ? `${r.os} · ${r.arch}`
              : undefined
        }
        actions={
          server.agent_outdated && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => actions.upgradeAgent(name)}
            >
              <ArrowUpCircleIcon />
              升级 agent
            </Button>
          )
        }
      />

      <Tabs
        value={tab}
        onValueChange={(t) =>
          setParams(t === "overview" ? {} : { tab: t }, { replace: true })
        }
      >
        <TabsList className="max-w-full justify-start overflow-x-auto">
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="metrics">资源</TabsTrigger>
          <TabsTrigger value="system">系统</TabsTrigger>
          <TabsTrigger value="network">网络</TabsTrigger>
          <TabsTrigger value="terminal">终端</TabsTrigger>
          <TabsTrigger value="settings">设置</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              label="系统"
              value={info?.os ?? r?.os}
              sub={info ? `内核 ${info.kernel}` : r?.arch}
              loading={!info && host.loading}
            />
            <Stat
              label="负载"
              value={
                info ? info.load.map((l) => l.toFixed(2)).join(" ") : undefined
              }
              sub={
                info
                  ? `${info.cpus} 核 · 已运行 ${uptime(info.uptime_secs)}`
                  : undefined
              }
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
            <Row k="本期流量" v={trafficText(traffic)} />
            <Row
              k="docker"
              v={
                r?.docker_version &&
                `${r.docker_version}${r.compose_version ? ` · compose ${r.compose_version}` : ""}`
              }
            />
            <Row
              k="agent"
              v={r && `${r.version}${r.build ? ` · ${r.build}` : ""}`}
            />
          </dl>
          <SectionTitle
            count={services.length + gateways.length + direct.length}
          >
            在这台机器上
          </SectionTitle>
          {services.length + gateways.length + direct.length === 0 ? (
            <Empty>还没有服务</Empty>
          ) : (
            <div className="flex flex-wrap gap-2">
              {services.map((s) => (
                <Link
                  key={s.name}
                  to={`/services/${s.name}`}
                  className="flex items-center gap-2 rounded-lg border bg-card px-3 py-1.5 text-sm hover:bg-accent"
                >
                  <Dot tone={serviceTone(s).tone} />
                  {s.name}
                </Link>
              ))}
              {gateways.map((g) => (
                <Link
                  key={g.name}
                  to={`/entries?open=${g.name}`}
                  className="rounded-lg border border-dashed bg-card px-3 py-1.5 text-sm hover:bg-accent"
                >
                  入口 {g.name}
                </Link>
              ))}
              {direct.map((r) => (
                <a
                  key={r.id}
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  title={`直接指向 ${r.spec.upstream}`}
                  className="flex items-center gap-1.5 rounded-lg border border-dashed bg-card px-3 py-1.5 text-sm hover:bg-accent"
                >
                  <span className="font-mono">{r.spec.hostname}</span>
                  <span className="text-xs text-muted-foreground">
                    → :{r.spec.upstream?.split(":")[1]}
                    {r.spec.upstream?.endsWith(":7700")
                      ? " · Wharf 控制面"
                      : ""}
                  </span>
                </a>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="metrics" className="mt-4">
          <MetricsPanel subject={name} kind="host" title="" />
          <ServiceUsage server={name} />
        </TabsContent>

        <TabsContent value="system" className="mt-4">
          <ServerBaseline server={server} />
          <div className="mb-4 flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!server.online}
              onClick={() => actions.prune(name)}
            >
              <Trash2Icon />
              清理没在用的镜像
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={!server.online || host.loading}
              onClick={host.load}
            >
              <RefreshCwIcon
                className={host.loading ? "animate-spin" : undefined}
              />
              重新读取
            </Button>
          </div>
          <ErrorNote error={host.error} />
          {!info ? (
            host.loading ? (
              <Skeleton className="h-40 rounded-xl" />
            ) : (
              <Empty>
                {server.online ? "读取中…" : "服务器离线，读不到系统信息"}
              </Empty>
            )
          ) : (
            <SystemInfo
              info={info}
              apt={
                <AptUpgrade
                  server={server.name}
                  enabled={server.online && !!server.settings.host_terminal}
                  count={info.updates?.length ?? 0}
                  onDone={host.load}
                />
              }
            />
          )}
        </TabsContent>

        <TabsContent value="network" className="mt-4">
          <ServerLinks server={name} />
          <SectionTitle>网络设置</SectionTitle>
          <SettingsForm server={server} canRemove={false} section="network" />
        </TabsContent>

        <TabsContent value="terminal" className="mt-4">
          {terminalStatus ? (
            <Empty>
              {terminalStatus === "未开启"
                ? "宿主机终端没有开启，在“设置”标签里打开。"
                : terminalStatus === "离线"
                  ? "服务器离线。"
                  : "agent 版本太旧，先升级 agent。"}
            </Empty>
          ) : (
            <HostSessions server={name} />
          )}
        </TabsContent>

        <TabsContent value="settings" className="mt-4">
          <SettingsForm
            server={server}
            canRemove={services.length + gateways.length === 0}
          />
        </TabsContent>
      </Tabs>
    </>
  );
}

function SystemInfo({ info, apt }: { info: HostInfo; apt: ReactNode }) {
  return (
    <>
      <SectionTitle count={info.updates?.length}>待装更新</SectionTitle>
      {info.updates && apt}
      {info.reboot_required && (
        <Notice kind="warn" className="mb-3">
          需要重启
        </Notice>
      )}
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
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {u.from || "新装"}
                    </TableCell>
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
                  <span className="text-muted-foreground">
                    {" "}
                    / {d.active} 在用
                  </span>
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {d.size}
                </TableCell>
                <TableCell className="text-right font-mono text-xs text-muted-foreground">
                  {d.reclaimable}
                </TableCell>
              </TableRow>
            ))}
            <LogRow label="容器日志" bytes={info.container_logs} />
            <LogRow label="journal" bytes={info.journal} />
            <LogRow label="/var/log" bytes={info.var_log} />
          </TableBody>
        </Table>
      </div>
      {!!info.ssh_logins?.length && (
        <>
          <SectionTitle>SSH 登录</SectionTitle>
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>用户</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>方式</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {info.ssh_logins.map((l, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <span title={new Date(l.at).toLocaleString("zh-CN")}>
                        {ago(l.at)}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {l.user}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {l.from}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {l.method}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}
    </>
  );
}

type Settings = ServerView["settings"] & {
  public_ip?: string;
  registry_mirrors?: Record<string, string[]>;
  mirrors_only?: boolean;
  build_env?: Record<string, string>;
  git_proxy?: string;
  pull_proxy?: string;
  github_mirror?: string;
  lan_addrs?: string[];
  traffic_quota_gb?: number;
  traffic_reset_day?: number;
};

/** 私有网段 IPv4：10/8、172.16/12、192.168/16。公网地址不能绑，否则服务直接暴露。 */
const isPrivate = (ip: string) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+(\.\d+)?$/.test(ip) &&
  ip.split(".").length === 4;

const mirrorsText = (m?: Record<string, string[]>) =>
  Object.entries(m ?? {})
    .map(([k, v]) => `${k}=${v.join(",")}`)
    .join("\n");

function parseMirrors(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf("=");
    if (i <= 0) continue;
    const list = line
      .slice(i + 1)
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    if (list.length) out[line.slice(0, i).trim()] = list;
  }
  return out;
}

/** 服务器设置：和 `wharf server set` 同一组字段；网络相关字段在"网络"标签。 */
/** 服务器设置。`network` 只放公网 IP、局域网、出口和代理，其余在"设置"标签。 */
function SettingsForm({
  server,
  canRemove,
  section = "settings",
}: {
  server: ServerView;
  canRemove: boolean;
  section?: "settings" | "network";
}) {
  const net = section === "network";
  const actions = useActions();
  const nav = useNavigate();
  const cur = server.settings as Settings;
  const [publicIp, setPublicIp] = useState(cur.public_ip ?? "");
  const [mirrors, setMirrors] = useState(mirrorsText(cur.registry_mirrors));
  const [mirrorsOnly, setMirrorsOnly] = useState(!!cur.mirrors_only);
  const [buildEnv, setBuildEnv] = useState(formatEnv(cur.build_env));
  const [gitProxy, setGitProxy] = useState(cur.git_proxy ?? "");
  const [pullProxy, setPullProxy] = useState(cur.pull_proxy ?? "");
  const [githubMirror, setGithubMirror] = useState(cur.github_mirror ?? "");
  const [lanAddrs, setLanAddrs] = useState<string[]>(cur.lan_addrs ?? []);
  // 候选：agent 上报的私有网段地址，加上已经设置的。
  const lanChoices = [
    ...new Set([
      ...(server.report?.lan_ips ?? []).filter(isPrivate),
      ...(cur.lan_addrs ?? []),
    ]),
  ];
  const [hostTerminal, setHostTerminal] = useState(cur.host_terminal);
  const [hostExec, setHostExec] = useState(cur.host_exec);
  const [egress, setEgress] = useState<EgressSpec | undefined>(cur.egress);
  const [via, setVia] = useState(cur.via ?? "");
  const [quota, setQuota] = useState(
    cur.traffic_quota_gb ? String(cur.traffic_quota_gb) : "",
  );
  const [resetDay, setResetDay] = useState(
    cur.traffic_reset_day ? String(cur.traffic_reset_day) : "",
  );
  const quotaNum = Number(quota.trim() || 0);
  const resetNum = Number(resetDay.trim() || 0);
  const trafficValid =
    Number.isInteger(quotaNum) &&
    quotaNum >= 0 &&
    Number.isInteger(resetNum) &&
    resetNum >= 0 &&
    resetNum <= 28;
  const [removing, setRemoving] = useState(false);

  const next: Settings = {
    ...cur,
    public_ip: publicIp.trim() || undefined,
    registry_mirrors: parseMirrors(mirrors),
    mirrors_only: mirrorsOnly,
    build_env: parseEnv(buildEnv),
    git_proxy: gitProxy.trim() || undefined,
    pull_proxy: pullProxy.trim() || undefined,
    github_mirror: githubMirror.trim().replace(/\/+$/, "") || undefined,
    lan_addrs: lanAddrs.length ? lanAddrs : undefined,
    host_terminal: hostTerminal,
    host_exec: hostExec,
    egress,
    via: via || undefined,
    traffic_quota_gb: quotaNum > 0 ? quotaNum : undefined,
    traffic_reset_day: resetNum > 0 ? resetNum : undefined,
  };
  const norm = (x: Settings) =>
    JSON.stringify({
      ...x,
      public_ip: x.public_ip || undefined,
      git_proxy: x.git_proxy || undefined,
      pull_proxy: x.pull_proxy || undefined,
      github_mirror: x.github_mirror || undefined,
      registry_mirrors: x.registry_mirrors ?? {},
      build_env: x.build_env ?? {},
      mirrors_only: !!x.mirrors_only,
      egress: x.egress ?? undefined,
      via: x.via || undefined,
      lan_addrs: x.lan_addrs?.length ? x.lan_addrs : undefined,
    });
  const changed = norm(next) !== norm(cur);

  const remove = async () => {
    setRemoving(false);
    try {
      await api.del(`/api/servers/${encodeURIComponent(server.name)}`);
      toast.success(`已删除服务器 ${server.name}`);
      nav("/servers");
    } catch (e) {
      toast.error(`不能删除 ${server.name}`, {
        description: (e as Error).message,
      });
    }
  };

  return (
    <div className="grid max-w-2xl gap-5">
      {net && (
        <>
          <Field
            label="公网 IP"
            htmlFor="public-ip"
            help={`不填用 agent 探测的${server.public_ip ? `（现在是 ${server.public_ip}）` : ""}。直连入口的 DNS 指向它。`}
          >
            <Input
              id="public-ip"
              value={publicIp}
              placeholder="自动探测"
              onChange={(e) => setPublicIp(e.target.value)}
            />
          </Field>
        </>
      )}
      {!net && (
        <>
          <Field
            label="镜像源"
            htmlFor="mirrors"
            help="每行一个仓库，例如 docker.io=docker.1ms.run,docker.m.daocloud.io，按顺序尝试。"
          >
            <Textarea
              id="mirrors"
              rows={3}
              className="font-mono text-xs"
              value={mirrors}
              onChange={(e) => setMirrors(e.target.value)}
            />
          </Field>
          <label className="-mt-3 flex cursor-pointer items-center gap-2 text-sm">
            <Checkbox
              checked={mirrorsOnly}
              onCheckedChange={(v) => setMirrorsOnly(v === true)}
            />
            有镜像源时不再尝试原地址
          </label>
          <Field
            label="构建参数"
            htmlFor="build-env"
            help="每行 KEY=VALUE，传给内置模板。国内机器常配 PIP_INDEX_URL、GOPROXY。"
          >
            <CodeEditor
              id="build-env"
              lang="env"
              className="min-h-16"
              value={buildEnv}
              onChange={setBuildEnv}
            />
          </Field>
        </>
      )}
      {net && (
        <>
          <Field
            label="局域网访问"
            help="勾选后，镜像和代码部署的服务端口也绑到这些地址，同一局域网里可以直接打开。机器之间仍走内网地址。保存后这台机器上的服务会重建容器。"
          >
            {lanChoices.length ? (
              <div className="grid gap-2">
                {lanChoices.map((ip) => (
                  <label
                    key={ip}
                    className="flex cursor-pointer items-center gap-2.5 font-mono text-sm"
                  >
                    <Checkbox
                      checked={lanAddrs.includes(ip)}
                      onCheckedChange={(v) =>
                        setLanAddrs(
                          v === true
                            ? [...lanAddrs, ip]
                            : lanAddrs.filter((x) => x !== ip),
                        )
                      }
                    />
                    {ip}
                  </label>
                ))}
              </div>
            ) : (
              <span className="text-sm text-muted-foreground">
                agent 没有发现私有网段的地址
              </span>
            )}
          </Field>
          <EgressFields
            server={server.name}
            egress={egress}
            onEgress={setEgress}
            via={via}
            onVia={setVia}
          />
          <Field
            label="拉代码代理"
            htmlFor="git-proxy"
            help="只用于 git。国内机器连不上 GitHub 时经海外机器转发。"
          >
            <Input
              id="git-proxy"
              value={gitProxy}
              placeholder="http://100.x.x.x:8118"
              onChange={(e) => setGitProxy(e.target.value)}
            />
          </Field>
          <Field
            label="拉镜像代理"
            htmlFor="pull-proxy"
            help="写进宿主机 dockerd 配置，ghcr 等海外仓库经它拉，镜像源和内网直连。执行时会重启 dockerd（开启 live-restore，容器不停）。"
          >
            <Input
              id="pull-proxy"
              value={pullProxy}
              placeholder="http://100.x.x.x:8118"
              onChange={(e) => setPullProxy(e.target.value)}
            />
          </Field>
          <Field
            label="GitHub 镜像"
            htmlFor="github-mirror"
            help="拉代码时代替 https://github.com/ 的地址（Wharf 的 mirror 服务），可以用 [[密钥名]] 引用访问口令。"
          >
            <Input
              id="github-mirror"
              value={githubMirror}
              placeholder="https://gh.example.com/[[MIRROR_TOKEN]]"
              onChange={(e) => setGithubMirror(e.target.value)}
            />
          </Field>
        </>
      )}
      {!net && (
        <>
          <Field
            label="流量"
            help="每月额度（GB）和重置日（1 到 28，北京时间），只用于显示本期用了多少。都不填按每月 1 号算、不显示额度。"
          >
            <div className="flex gap-2">
              <Input
                inputMode="numeric"
                className="w-32"
                value={quota}
                placeholder="额度 GB"
                onChange={(e) => setQuota(e.target.value)}
              />
              <Input
                inputMode="numeric"
                className="w-32"
                value={resetDay}
                placeholder="重置日"
                onChange={(e) => setResetDay(e.target.value)}
              />
            </div>
          </Field>
          <div className="grid gap-2">
            <label className="flex cursor-pointer items-center gap-2.5 text-sm">
              <Checkbox
                checked={hostTerminal}
                onCheckedChange={(v) => setHostTerminal(v === true)}
              />
              允许从页面打开宿主机终端
            </label>
            <label className="flex cursor-pointer items-center gap-2.5 text-sm">
              <Checkbox
                checked={hostExec}
                onCheckedChange={(v) => setHostExec(v === true)}
              />
              允许通过 API 在宿主机执行命令（CLI、AI 用）
            </label>
          </div>
        </>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          disabled={!changed || !trafficValid}
          onClick={() =>
            actions.plan({
              title: `设置 ${server.name}`,
              changes: [
                { op: "update_server", name: server.name, settings: next },
              ],
            })
          }
        >
          预览改动
        </Button>
      </div>
      {!net && (
        <div className="mt-6 flex flex-wrap items-center gap-3 rounded-xl border border-destructive/30 p-4">
          <div className="grid flex-1 gap-0.5 text-sm">
            <span className="font-medium">删除服务器</span>
            <span className="text-xs text-muted-foreground">
              {canRemove
                ? "只删除 Wharf 里的记录，机器上的 agent 需要自己停掉。"
                : "上面还有服务或入口，先迁走或删掉。"}
            </span>
          </div>
          <Button
            variant="destructive"
            size="sm"
            disabled={!canRemove}
            onClick={() => setRemoving(true)}
          >
            删除
          </Button>
        </div>
      )}
      <Dialog open={removing} onOpenChange={setRemoving}>
        <DialogContent aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>删除服务器 {server.name}？</DialogTitle>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRemoving(false)}>
              取消
            </Button>
            <Button variant="destructive" onClick={remove}>
              删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Stat({
  label,
  value,
  sub,
  used,
  loading,
}: {
  label: string;
  value?: ReactNode;
  sub?: ReactNode;
  used?: number;
  loading?: boolean;
}) {
  return (
    <Card className="py-4">
      <CardContent className="px-4">
        <div className="text-xs text-muted-foreground">{label}</div>
        {loading ? (
          <Skeleton className="mt-2 h-5 w-24" />
        ) : (
          <div className="mt-1 truncate font-medium">{value ?? "-"}</div>
        )}
        {sub && (
          <div className="mt-0.5 truncate text-xs text-muted-foreground">
            {sub}
          </div>
        )}
        {used != null && (
          <div className="mt-2 h-1 overflow-hidden rounded-full bg-muted">
            <div
              className={`h-full rounded-full ${used > 0.9 ? "bg-destructive" : used > 0.75 ? "bg-warning" : "bg-primary/60"}`}
              style={{ width: `${Math.min(100, used * 100)}%` }}
            />
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
      <TableCell className="text-right font-mono text-xs">
        {size(bytes)}
      </TableCell>
      <TableCell />
    </TableRow>
  );
}
