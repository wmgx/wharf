import { ObjectIssues } from "@/components/issues";
import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { Dot, Empty, Notice, SectionTitle, serviceTone } from "@/components/common";
import { Facts, Panel } from "@/components/kit";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { HostInfo, ServerView, Status } from "@/types";
import { ResourceNote } from "../service/note";
import { parseUpstream, size, type Traffic } from "./format";

export function Overview({ server, status, info, traffic, loading }: { server: ServerView; status: Status; info: HostInfo | null; traffic: Traffic | null; loading: boolean }) {
  const name = server.name;
  const r = server.report;
  const disk = r?.disk;
  const egress = r?.egress_info;
  const quota = r?.docker_quota;
  const quotaText = quota?.remaining != null && quota.limit != null && quota.window_secs != null
    ? `${quota.remaining} / ${quota.limit}（${quota.window_secs / 3600} 小时窗口，查于 ${quota.checked_at}）`
    : quota?.error
      ? `查不到（${quota.error}，查于 ${quota.checked_at}）`
      : "查不到";
  const mirror = !!server.settings.registry_mirrors?.["docker.io"]?.length;
  const agent = server.agent;
  const limit = (v: number) => v === 0 ? "不限" : size(v);
  const offset = server.clock_offset_ms;
  const services = status.services.filter((s) => s.spec.server === name);
  const gateways = status.gateways.filter((g) => g.spec.server === name);
  const ips = [server.public_ip, server.private_addr?.ip].filter(Boolean);
  const direct = status.routes.flatMap((r) => {
    if (r.spec.service || r.spec.redirect) return [];
    const upstream = parseUpstream(r.upstream || r.spec.upstream);
    if (!upstream) return [];
    const loopback = ["127.0.0.1", "localhost", "::1"].includes(upstream.host);
    return ips.includes(upstream.host) || (loopback && gateways.some((g) => g.name === r.gateway))
      ? [{ route: r, port: upstream.port }] : [];
  });
  const used = traffic ? traffic.rx + traffic.tx : 0;
  return <>
    <ObjectIssues kind="server" name={server.name} />
    {info?.reboot_required && <Notice kind="warn" className="mb-3">装了需要重启才生效的更新</Notice>}
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Stat label="CPU" value={info ? `负载 ${info.load[0].toFixed(2)}` : undefined} sub={info ? `${info.cpus} 核` : undefined} used={info ? info.load[0] / info.cpus : undefined} loading={!info && loading} />
      <Stat label="内存" value={info ? `可用 ${size(info.mem_available)}` : undefined} sub={info ? `共 ${size(info.mem_total)}` : undefined} used={info ? 1 - info.mem_available / info.mem_total : undefined} loading={!info && loading} />
      <Stat label="磁盘" value={disk ? `剩 ${size(disk.free)}` : undefined} sub={disk && <>共 {size(disk.total)}
      {server.disk_days_left != null && server.disk_days_left <= 90 && <span className={`block ${server.disk_days_left <= 14 ? "text-warning" : ""}`}>预计 {server.disk_days_left < 1 ? "不到 1" : Math.floor(server.disk_days_left)} 天写满</span>}
      {r?.docker_disk && r.docker_disk.total !== disk.total && <span className="block">Docker 盘剩 {size(r.docker_disk.free)}
      </span>}
      </>} used={disk ? 1 - disk.free / disk.total : undefined} />
      <Stat label="流量" value={traffic ? `本期 ${size(used)}` : undefined} sub={traffic ? traffic.quota ? `额度 ${size(traffic.quota)} · 已用 ${Math.round(used / traffic.quota * 100)}%` : `${traffic.since.slice(5)} 起` : undefined} used={traffic?.quota ? used / traffic.quota : undefined} />
      {agent && <Stat label="agent"
        value={agent.mem != null || agent.cpu != null
          ? `内存 ${agent.mem != null ? size(agent.mem) : "-"} · CPU ${agent.cpu != null ? `${agent.cpu.toFixed(1)}%` : "-"}`
          : undefined}
        sub={<>
          {agent.memory_limit == null || agent.configured_limit !== agent.memory_limit
            ? `设置 ${limit(agent.configured_limit)} · 上限 ${agent.memory_limit != null ? limit(agent.memory_limit) : "-"}`
            : `上限 ${limit(agent.memory_limit)}`}
          {agent.memory_pct != null && ` · 已用 ${agent.memory_pct.toFixed(1)}%`}
        </>}
        used={agent.memory_pct != null ? agent.memory_pct / 100 : undefined}
      />}
    </div>
    {agent?.limit_error && <Notice kind="warn" className="mt-3">agent 内存上限设置失败：{agent.limit_error}</Notice>}
    <SectionTitle>备注</SectionTitle>
    <ResourceNote path={`/api/servers/${encodeURIComponent(name)}/note`} value={server.note} />
    <SectionTitle>基本信息</SectionTitle>
    <Panel className="p-4">
      <Facts items={[
        ["公网 IP", server.public_ip !== (egress?.ipv4 ?? r?.public_ip) && server.public_ip && <span className="font-mono text-xs">
          {server.public_ip}
        </span>],
        ["出口 IPv4", <span className="font-mono text-xs">{egress?.ipv4 ?? r?.public_ip ?? "-"}</span>],
        ["出口 IPv6", <span className="font-mono text-xs">{egress?.ipv6 ?? (egress ? "无" : "-")}</span>],
        ["运营商", [egress?.asn, egress?.operator].filter(Boolean).join(" ") || "-"],
        ["地区", [egress?.country, egress?.city].filter(Boolean).join(" ") || "-"],
        ["Docker Hub 剩余额度", `${quotaText}${mirror ? " · 已设镜像源" : ""}`],
        ["内网地址", server.private_addr?.ip && <span className="font-mono text-xs">
          {server.private_addr.ip}
        </span>],
        ["延迟", server.rtt_ms != null ? `${server.rtt_ms} ms` : "-"],
        ["时间偏差", offset != null ? <span className={Math.abs(offset) > 5000 ? "text-warning" : undefined}>{Math.abs(offset) < 1000 ? "< 1 秒" : `${offset > 0 ? "快" : "慢"} ${(Math.abs(offset) / 1000).toFixed(1)} 秒`}</span> : "-"],
        ["系统", info ? `${info.os ?? r?.os ?? "-"} · 内核 ${info.kernel}` : r?.os],
        ["docker", r?.docker_version && `${r.docker_version}${r.compose_version ? ` · compose ${r.compose_version}` : ""}`],
        ["agent", r && `${r.version}${r.build ? ` · ${r.build}` : ""}`],
      ]} />
    </Panel>
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
            to={`/domains?tab=entries&entry=${g.name}`}
            className="rounded-lg border border-dashed bg-card px-3 py-1.5 text-sm hover:bg-accent"
          >
            入口 {g.name}
          </Link>
        ))}
        {direct.map(({ route: r, port }) => (
          <a
            key={r.id}
            href={r.url}
            target="_blank"
            rel="noreferrer"
            title={`直接指向 ${r.spec.upstream}`}
            className="flex items-center gap-1.5 rounded-lg border border-dashed bg-card px-3 py-1.5 text-sm hover:bg-accent"
          >
            <span className="font-mono">
              {r.spec.hostname}
            </span>
            <span className="text-xs text-muted-foreground">
              → :{port}
              {(r.core || port === "7700")
                ? " · Wharf 控制面"
                : ""}
            </span>
          </a>
        ))}
      </div>
    )}
  </>;
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
        <div className="text-xs text-muted-foreground">
          {label}
        </div>
        {loading ? (
          <Skeleton className="mt-2 h-5 w-24" />
        ) : (
          <div className="mt-1 truncate font-medium">
            {value ?? "-"}
          </div>
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
