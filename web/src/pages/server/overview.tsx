import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { Dot, Empty, Notice, SectionTitle, serviceTone } from "@/components/common";
import { Facts, Panel } from "@/components/kit";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { HostInfo, ServerView, Status } from "@/types";
import { size, type Traffic } from "./format";

export function Overview({ server, status, info, traffic, loading }: { server: ServerView; status: Status; info: HostInfo | null; traffic: Traffic | null; loading: boolean }) {
  const name = server.name;
  const r = server.report;
  const disk = r?.disk;
  const services = status.services.filter((s) => s.spec.server === name);
  const gateways = status.gateways.filter((g) => g.spec.server === name);
  const ips = [server.public_ip, server.private_addr?.ip].filter(Boolean);
  const direct = status.routes.filter((r) => !r.spec.service && ips.some((ip) => r.spec.upstream?.split(":")[0] === ip));
  const used = traffic ? traffic.rx + traffic.tx : 0;
  return <>
    {info?.reboot_required && <Notice kind="warn" className="mb-3">装了需要重启才生效的更新</Notice>}
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Stat label="CPU" value={info ? `负载 ${info.load[0].toFixed(2)}` : undefined} sub={info ? `${info.cpus} 核` : undefined} used={info ? info.load[0] / info.cpus : undefined} loading={!info && loading} />
      <Stat label="内存" value={info ? `可用 ${size(info.mem_available)}` : undefined} sub={info ? `共 ${size(info.mem_total)}` : undefined} used={info ? 1 - info.mem_available / info.mem_total : undefined} loading={!info && loading} />
      <Stat label="磁盘" value={disk ? `剩 ${size(disk.free)}` : undefined} sub={disk && <>共 {size(disk.total)}{r?.docker_disk && r.docker_disk.total !== disk.total && <span className="block">Docker 盘剩 {size(r.docker_disk.free)}
      </span>}
      </>} used={disk ? 1 - disk.free / disk.total : undefined} />
      <Stat label="流量" value={traffic ? `本期 ${size(used)}` : undefined} sub={traffic ? traffic.quota ? `额度 ${size(traffic.quota)} · 已用 ${Math.round(used / traffic.quota * 100)}%` : `${traffic.since.slice(5)} 起` : undefined} used={traffic?.quota ? used / traffic.quota : undefined} />
    </div>
    <SectionTitle>基本信息</SectionTitle>
    <Panel className="p-4">
      <Facts items={[
        ["公网 IP", server.public_ip && <span className="font-mono text-xs">
          {server.public_ip}
        </span>],
        ["内网地址", server.private_addr?.ip && <span className="font-mono text-xs">
          {server.private_addr.ip}
        </span>],
        ["延迟", server.rtt_ms != null ? `${server.rtt_ms} ms` : "-"],
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
        {direct.map((r) => (
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
              → :{r.spec.upstream?.split(":")[1]}
              {r.spec.upstream?.endsWith(":7700")
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
