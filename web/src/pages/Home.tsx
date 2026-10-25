import { ArrowUpRightIcon, PlusIcon } from "lucide-react";
import { useState, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import { CardsSkeleton, Empty, Mark, PageHeader, SectionTitle, ServerTag, StatusBadge, serviceTone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import { NewService } from "./NewService";

const card =
  "group flex flex-col gap-3 rounded-xl border bg-card p-4 shadow-xs transition-all hover:-translate-y-px hover:border-foreground/15 hover:shadow-md animate-in fade-in slide-in-from-bottom-1 fill-mode-both";

/** 首页导航：每条路由一张卡片，直接点开；没有域名的服务给内网地址。 */
export function Home() {
  const { status, refresh } = useStatus();
  const [creating, setCreating] = useState(false);

  const byService = new Map(status?.services.map((s) => [s.name, s]));
  const routed = new Set(status?.routes.map((r) => r.spec.service));
  const internal = status?.services.filter((s) => !routed.has(s.name)) ?? [];

  return (
    <>
      <PageHeader
        title="港口"
        description={status ? `${status.servers.length} 台服务器 · ${status.services.length} 个服务 · ${status.routes.length} 个域名` : "载入中…"}
        actions={
          <Button onClick={() => setCreating(true)}>
            <PlusIcon />
            新建服务
          </Button>
        }
      />

      <SectionTitle count={status?.routes.length}>域名</SectionTitle>
      {!status ? (
        <CardsSkeleton />
      ) : status.routes.length === 0 ? (
        <Empty>还没有域名</Empty>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-3">
          {status.routes.map((r, i) => {
            const svc = r.spec.service ? byService.get(r.spec.service) : undefined;
            const label = r.spec.service || r.spec.upstream || "-";
            const { tone, text } = serviceTone(svc);
            return (
              <a className={card} style={{ animationDelay: `${i * 30}ms` } as CSSProperties} key={r.id} href={r.url} target="_blank" rel="noreferrer">
                <div className="flex items-center gap-3">
                  <Mark name={label} url={r.url} />
                  <div className="min-w-0">
                    <div className={r.spec.service ? "font-semibold" : "font-mono text-sm font-semibold"}>{label}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">{r.url.replace(/^https?:\/\//, "")}</div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5">
                  {svc && <StatusBadge tone={tone}>{text}</StatusBadge>}
                  <ServerTag name={svc?.spec.server ?? "-"} />
                  <ArrowUpRightIcon className="ml-auto size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-primary" />
                </div>
              </a>
            );
          })}
        </div>
      )}

      {internal.length > 0 && (
        <>
          <SectionTitle count={internal.length}>只在内网</SectionTitle>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-3">
            {internal.map((s, i) => {
              const { tone, text } = serviceTone(s);
              return (
                <Link className={card} style={{ animationDelay: `${i * 30}ms` }} key={s.name} to={`/services/${s.name}`}>
                  <div className="flex items-center gap-3">
                    <Mark name={s.name} />
                    <div className="min-w-0">
                      <div className="font-semibold">{s.name}</div>
                      {Object.entries(s.addresses).map(([port, addr]) => (
                        <div className="truncate font-mono text-xs text-muted-foreground" key={port}>
                          {addr}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <StatusBadge tone={tone}>{text}</StatusBadge>
                    <ServerTag name={s.spec.server} />
                  </div>
                </Link>
              );
            })}
          </div>
        </>
      )}

      <NewService
        open={creating}
        onClose={() => {
          setCreating(false);
          refresh();
        }}
      />
    </>
  );
}
