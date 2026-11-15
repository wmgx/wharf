import { useState } from "react";
import { ShareDialog } from "@/components/share-dialog";
import { ArrowUpRightIcon, PlusIcon } from "lucide-react";
import { Empty, SectionTitle } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Probe } from "@/components/probe";
import { Button } from "@/components/ui/button";
import { OpMenu, routeOps } from "@/components/ops";
import type { RouteView } from "@/types";

export function DomainsTab({
  service,
  routes,
  onAdd,
}: {
  service: string;
  routes: RouteView[];
  onAdd: () => void;
}) {
  const [sharing, setSharing] = useState(false);
  const add = <div className="flex gap-2"><Button variant="outline" size="sm" onClick={() => setSharing(true)}>分享</Button><Button variant="outline" size="sm" onClick={onAdd}><PlusIcon />加域名</Button></div>;
  return (
    <div>
      <ShareDialog service={service} open={sharing} onClose={() => setSharing(false)} />
      <SectionTitle action={routes.length ? add : undefined}>域名</SectionTitle>
      {routes.length === 0 ? (
        <Empty action={add}>还没有域名，现在只能从内网访问</Empty>
      ) : (
        <Rows>
          {routes.map((r) => (
            <Row key={r.id} to={`/domains?open=${encodeURIComponent(r.spec.hostname)}`}>
              <a
                className="inline-flex min-w-0 flex-1 items-center gap-1 font-mono text-sm text-primary hover:underline"
                href={r.url}
                target="_blank"
                rel="noreferrer"
              >
                <span className="truncate">{r.url}</span>
                <ArrowUpRightIcon className="size-3.5 shrink-0" />
              </a>
              <Probe probe={r.probe} />
              <span className="text-xs text-muted-foreground">
                {r.gateway ? `经 ${r.gateway}` : ""}
                {r.spec.link === "tunnel" ? " · 反向隧道" : ""}
                {r.spec.expires_at != null && <span className={r.spec.expires_at <= Date.now() ? "text-warning" : ""}>{r.spec.expires_at <= Date.now() ? " · 已失效" : ` · 临时分享，${new Date(r.spec.expires_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })} 到期`}</span>}
              </span>
              <OpMenu ops={routeOps} target={r} label={`${r.spec.hostname} 的操作`} size="icon-sm" />
            </Row>
          ))}
        </Rows>
      )}
    </div>
  );
}
