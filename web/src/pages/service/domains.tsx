import { ArrowUpRightIcon, PlusIcon } from "lucide-react";
import { Empty, SectionTitle } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Probe } from "@/components/probe";
import { Button } from "@/components/ui/button";
import { OpMenu, routeOps } from "@/components/ops";
import type { RouteView } from "@/types";

export function DomainsTab({
  routes,
  onAdd,
}: {
  routes: RouteView[];
  onAdd: () => void;
}) {
  const add = <Button variant="outline" size="sm" onClick={onAdd}><PlusIcon />加域名</Button>;
  return (
    <div>
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
              </span>
              <OpMenu ops={routeOps} target={r} label={`${r.spec.hostname} 的操作`} size="icon-sm" />
            </Row>
          ))}
        </Rows>
      )}
    </div>
  );
}
