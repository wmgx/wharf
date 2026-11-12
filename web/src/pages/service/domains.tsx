import { ArrowUpRightIcon, LockIcon, LockOpenIcon, PlusIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { useActions } from "@/components/actions";
import { Empty, SectionTitle } from "@/components/common";
import { ConfirmDialog, Row, Rows } from "@/components/kit";
import { Probe } from "@/components/probe";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import type { RouteView } from "@/types";

export function DomainsTab({
  routes,
  onAdd,
}: {
  routes: RouteView[];
  onAdd: () => void;
}) {
  const actions = useActions();
  const [removing, setRemoving] = useState<string | null>(null);
  const add = <Button variant="outline" size="sm" onClick={onAdd}><PlusIcon />加域名</Button>;
  return (
    <div>
      <SectionTitle action={routes.length ? add : undefined}>域名</SectionTitle>
      {routes.length === 0 ? (
        <Empty action={add}>还没有域名，现在只能从内网访问</Empty>
      ) : (
        <Rows>
          {routes.map((r) => (
            <Row key={r.id}>
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
              {r.spec.auth ? (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="xs">
                      <LockIcon />
                      已开登录保护
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onSelect={() => actions.basicAuth(r.spec.hostname)}>改账号密码</DropdownMenuItem>
                    <DropdownMenuItem
                      onSelect={() =>
                        actions.plan({
                          title: `关闭 ${r.spec.hostname} 的登录保护`,
                          changes: [{ op: "upsert_route", spec: { ...r.spec, auth: false } }],
                        })
                      }
                    >
                      关闭登录保护
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              ) : (
                <Button variant="ghost" size="xs" onClick={() => actions.basicAuth(r.spec.hostname, true)}>
                  <LockOpenIcon />
                  开启登录保护
                </Button>
              )}
              <Button variant="ghost" size="xs" onClick={() => setRemoving(r.spec.hostname)}>
                <XIcon />
                移除
              </Button>
            </Row>
          ))}
        </Rows>
      )}
      <ConfirmDialog open={!!removing} title={`移除域名 ${removing}？`} onCancel={() => setRemoving(null)} onConfirm={() => { const hostname = removing!; setRemoving(null); actions.plan({ title: `移除 ${hostname}`, changes: [{ op: "remove_route", hostname }] }); }}>服务不受影响，DNS 记录和证书一起移除。</ConfirmDialog>
    </div>
  );
}
