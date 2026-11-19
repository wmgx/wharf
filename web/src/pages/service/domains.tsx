import { useState } from "react";
import { AccessProtection } from "@/components/access-protection";
import { ForwardDialog } from "@/components/forward-dialog";
import { useActions } from "@/components/actions";
import { useStatus } from "@/status";
import { isShare } from "@/components/share-list";
import { ArrowUpRightIcon, PlusIcon } from "lucide-react";
import { Empty, SectionTitle } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Probe } from "@/components/probe";
import { Button } from "@/components/ui/button";
import { OpMenu, routeOps } from "@/components/ops";
import type { RouteView } from "@/types";

export function DomainsTab({
  service,
  routes: all,
  onAdd,
  onOpen,
}: {
  service: string;
  routes: RouteView[];
  onAdd: () => void;
  onOpen: (hostname: string) => void;
}) {
  const { status } = useStatus();
  const actions = useActions();
  const [protecting, setProtecting] = useState<RouteView | null>(null);
  const [forwarding, setForwarding] = useState(false);
  const forwards = (status?.gateways ?? []).flatMap((g) => (g.spec.layer4 ?? []).filter((f) => f.service === service).map((f) => ({ g, f })));
  const routes = all.filter((r) => !isShare(r));
  const add = <Button variant="outline" size="sm" onClick={onAdd}><PlusIcon />加域名</Button>;
  return (
    <div>
      {protecting && <AccessProtection route={protecting} onClose={() => setProtecting(null)} />}
      {forwarding && <ForwardDialog service={service} onClose={() => setForwarding(false)} />}
      <SectionTitle action={routes.length ? add : undefined}>域名</SectionTitle>
      {routes.length === 0 ? (
        <Empty action={add}>还没有域名，现在只能从内网访问</Empty>
      ) : (
        <Rows limit={10}>
          {routes.map((r) => (
            <Row className="flex-wrap" key={r.id} onClick={() => onOpen(r.spec.hostname)}>
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
              <Button variant="outline" size="xs" onClick={() => setProtecting(r)}>{r.spec.sso?.mode === "oidc" ? "OIDC" : r.spec.sso?.public ? "公开" : r.spec.sso ? "门禁" : r.spec.auth ? "账号密码" : "不保护"}</Button>
              {r.spec.internal && <span className="text-xs text-muted-foreground">内网域名</span>}
              {r.spec.sso?.mode === "login" && <span className="text-xs text-muted-foreground">代登录 · {r.sso_login ? r.sso_login.ok ? "成功" : "失败" : "未登录"}</span>}
              <span className="text-xs text-muted-foreground">
                {r.gateway ? `经 ${r.gateway}` : ""}
                {r.spec.link === "tunnel" ? " · 反向隧道" : ""}
                </span>
              <OpMenu ops={routeOps.map((op) => op.id === "protection" ? { ...op, run: (route: RouteView) => setProtecting(route) } : op)} target={r} label={`${r.spec.hostname} 的操作`} size="icon-sm" />
            </Row>
          ))}
        </Rows>
      )}
      <SectionTitle count={forwards.length} action={<Button variant="outline" size="sm" disabled={!status?.gateways.some((g) => g.spec.kind === "caddy")} onClick={() => setForwarding(true)}>加转发</Button>}>四层转发</SectionTitle>
      {forwards.length ? <Rows limit={10}>{forwards.map(({ g, f }) => <Row key={`${g.name}/${!!f.udp}/${f.listen}`}>
        <span className="min-w-0 flex-1 break-all text-sm">{g.name} · :{f.listen}/{f.udp ? "UDP" : "TCP"} → {f.port ?? "默认端口"}</span>
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `移除 ${g.name} 的四层转发 :${f.listen}`, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, layer4: (g.spec.layer4 ?? []).filter((v) => v.listen !== f.listen || !!v.udp !== !!f.udp) } }] })}>移除</Button>
      </Row>)}</Rows> : null}
    </div>
  );
}
