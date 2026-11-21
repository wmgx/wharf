import { Trash2Icon } from "lucide-react";
import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ForwardDialog } from "@/components/forward-dialog";
import { WildcardDialog } from "@/components/wildcard-dialog";
import { CodeBlock, Empty, SectionTitle, ServerTag } from "@/components/common";
import { CertDays, diagnosisOf } from "@/components/health";
import { Facts, Row, Rows } from "@/components/kit";
import { LogStream } from "@/components/LogStream";
import { Button } from "@/components/ui/button";
import { SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { AccountView, GatewayTls, GatewayView } from "@/types";
import { GatewayErrorPage } from "../gateway-error-page";

const TLS_TEXT: Record<GatewayTls, string> = { auto: "自动签证书", internal: "自签证书", off: "只走 HTTP" };

export function GatewayDetail({ g, onDone, onDomain }: { g: GatewayView; onDone: () => void; onDomain: (hostname: string) => void }) {
  const actions = useActions();
  const [configOpen, setConfigOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const { status } = useStatus();
  const [wildcardOpen, setWildcardOpen] = useState(false);
  const { data: accounts } = usePoll<AccountView[]>(g.spec.kind === "caddy" && g.spec.tls !== "off" ? "/api/accounts" : null, 30000);
  const [forwardOpen, setForwardOpen] = useState(false);
  const forwards = g.spec.layer4 ?? [];
  const saveForwards = (next: NonNullable<GatewayView["spec"]["layer4"]>, title: string) => {
    actions.plan({ title, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, layer4: next } }] });
  };
  const addForward = <Button variant="outline" size="xs" onClick={() => setForwardOpen(true)}>加转发</Button>;
  const wildcard = g.spec.wildcard ?? [];
  const hasZones = (accounts ?? []).some((a) => a.zones.length > 0);
  const saveWildcard = (next: string[], title: string) => {
    setWildcardOpen(false);
    actions.plan({ title, changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, wildcard: next } }] });
  };
  const { data: config } = usePoll<{ config: string; compose: string }>(configOpen ? `/api/gateways/${encodeURIComponent(g.name)}/config` : null, 30000);
  return <>
    <SheetHeader className="border-b">
      <SheetTitle>
        {g.name}
      </SheetTitle>
      <SheetDescription>入口（网关）</SheetDescription>
    </SheetHeader>
    <div className="flex-1 overflow-auto p-4">
      <Facts items={[
        ["服务器", <ServerTag name={g.spec.server} />],
        ["默认入口", g.spec.default ? "是" : <Button variant="outline" size="xs" onClick={() => {
          const old = status?.gateways.find((x) => x.spec.default && x.name !== g.name);
          actions.plan({
            title: `把 ${g.name} 设为默认入口`,
            changes: [
              ...(old ? [{ op: "upsert_gateway" as const, name: old.name, spec: { ...old.spec, default: undefined } }] : []),
              { op: "upsert_gateway" as const, name: g.name, spec: { ...g.spec, default: true } },
            ],
          });
        }}>设为默认</Button>],
        ["类型", g.spec.kind === "cloudflare_tunnel" && `Cloudflare 隧道（wharf-${g.name}）`],
        ["厂商账号", g.spec.kind === "cloudflare_tunnel" && g.spec.account],
        ["证书", g.spec.kind === "caddy" && TLS_TEXT[g.spec.tls ?? "auto"]],
        ["端口", g.spec.kind === "caddy" && <span className="font-mono text-xs">HTTP {g.spec.http_port ?? 80} · HTTPS {g.spec.https_port ?? 443}
        </span>],
        ["错误页", g.spec.kind === "caddy" && <GatewayErrorPage g={g} />],
        ["泛域名证书", g.spec.kind === "caddy" && g.spec.tls !== "off" && <div className="flex flex-wrap items-center gap-2">
          {wildcard.length ? wildcard.map((z) => <span key={z} className="inline-flex min-w-0 max-w-full items-center gap-1">
            <span className="break-all font-mono text-xs">*.{z}</span>
            <Button variant="outline" size="xs" onClick={() => saveWildcard(wildcard.filter((v) => v !== z), `关闭 *.${z} 的泛域名证书`)}>关闭</Button>
          </span>) : "没开"}
          <Button variant="outline" size="xs" disabled={!hasZones} onClick={() => setWildcardOpen(true)}>开启</Button>
        </div>],
      ]} />
      <SectionTitle>域名</SectionTitle>
      {g.routes.length ? <Rows>
        {g.routes.map((hostname) => <Row key={hostname} onClick={() => onDomain(hostname)}>
          <span className="min-w-0 flex-1 truncate font-mono text-xs">
            {hostname}
          </span>
          <CertDays d={diagnosisOf(status, hostname)} />
        </Row>)}
      </Rows> : <Empty>没有域名</Empty>}
      {g.spec.kind === "caddy" && <>
        <SectionTitle action={addForward}>四层转发</SectionTitle>
        {forwards.length ? <Rows>{forwards.map((f) => <Row key={`${!!f.udp}:${f.listen}`}>
          <span className="shrink-0 font-mono text-xs">:{f.listen}{f.udp ? "/udp" : ""}</span>
          <span className="text-muted-foreground">→</span>
          <span className="min-w-0 flex-1 break-all font-mono text-xs">{f.service ? `${f.service}${f.port ? `:${f.port}` : ""}` : f.upstream}</span>
          <Button variant="outline" size="xs" onClick={() => saveForwards(forwards.filter((v) => v.listen !== f.listen || !!v.udp !== !!f.udp), `移除 ${g.name} 的四层转发 :${f.listen}`)}>移除</Button>
        </Row>)}</Rows> : <Empty action={addForward}>还没有四层转发</Empty>}
      </>}
      <details className="mt-8 text-sm" onToggle={(e) => setConfigOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer">生成的配置</summary>
        {configOpen && <CodeBlock className="mt-3">
          {config?.config ?? "载入中…"}
        </CodeBlock>}
      </details>
      <details className="mt-8 text-sm" onToggle={(e) => setLogsOpen(e.currentTarget.open)}>
        <summary className="cursor-pointer">日志</summary>
        {logsOpen && <LogStream path={`/api/gateways/${encodeURIComponent(g.name)}/logs/stream`} />}
      </details>
    </div>
    <SheetFooter className="flex-row items-center justify-between border-t">
      <span className="text-xs text-muted-foreground">
        {g.routes.length ? "先移除这个入口上的域名" : ""}
      </span>
      <Button variant="outline" className="text-destructive" disabled={g.routes.length > 0} onClick={() => { onDone(); actions.plan({ title: `删除入口 ${g.name}`, changes: [{ op: "remove_gateway", name: g.name }] }); }}>
        <Trash2Icon />删除入口</Button>
    </SheetFooter>
    {wildcardOpen && <WildcardDialog gateways={[g]} onClose={() => setWildcardOpen(false)} />}
    {forwardOpen && <ForwardDialog gateway={g} onClose={() => setForwardOpen(false)} />}
  </>;
}
