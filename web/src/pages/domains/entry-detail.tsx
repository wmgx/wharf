import { Trash2Icon } from "lucide-react";
import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CodeBlock, Empty, SectionTitle, ServerTag } from "@/components/common";
import { CertDays, diagnosisOf } from "@/components/health";
import { ConfirmDialog, Facts, Row, Rows } from "@/components/kit";
import { LogStream } from "@/components/LogStream";
import { Button } from "@/components/ui/button";
import { SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { GatewayTls, GatewayView } from "@/types";
import { GatewayErrorPage } from "../gateway-error-page";

const TLS_TEXT: Record<GatewayTls, string> = { auto: "自动签证书", internal: "自签证书", off: "只走 HTTP" };

export function GatewayDetail({ g, onDone, onDomain }: { g: GatewayView; onDone: () => void; onDomain: (hostname: string) => void }) {
  const actions = useActions();
  const [removing, setRemoving] = useState(false);
  const [configOpen, setConfigOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const { status } = useStatus();
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
        ["类型", g.spec.kind === "cloudflare_tunnel" && `Cloudflare 隧道（wharf-${g.name}）`],
        ["厂商账号", g.spec.kind === "cloudflare_tunnel" && g.spec.account],
        ["证书", g.spec.kind === "caddy" && TLS_TEXT[g.spec.tls ?? "auto"]],
        ["端口", g.spec.kind === "caddy" && <span className="font-mono text-xs">HTTP {g.spec.http_port ?? 80} · HTTPS {g.spec.https_port ?? 443}
        </span>],
        ["错误页", g.spec.kind === "caddy" && <GatewayErrorPage g={g} />],
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
      <Button variant="outline" className="text-destructive" disabled={g.routes.length > 0} onClick={() => setRemoving(true)}>
        <Trash2Icon />删除入口</Button>
    </SheetFooter>
    <ConfirmDialog open={removing} title={`删除入口 ${g.name}？`} onCancel={() => setRemoving(false)} onConfirm={() => { setRemoving(false); onDone(); actions.plan({ title: `删除入口 ${g.name}`, changes: [{ op: "remove_gateway", name: g.name }] }); }}>入口的容器会被删除。</ConfirmDialog>
  </>;
}
