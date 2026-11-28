import { useNavigate } from "react-router-dom";
import { Fragment } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ago, Empty, SectionTitle, StatusBadge } from "@/components/common";
import { AckButton, ackSummary, IssueRow, useIssues } from "@/components/issues";
import { Panel, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { AlertsView, IssueLevel } from "@/types";

export function Open() {
  const nav = useNavigate();
  const issues = useIssues();
  const actions = useActions();
  const { data: alerts, refresh } = usePoll<AlertsView>("/api/alerts", 30000);
  const updates = issues.filter((i) => i.code === "update_available" && i.subject);
  const groups: [IssueLevel, string][] = [["fault", "故障"], ["warn", "要看一眼"], ["info", "可以做的"]];
  if (!issues.length && !alerts?.firing.length) return <Empty>现在没有要处理的</Empty>;
  return (
    <>
      {!!alerts?.firing.length && <>
        <SectionTitle count={alerts.firing.length}>正在告警</SectionTitle>
        <Panel className="grid gap-1.5 p-4 text-sm">
          {alerts.firing.map((f) => <div key={`${f.rule}/${f.subject}`} className="flex flex-wrap items-center gap-2">
            <StatusBadge tone="bad">{alerts.rules.find((r) => r.id === f.rule)?.name ?? alerts.notices.find((n) => n.id === f.rule)?.name ?? f.rule}</StatusBadge>
            <span className="min-w-0 flex-1 break-words">
              {f.title}
              {f.ack && <span className="mt-0.5 block text-xs text-muted-foreground">{ackSummary(f.ack)}</span>}
            </span>
            <span className="text-xs text-muted-foreground">{ago(new Date(f.since).toISOString())}起</span>
            <AckButton target={{ rule: f.rule, subject: f.subject }} ack={f.ack} onDone={refresh} />
            <Button variant="outline" size="xs" onClick={() => nav(alertPath(f.rule, f.subject, alerts.custom_rules?.some((c) => c.name === f.rule)))}>查看</Button>
          </div>)}
        </Panel>
      </>}
      {groups.map(([level, label]) => {
        const items = issues.filter((i) => i.level === level);
        if (!items.length) return null;
        return <Fragment key={level}>
          <SectionTitle count={items.length} action={level === "info" && updates.length > 1 ? <Button variant="outline" size="sm" onClick={() => actions.plan({ title: `更新 ${updates.length} 个服务`, changes: updates.map((i) => ({ op: "refresh_images", name: i.subject!.name })) })}>全部更新</Button> : undefined}>{label}</SectionTitle>
          <Rows limit={10}>{items.map((i, index) => <IssueRow key={`${i.code}-${i.subject?.name ?? ""}-${index}`} issue={i} />)}</Rows>
        </Fragment>;
      })}
    </>
  );
}

function alertPath(rule: string, subject: string, isCustom?: boolean): string {
  if (isCustom) return `/services/${encodeURIComponent(subject)}?tab=metrics`;
  if (rule === "expiry_soon" || rule === "expiry_urgent") { const [kind, ...parts] = subject.split(":"); const name = encodeURIComponent(parts.join(":")); return kind === "domain" ? `/domains?q=${name}` : `/servers/${name}?tab=settings`; }
  const name = encodeURIComponent(subject);
  if (["domain_down", "cert_expiring"].includes(rule)) return `/domains?open=${name}`;
  if (["link_cert_expiring", "link_ca_expiring"].includes(rule)) return "/domains?tab=entries";
  if (["container_restarting", "http_5xx", "oom_killed"].includes(rule)) return `/services/${name}?tab=logs`;
  if (["monitor_failed", "svc_mem_near_limit", "heartbeat_late"].includes(rule)) return `/services/${name}?tab=metrics`;
  if (["log_keyword", "port_down"].includes(rule)) return `/services/${encodeURIComponent(subject.split(":")[0])}?tab=metrics`;
  if (rule === "mem_forecast") {
    if (subject.startsWith("服务 ")) return `/services/${encodeURIComponent(subject.slice(3))}?tab=metrics`;
    if (subject.startsWith("服务器 ")) return `/servers/${encodeURIComponent(subject.slice(4))}`;
  }
  if (["link_loss", "tailnet_relay", "tailnet_key_expiring", "external_incident"].includes(rule)) return "/network";
  if (rule === "vendor_token_invalid") return "/settings";
  if (rule === "host_unit_down") return `/servers/${encodeURIComponent(subject.split(":")[0])}?tab=host`;
  return `/servers/${name}${rule === "disk_forecast" ? "?tab=disk" : ""}`;
}
