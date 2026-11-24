import { CircleAlertIcon, InfoIcon, TriangleAlertIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AlertConfirmation } from "@/components/alert-confirmation";
import { useActions } from "@/components/actions";
import { CopyButton, SectionTitle } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import type { Issue, IssueSubject } from "@/types";

export function useIssues(): Issue[] {
  const status = useStatus().status;
  return [...(status?.issues ?? []), ...(status?.servers.filter((s) => s.agent_outdated).map((s): Issue => ({ code: "agent_outdated", level: "info", subject: { kind: "server", name: s.name }, title: `${s.name} 的 agent 可以升级` })) ?? [])];
}

export function issueCount(issues: Issue[]): number {
  return issues.filter((i) => i.level !== "info").length;
}

export function subjectPath(s: IssueSubject): string {
  const name = encodeURIComponent(s.name);
  switch (s.kind) {
    case "server": return `/servers/${name}`;
    case "service": return `/services/${name}`;
    case "gateway": return `/domains?tab=entries&entry=${name}`;
    case "edge": return `/edge/${name}`;
    case "task": return `/tasks/${name}?tab=runs`;
    case "domain": return `/domains?q=${name}`;
    case "route": return `/domains?open=${name}`;
    default: return "/domains";
  }
}

export function IssueRow({ issue }: { issue: Issue }) {
  const actions = useActions();
  const nav = useNavigate();
  const { status, refresh } = useStatus();
  const Icon = issue.level === "fault" ? CircleAlertIcon : issue.level === "warn" ? TriangleAlertIcon : InfoIcon;
  const color = issue.level === "fault" ? "text-destructive" : issue.level === "warn" ? "text-warning" : "text-muted-foreground";
  const subject = issue.subject;
  const tag = subject ? status?.updates?.services[subject.name]?.tags?.[0] : undefined;
  return (
    <Row className="items-start">
      <Icon className={`mt-0.5 size-4 shrink-0 ${color}`} />
      <span className="min-w-0 flex-1 break-all">{issue.title}
        {issue.code === "dns_not_effective" && issue.hint && <code className="mt-1.5 block font-mono text-xs text-foreground/70">{issue.hint}</code>}
      </span>
      {issue.alert && <AlertConfirmation target={issue.alert} ack={issue.ack} refresh={refresh} />}
      {issue.code === "dns_not_effective" && issue.hint && <CopyButton text={issue.hint} />}
      {issue.code === "update_available" && subject ? (
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `更新 ${subject.name}`, changes: [{ op: "refresh_images", name: subject.name }] })}>更新</Button>
      ) : issue.code === "tag_available" && subject && tag ? (
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `${subject.name} 升级到 ${tag.tag}`, changes: [{ op: "retag_image", name: subject.name, image: tag.image, tag: tag.tag }] })}>升级到 {tag.tag}</Button>
      ) : issue.code === "agent_outdated" && subject ? (
        <Button variant="outline" size="xs" onClick={() => actions.upgradeAgent(subject.name)}>升级 agent</Button>
      ) : issue.code === "pending_changes" ? (
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: "执行未完成的改动", changes: [] })}>预览改动</Button>
      ) : subject ? (
        <Button variant="outline" size="xs" onClick={() => nav(issue.code === "baseline_drift" ? `/servers/${encodeURIComponent(subject.name)}?tab=updates` : issue.code === "exposed_port" ? `/servers/${encodeURIComponent(subject.name)}?tab=exposure` : issue.code === "host_unit_down" ? `/servers/${encodeURIComponent(subject.name)}?tab=host` : issue.code === "disk_low" || issue.code === "disk_forecast" ? `/servers/${encodeURIComponent(subject.name)}?tab=disk` : ["monitor_down", "log_keyword", "port_down", "heartbeat_late"].includes(issue.code) ? `/services/${encodeURIComponent(subject.name)}?tab=metrics` : issue.code === "recovery_low" ? "/settings?tab=security" : subjectPath(subject))}>{issue.code === "exposed_port" ? "去确认" : issue.code === "baseline_drift" ? "看基线" : issue.code === "host_unit_down" ? "看日志" : "查看"}</Button>
      ) : <Button variant="outline" size="xs" onClick={() => nav(issue.code === "recovery_low" ? "/settings?tab=security" : issue.code === "domain_expiring" ? "/domains" : "/inbox")}>查看</Button>}
    </Row>
  );
}

export function ObjectIssues({ kind, name }: { kind: string; name: string }) {
  const issues = useIssues().filter((i) => i.subject?.kind === kind && i.subject.name === name);
  if (!issues.length) return null;
  return <><SectionTitle count={issues.length}>待处理</SectionTitle><Rows>{issues.map((issue, i) => <IssueRow key={`${issue.code}-${i}`} issue={issue} />)}</Rows></>;
}
