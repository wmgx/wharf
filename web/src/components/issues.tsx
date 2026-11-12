import { CircleAlertIcon, InfoIcon, TriangleAlertIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useActions } from "@/components/actions";
import { Row } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import type { Issue, IssueSubject, Status } from "@/types";

export function useIssues(): Issue[] {
  return useStatus().status?.issues ?? [];
}

export function issueCount(issues: Issue[]): number {
  return issues.filter((i) => i.level !== "info").length;
}

export function subjectPath(s: IssueSubject, status: Status | null): string {
  const name = encodeURIComponent(s.name);
  switch (s.kind) {
    case "server": return `/servers/${name}`;
    case "service": return `/services/${name}`;
    case "gateway": return `/entries?open=${name}`;
    case "edge": return `/edge/${name}`;
    case "task": return "/tasks";
    case "route": {
      const service = status?.routes.find((r) => r.spec.hostname === s.name)?.spec.service;
      return service ? `/services/${encodeURIComponent(service)}?tab=network` : "/entries";
    }
    default: return "/entries";
  }
}

export function IssueRow({ issue }: { issue: Issue }) {
  const actions = useActions();
  const nav = useNavigate();
  const { status } = useStatus();
  const Icon = issue.level === "fault" ? CircleAlertIcon : issue.level === "warn" ? TriangleAlertIcon : InfoIcon;
  const color = issue.level === "fault" ? "text-destructive" : issue.level === "warn" ? "text-warning" : "text-muted-foreground";
  const subject = issue.subject;
  return (
    <Row className="items-start">
      <Icon className={`mt-0.5 size-4 shrink-0 ${color}`} />
      <span className="min-w-0 flex-1 break-all">{issue.title}</span>
      {issue.code === "update_available" && subject ? (
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: `更新 ${subject.name}`, changes: [{ op: "refresh_images", name: subject.name }] })}>更新</Button>
      ) : issue.code === "pending_changes" ? (
        <Button variant="outline" size="xs" onClick={() => actions.plan({ title: "执行未完成的改动", changes: [] })}>预览改动</Button>
      ) : subject ? (
        <Button variant="outline" size="xs" onClick={() => nav(issue.code === "baseline_drift" ? `/servers/${encodeURIComponent(subject.name)}?tab=system` : issue.code === "host_unit_down" ? `/servers/${encodeURIComponent(subject.name)}?tab=host` : subjectPath(subject, status))}>查看</Button>
      ) : null}
    </Row>
  );
}
