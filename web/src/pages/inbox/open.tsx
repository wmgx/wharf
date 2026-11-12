import { Fragment } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ago, Empty, SectionTitle, StatusBadge } from "@/components/common";
import { IssueRow, useIssues } from "@/components/issues";
import { Panel, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { AlertsView, IssueLevel } from "@/types";

export function Open() {
  const issues = useIssues();
  const actions = useActions();
  const { data: alerts } = usePoll<AlertsView>("/api/alerts", 30000);
  const updates = issues.filter((i) => i.code === "update_available" && i.subject);
  const groups: [IssueLevel, string][] = [["fault", "故障"], ["warn", "要看一眼"], ["info", "可以做的"]];
  if (!issues.length && !alerts?.firing.length) return <Empty>现在没有要处理的</Empty>;
  return (
    <>
      {groups.map(([level, label]) => {
        const items = issues.filter((i) => i.level === level);
        if (!items.length) return null;
        return <Fragment key={level}>
          <SectionTitle count={items.length} action={level === "info" && updates.length > 1 ? <Button variant="outline" size="sm" onClick={() => actions.plan({ title: `更新 ${updates.length} 个服务`, changes: updates.map((i) => ({ op: "refresh_images", name: i.subject!.name })) })}>全部更新</Button> : undefined}>{label}</SectionTitle>
          <Rows>{items.map((i, index) => <IssueRow key={`${i.code}-${i.subject?.name ?? ""}-${index}`} issue={i} />)}</Rows>
        </Fragment>;
      })}
      {!!alerts?.firing.length && <>
        <SectionTitle count={alerts.firing.length}>正在告警</SectionTitle>
        <Panel className="grid gap-1.5 p-4 text-sm">
          {alerts.firing.map((f) => <div key={`${f.rule}/${f.subject}`} className="flex flex-wrap items-center gap-2">
            <StatusBadge tone="bad">{alerts.rules.find((r) => r.id === f.rule)?.name ?? alerts.notices.find((n) => n.id === f.rule)?.name ?? f.rule}</StatusBadge>
            <span>{f.title}</span><span className="text-xs text-muted-foreground">{ago(new Date(f.since).toISOString())}起</span>
          </div>)}
        </Panel>
      </>}
    </>
  );
}
