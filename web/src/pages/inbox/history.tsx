import { usePoll } from "@/api";
import { Empty, SectionTitle, StatusBadge } from "@/components/common";
import { Panel } from "@/components/kit";
import type { AlertsView } from "@/types";

const clock = (ms: number) => new Date(ms).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });

export function History() {
  const { data: v } = usePoll<AlertsView>("/api/alerts", 30000);
  if (!v) return null;
  const nameOf = (id: string) => v.rules.find((r) => r.id === id)?.name ?? v.notices.find((n) => n.id === id)?.name ?? id;
  return (
    <>
      <SectionTitle count={v.history.length}>最近推送</SectionTitle>
      {v.history.length ? (
        <Panel className="grid gap-1.5 p-4 text-sm">
          {v.history.map((h, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2">
              <span className="w-24 shrink-0 text-xs text-muted-foreground tabular-nums">{clock(h.at)}</span>
              <StatusBadge tone={h.ok ? "ok" : "bad"}>{h.ok ? "恢复" : "告警"}</StatusBadge>
              <span className="min-w-0">{h.title}</span>
              {h.skipped && <span className="text-xs text-muted-foreground">（没发：{h.skipped}）</span>}
              <span className="ml-auto text-xs text-muted-foreground">{nameOf(h.source)}</span>
            </div>
          ))}
        </Panel>
      ) : (
        <Empty>最近 7 天没有推送</Empty>
      )}
    </>
  );
}
