import { TerminalIcon } from "lucide-react";
import { usePoll } from "@/api";
import { CardsSkeleton, Empty, ErrorNote, StatusBadge, ago } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import type { ShellLog } from "@/types";

export function Shell() {
  const { data, error } = usePoll<ShellLog[]>("/api/shell-log?limit=200", 10000);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <CardsSkeleton count={2} />;
  if (data.length === 0) return <Empty>还没有在宿主机上执行过命令</Empty>;
  return (
    <Rows>
      {data.map((l) => {
        const ok = !l.error && (l.exit_code == null || l.exit_code === 0);
        return (
          <Row key={l.id} className="items-start">
            <TerminalIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            <div className="grid min-w-0 flex-1 gap-0.5">
              <span className="truncate font-mono text-sm">{l.command ?? (l.kind === "terminal" ? "打开终端" : l.kind)}</span>
              <span className="truncate text-xs text-muted-foreground">
                {[l.server, l.actor, ago(l.at), l.duration_ms != null && `${(l.duration_ms / 1000).toFixed(1)} 秒`, l.error].filter(Boolean).join(" · ")}
              </span>
            </div>
            {l.exit_code != null && <StatusBadge tone={ok ? "ok" : "bad"}>{`退出 ${l.exit_code}`}</StatusBadge>}
          </Row>
        );
      })}
    </Rows>
  );
}
