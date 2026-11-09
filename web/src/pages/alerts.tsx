import { BellOffIcon, RotateCcwIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, SectionTitle, StatusBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertPatch, AlertsView } from "@/types";

const MUTES: [number, string][] = [
  [60, "1 小时"],
  [24 * 60, "1 天"],
  [7 * 24 * 60, "7 天"],
];

const iso = (ms: number) => new Date(ms).toISOString();
const clock = (ms: number) => new Date(ms).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });

/** 告警规则（指标 + 阈值）和事件通知的开关、静默，正在触发的告警，最近推送。 */
export function Alerts() {
  const { data, refresh } = usePoll<AlertsView>("/api/alerts", 30000);
  const [view, setView] = useState<AlertsView | null>(null);
  const v = view ?? data;

  const patch = async (id: string, p: AlertPatch) => {
    try {
      setView(await api.put<AlertsView>(`/api/alerts/${encodeURIComponent(id)}`, p));
      refresh();
    } catch (e) {
      toast.error("保存失败", { description: (e as Error).message });
    }
  };

  if (!v) return null;
  const nameOf = (id: string) => v.rules.find((r) => r.id === id)?.name ?? v.notices.find((n) => n.id === id)?.name ?? id;

  return (
    <>
      <SectionTitle count={v.firing.length}>正在触发</SectionTitle>
      {v.firing.length ? (
        <div className="grid gap-1.5 rounded-xl border bg-card p-4 text-sm shadow-xs">
          {v.firing.map((f) => (
            <div key={`${f.rule}/${f.subject}`} className="flex flex-wrap items-center gap-2">
              <StatusBadge tone="bad">{nameOf(f.rule)}</StatusBadge>
              <span>{f.title}</span>
              <span className="text-xs text-muted-foreground">{ago(iso(f.since))}起</span>
            </div>
          ))}
        </div>
      ) : (
        <Empty>没有正在触发的告警</Empty>
      )}

      <SectionTitle>告警规则</SectionTitle>
      <div className="rounded-xl border bg-card shadow-xs">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">开</TableHead>
              <TableHead>规则</TableHead>
              <TableHead className="w-28">阈值</TableHead>
              <TableHead className="w-24">连续次数</TableHead>
              <TableHead className="w-40" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {v.rules.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <Checkbox checked={r.enabled} aria-label={`开关 ${r.name}`} onCheckedChange={(c) => patch(r.id, { enabled: c === true })} />
                </TableCell>
                <TableCell>
                  <div className="font-medium">{r.name}</div>
                  <div className="font-mono text-xs break-all text-muted-foreground">{r.condition}</div>
                </TableCell>
                <TableCell>
                  {r.threshold_editable ? (
                    <NumberInput value={r.threshold} onSave={(n) => patch(r.id, { threshold: n })} />
                  ) : (
                    <span className="font-mono text-xs text-muted-foreground">
                      {r.op} {r.threshold}
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <NumberInput value={r.for_n} integer onSave={(n) => patch(r.id, { for_n: n })} />
                </TableCell>
                <TableCell className="text-right">
                  <Controls muted={r.muted_until} customized={r.customized} onPatch={(p) => patch(r.id, p)} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <SectionTitle>事件通知</SectionTitle>
      <div className="grid gap-2 rounded-xl border bg-card p-4 shadow-xs">
        {v.notices.map((n) => (
          <div key={n.id} className="flex items-center gap-2.5 text-sm">
            <Checkbox checked={n.enabled} aria-label={`开关 ${n.name}`} onCheckedChange={(c) => patch(n.id, { enabled: c === true })} />
            <span>{n.name}</span>
            <span className="ml-auto">
              <Controls muted={n.muted_until} onPatch={(p) => patch(n.id, p)} />
            </span>
          </div>
        ))}
      </div>

      <SectionTitle count={v.history.length}>最近推送</SectionTitle>
      {v.history.length ? (
        <div className="grid gap-1.5 rounded-xl border bg-card p-4 text-sm shadow-xs">
          {v.history.map((h, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2">
              <span className="w-24 shrink-0 text-xs text-muted-foreground tabular-nums">{clock(h.at)}</span>
              <StatusBadge tone={h.ok ? "ok" : "bad"}>{h.ok ? "恢复" : "告警"}</StatusBadge>
              <span className="min-w-0">{h.title}</span>
              {h.skipped && <span className="text-xs text-muted-foreground">（没发：{h.skipped}）</span>}
              <span className="ml-auto text-xs text-muted-foreground">{nameOf(h.source)}</span>
            </div>
          ))}
        </div>
      ) : (
        <Empty>控制面这次启动后还没有推送</Empty>
      )}
    </>
  );
}

function Controls({ muted, customized, onPatch }: { muted?: number; customized?: boolean; onPatch: (p: AlertPatch) => void }) {
  return (
    <span className="inline-flex items-center gap-1">
      {muted ? (
        <Button variant="ghost" size="sm" onClick={() => onPatch({ mute_minutes: 0 })} title="取消静默">
          <BellOffIcon />
          静默到 {clock(muted)}
        </Button>
      ) : (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm">
              <BellOffIcon />
              静默
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {MUTES.map(([m, label]) => (
              <DropdownMenuItem key={m} onSelect={() => onPatch({ mute_minutes: m })}>
                {label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {customized && (
        <Button variant="ghost" size="icon-xs" aria-label="恢复默认" title="恢复默认" onClick={() => onPatch({ reset: true })}>
          <RotateCcwIcon />
        </Button>
      )}
    </span>
  );
}

/** 失焦或回车时保存，没变不保存。 */
function NumberInput({ value, integer, onSave }: { value: number; integer?: boolean; onSave: (n: number) => void }) {
  const [text, setText] = useState(String(value));
  const [prev, setPrev] = useState(value);
  if (prev !== value) {
    setPrev(value);
    setText(String(value));
  }
  const save = () => {
    const n = integer ? Number.parseInt(text, 10) : Number.parseFloat(text);
    if (!Number.isFinite(n) || n === value) {
      setText(String(value));
      return;
    }
    onSave(n);
  };
  return (
    <Input
      className="h-8 w-20"
      inputMode="decimal"
      value={text}
      onChange={(e) => setText(e.target.value)}
      onBlur={save}
      onKeyDown={(e) => e.key === "Enter" && e.currentTarget.blur()}
    />
  );
}
