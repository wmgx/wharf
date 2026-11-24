import { Panel, Tip } from "@/components/kit";
import { BellOffIcon, ChevronDownIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { SectionTitle } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertLevel, AlertPatch, AlertsView } from "@/types";

const MUTES: [number, string][] = [
  [60, "1 小时"],
  [24 * 60, "1 天"],
  [7 * 24 * 60, "7 天"],
];

const LEVELS: [AlertLevel, string][] = [
  ["urgent", "立即"],
  ["digest", "每日汇总"],
];

const clock = (ms: number) => new Date(ms).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });

const fmtTarget = (rule: string, subject?: string | null) => (subject ? `${rule}:${subject}` : rule);

export function Rules() {
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

  const setOptions = async (include_logs: boolean) => {
    try {
      setView(await api.put<AlertsView>("/api/alerts/options", { include_logs }));
      refresh();
    } catch (e) {
      toast.error("保存失败", { description: (e as Error).message });
    }
  };

  const removeSuppression = async (id: number) => {
    try {
      setView(await api.del<AlertsView>(`/api/alerts/suppress/${id}`));
      refresh();
    } catch (e) {
      toast.error("删除失败", { description: (e as Error).message });
    }
  };

  if (!v) return null;
  const builtins = v.builtin_suppressions ?? [];
  const custom = v.suppressions ?? [];
  return (
    <>
      <SectionTitle>告警规则</SectionTitle>
      <Panel>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">开</TableHead>
              <TableHead>规则</TableHead>
              <TableHead className="w-28">阈值</TableHead>
              <TableHead className="w-24">连续次数</TableHead>
              <TableHead className="w-28">级别</TableHead>
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
                <TableCell>
                  <LevelSelect level={r.level} onChange={(level) => patch(r.id, { level })} />
                </TableCell>
                <TableCell className="text-right">
                  <Controls muted={r.muted_until} customized={r.customized} onPatch={(p) => patch(r.id, p)} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      <SectionTitle>事件通知</SectionTitle>
      <Panel className="grid gap-2 p-4">
        {v.notices.map((n) => (
          <div key={n.id} className="flex items-center gap-2.5 text-sm">
            <Checkbox checked={n.enabled} aria-label={`开关 ${n.name}`} onCheckedChange={(c) => patch(n.id, { enabled: c === true })} />
            <span>{n.name}</span>
            <span className="ml-auto inline-flex items-center gap-1">
              <LevelSelect level={n.level} onChange={(level) => patch(n.id, { level })} />
              <Controls muted={n.muted_until} customized={n.customized} onPatch={(p) => patch(n.id, p)} />
            </span>
          </div>
        ))}
      </Panel>

      {(builtins.length > 0 || custom.length > 0) && (
        <>
          <SectionTitle>告警抑制</SectionTitle>
          <Panel className="grid gap-2 p-4">
            {builtins.map((s) => (
              <div key={s.id} className="flex items-center gap-2.5 text-sm">
                <Checkbox checked={s.enabled} aria-label={`开关 ${s.name}`} onCheckedChange={(c) => patch(s.id, { enabled: c === true })} />
                <span>{s.name}</span>
              </div>
            ))}
            {custom.map((s) => (
              <div key={s.id} className="flex items-center gap-2.5 text-sm">
                <span className="font-mono text-xs text-muted-foreground">#{s.id}</span>
                <span className="font-mono text-xs">
                  {fmtTarget(s.source_rule, s.source_subject)} → 忽略 {fmtTarget(s.target_rule, s.target_subject)}
                </span>
                <span className="ml-auto">
                  <Tip text="删除">
                    <Button variant="ghost" size="icon-xs" aria-label={`删除抑制 #${s.id}`} onClick={() => removeSuppression(s.id)}>
                      <Trash2Icon />
                    </Button>
                  </Tip>
                </span>
              </div>
            ))}
          </Panel>
        </>
      )}

      <label className="mt-6 flex w-fit cursor-pointer items-center gap-2.5 text-sm">
        <Checkbox checked={!!v.include_logs} onCheckedChange={(c) => setOptions(c === true)} />
        告警附带日志
      </label>
    </>
  );
}

function LevelSelect({ level, onChange }: { level: AlertLevel; onChange: (level: AlertLevel) => void }) {
  const label = LEVELS.find(([v]) => v === level)?.[1] ?? "立即";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm">
          {label}
          <ChevronDownIcon className="size-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {LEVELS.map(([val, text]) => (
          <DropdownMenuItem key={val} onSelect={() => val !== level && onChange(val)}>
            {text}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function Controls({ muted, customized, onPatch }: { muted?: number | null; customized?: boolean; onPatch: (p: AlertPatch) => void }) {
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
        <Tip text="恢复默认"><Button variant="ghost" size="icon-xs" aria-label="恢复默认" onClick={() => onPatch({ reset: true })}>
          <RotateCcwIcon />
        </Button></Tip>
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
