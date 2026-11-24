import { Panel, Tip } from "@/components/kit";
import { BellOffIcon, RotateCcwIcon } from "lucide-react";
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

function splitRuleSubject(raw: string): { rule: string; subject?: string } {
  const i = raw.indexOf(":");
  if (i < 0) return { rule: raw.trim() };
  const subject = raw.slice(i + 1).trim();
  return { rule: raw.slice(0, i).trim(), subject: subject || undefined };
}

export function Rules() {
  const { data, refresh } = usePoll<AlertsView>("/api/alerts", 30000);
  const [view, setView] = useState<AlertsView | null>(null);
  const [srcInput, setSrcInput] = useState("");
  const [dstInput, setDstInput] = useState("");
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

  const addSuppress = async () => {
    const src = splitRuleSubject(srcInput);
    const dst = splitRuleSubject(dstInput);
    if (!src.rule || !dst.rule) return;
    try {
      setView(
        await api.post<AlertsView>("/api/alerts/suppress", {
          source_rule: src.rule,
          source_subject: src.subject,
          target_rule: dst.rule,
          target_subject: dst.subject,
        }),
      );
      setSrcInput("");
      setDstInput("");
      refresh();
    } catch (e) {
      toast.error("保存失败", { description: (e as Error).message });
    }
  };

  const removeSuppress = async (id: number) => {
    try {
      setView(await api.del<AlertsView>(`/api/alerts/suppress/${id}`));
      refresh();
    } catch (e) {
      toast.error("删除失败", { description: (e as Error).message });
    }
  };

  if (!v) return null;
  return (
    <>
      <SectionTitle>告警规则</SectionTitle>
      <Panel>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">开</TableHead>
              <TableHead>规则</TableHead>
              <TableHead className="w-28">级别</TableHead>
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
                  <LevelMenu level={r.level} onChange={(level) => patch(r.id, { level })} />
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
      </Panel>

      <SectionTitle>事件通知</SectionTitle>
      <Panel className="grid gap-2 p-4">
        {v.notices.map((n) => (
          <div key={n.id} className="flex flex-wrap items-center gap-2.5 text-sm">
            <Checkbox checked={n.enabled} aria-label={`开关 ${n.name}`} onCheckedChange={(c) => patch(n.id, { enabled: c === true })} />
            <span>{n.name}</span>
            <span className="ml-auto inline-flex items-center gap-1">
              <LevelMenu level={n.level} onChange={(level) => patch(n.id, { level })} />
              <Controls muted={n.muted_until} customized={n.customized} onPatch={(p) => patch(n.id, p)} />
            </span>
          </div>
        ))}
      </Panel>

      <SectionTitle>告警抑制</SectionTitle>
      <Panel className="grid gap-2 p-4 text-sm">
        {(v.builtin_suppressions ?? []).map((s) => (
          <div key={s.id} className="flex items-center gap-2.5">
            <Checkbox checked={s.enabled} aria-label={`开关 ${s.name}`} onCheckedChange={(c) => patch(s.id, { enabled: c === true })} />
            <span>{s.name}</span>
          </div>
        ))}
        {(v.custom_suppressions ?? []).map((s) => (
          <div key={s.id} className="flex flex-wrap items-center gap-2 border-t pt-2">
            <span className="font-mono text-xs text-muted-foreground">#{s.id}</span>
            <span className="font-mono text-xs">
              {s.source_rule}{s.source_subject ? `:${s.source_subject}` : ""} → {s.target_rule}{s.target_subject ? `:${s.target_subject}` : ""}
            </span>
            <Button variant="ghost" size="xs" className="ml-auto" onClick={() => removeSuppress(s.id)}>
              删除
            </Button>
          </div>
        ))}
        <div className="flex flex-wrap items-center gap-2 border-t pt-2">
          <Input
            className="h-8 w-44 font-mono text-xs"
            placeholder="源规则[:对象]"
            value={srcInput}
            onChange={(e) => setSrcInput(e.target.value)}
          />
          <span className="text-muted-foreground">→</span>
          <Input
            className="h-8 w-44 font-mono text-xs"
            placeholder="忽略规则[:对象]"
            value={dstInput}
            onChange={(e) => setDstInput(e.target.value)}
          />
          <Button variant="outline" size="sm" disabled={!srcInput.trim() || !dstInput.trim()} onClick={addSuppress}>
            添加
          </Button>
        </div>
      </Panel>

      <label className="mt-6 flex w-fit cursor-pointer items-center gap-2.5 text-sm">
        <Checkbox checked={!!v.include_logs} onCheckedChange={(c) => setOptions(c === true)} />
        告警附带日志
      </label>
    </>
  );
}

function LevelMenu({ level, onChange }: { level: AlertLevel; onChange: (l: AlertLevel) => void }) {
  const label = LEVELS.find(([k]) => k === level)?.[1] ?? level;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm">
          {label}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {LEVELS.map(([k, text]) => (
          <DropdownMenuItem key={k} onSelect={() => k !== level && onChange(k)}>
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
