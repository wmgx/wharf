import { PencilIcon, StickyNoteIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import type { ServiceView } from "@/types";

const LIMIT = 4000;

/** 服务备注：给人看的说明，直接保存，不走计划、不影响部署。 */
export function NoteCard({ svc }: { svc: ServiceView }) {
  // 保存后先显示本地值，等轮询拿到新数据。
  const [saved, setSaved] = useState<string | undefined>(undefined);
  const note = saved ?? svc.note ?? "";
  const [draft, setDraft] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (draft === null) return;
    setBusy(true);
    try {
      await api.put(`/api/services/${encodeURIComponent(svc.name)}/note`, { note: draft });
      setSaved(draft.trim());
      setDraft(null);
    } catch (e) {
      toast.error("备注没有保存", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  if (draft === null && !note) {
    return (
      <button
        type="button"
        onClick={() => setDraft("")}
        className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <StickyNoteIcon className="size-3.5" />
        加备注
      </button>
    );
  }

  return (
    <Card className="gap-3 py-4 shadow-xs">
      <CardHeader className="flex flex-row items-center justify-between px-5">
        <CardTitle className="text-sm font-medium text-muted-foreground">备注</CardTitle>
        {draft === null && (
          <Button size="xs" variant="ghost" onClick={() => setDraft(note)}>
            <PencilIcon />
            编辑
          </Button>
        )}
      </CardHeader>
      <CardContent className="px-5">
        {draft === null ? (
          <div className="text-sm break-words whitespace-pre-wrap" onDoubleClick={() => setDraft(note)}>
            {note}
          </div>
        ) : (
          <div className="grid gap-2">
            <Textarea
              autoFocus
              className="min-h-24 text-sm"
              placeholder="例如：用途、账号在哪、注意事项……"
              value={draft}
              maxLength={LIMIT}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) save();
                if (e.key === "Escape") setDraft(null);
              }}
            />
            <div className="flex items-center gap-2">
              <Button size="sm" disabled={busy} onClick={save}>
                保存
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setDraft(null)}>
                取消
              </Button>
              <span className="ml-auto text-xs text-muted-foreground">⌘/Ctrl + Enter 保存 · 不影响部署</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
