import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { AlertAck, AlertAckRequest, AlertTarget } from "@/types";

export function AlertConfirmation({ target, ack, refresh }: { target: AlertTarget; ack?: AlertAck | null; refresh: () => void }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  if (ack) {
    return <span className="break-words text-xs text-muted-foreground">
      已确认 · {ack.by} · {new Date(ack.at).toLocaleString("zh-CN")}{ack.note ? ` · ${ack.note}` : ""}
    </span>;
  }

  async function confirm() {
    setSaving(true);
    try {
      const body: AlertAckRequest = { rule: target.rule, subject: target.subject, acked: true, note };
      await api.put<AlertAck>("/api/alerts/ack", body);
      setOpen(false);
      setNote("");
      refresh();
    } catch (error) {
      toast.error("确认失败", { description: (error as Error).message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button variant="outline" size="xs">确认</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>确认告警</DialogTitle></DialogHeader>
        <form className="grid gap-4" onSubmit={(e) => { e.preventDefault(); void confirm(); }}>
          <Input aria-label="备注" placeholder="备注（选填）" maxLength={200} value={note} onChange={(e) => setNote(e.target.value)} />
          <DialogFooter><Button type="submit" disabled={saving}>确认</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
