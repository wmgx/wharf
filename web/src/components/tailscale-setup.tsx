import { KeyRoundIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, ErrorNote } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { SecretView } from "@/types";

const SECRET = "TAILSCALE_OAUTH";

/** Tailscale OAuth 客户端：给没装 Tailscale 的机器现开一次性密钥用。只写不读。 */
export function TailscaleSetup() {
  const { data, refresh } = usePoll<SecretView[]>("/api/secrets", 60000);
  const [open, setOpen] = useState(false);
  const current = data?.find((s) => s.name === SECRET);
  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        <KeyRoundIcon />
        {current ? `Tailscale · ${ago(current.updated_at)}` : "设置 Tailscale"}
      </Button>
      {open && (
        <OAuthDialog
          onClose={() => setOpen(false)}
          onSaved={() => {
            setOpen(false);
            refresh();
          }}
        />
      )}
    </>
  );
}

function OAuthDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [id, setId] = useState("");
  const [secret, setSecret] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(`/api/secrets/${SECRET}`, { value: `${id.trim()}:${secret.trim()}` });
      setSecret("");
      toast.success("已保存 Tailscale OAuth 客户端");
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>Tailscale OAuth 客户端</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <Field label="Client ID" htmlFor="ts-id" help="权限 Auth Keys 写，标签 tag:wharf">
            <Input id="ts-id" autoComplete="off" value={id} onChange={(e) => setId(e.target.value)} className="font-mono" />
          </Field>
          <Field label="Client secret" htmlFor="ts-secret">
            <Input id="ts-secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} className="font-mono" />
          </Field>
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!id.trim() || !secret.trim() || saving} onClick={save}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
