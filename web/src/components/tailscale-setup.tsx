import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Dot, ErrorNote } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { SecretView } from "@/types";

const SECRET = "TAILSCALE_OAUTH";

/** Tailscale OAuth 客户端：给没装 Tailscale 的机器现开一次性密钥用。只写不读。 */
export function TailscaleDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { data, refresh } = usePoll<SecretView[]>("/api/secrets", 60000);
  const current = data?.find((s) => s.name === SECRET);
  return open ? <OAuthDialog current={current} onClose={onClose} onSaved={() => { refresh(); onClose(); }} /> : null;
}

function OAuthDialog({ current, onClose, onSaved }: { current?: SecretView; onClose: () => void; onSaved: () => void }) {
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
          <DialogTitle>组网设置</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="flex items-center gap-2 text-sm"><Dot tone={current ? "ok" : "idle"} />{current ? `Tailscale 凭据已保存，${ago(current.updated_at)}更新` : "还没设置。没装 Tailscale 的机器加入时要用它。"}</div>
          <Field label="Client ID" htmlFor="ts-id" help="在 Tailscale 后台新建 OAuth 客户端，权限选 Auth Keys（写），标签填 tag:wharf。保存后不能再查看，只能替换。">
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
            {saving ? "保存中…" : current ? "替换" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
