import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ago, ErrorNote } from "./common";
import { Field } from "./fields";

/** 和后端 BASIC_AUTH_SECRET 一致。 */
export const BASIC_AUTH_SECRET = "BASIC_AUTH";

interface SecretView {
  name: string;
  updated_at: string;
}

/** 保存账号后广播，正在显示"还没有设置"的地方重新查询。 */
const SAVED_EVENT = "wharf:basic-auth-saved";

/** 登录保护账号什么时候设置的；没设置是 null，还在查询是 undefined。 */
export function useBasicAuthSetAt(reload = 0): string | null | undefined {
  const [at, setAt] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    const load = () =>
      api
        .get<SecretView[]>("/api/secrets")
        .then((list) => setAt(list.find((s) => s.name === BASIC_AUTH_SECRET)?.updated_at ?? null))
        .catch(() => setAt(null));
    load();
    window.addEventListener(SAVED_EVENT, load);
    return () => window.removeEventListener(SAVED_EVENT, load);
  }, [reload]);
  return at;
}

/**
 * 设置登录保护的账号。所有开了登录保护的域名共用这一个账号。
 * 密码只发给控制面，控制面只保存 bcrypt 哈希。
 */
export function BasicAuthDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const setAt = useBasicAuthSetAt(open ? 1 : 0);

  useEffect(() => {
    if (!open) return;
    setPassword("");
    setError(null);
  }, [open]);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(`/api/secrets/${BASIC_AUTH_SECRET}`, { value: `${user.trim()}:${password}` });
      setPassword("");
      window.dispatchEvent(new Event(SAVED_EVENT));
      toast.success("已设置登录保护账号");
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>登录保护账号</DialogTitle>
          <DialogDescription>
            {setAt ? `上次设置于 ${ago(setAt)}` : "未设置"}
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <Field label="用户名" htmlFor="ba-user">
            <Input id="ba-user" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" />
          </Field>
          <Field label="密码" htmlFor="ba-pass" help="至少 8 位">
            <Input id="ba-pass" type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          </Field>
          <ErrorNote error={error} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              取消
            </Button>
            <Button type="submit" disabled={saving || !user.trim() || password.length < 8}>
              保存
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
