import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ago, ErrorNote } from "./common";
import { Field } from "./fields";

/** 旧的全局账号，域名没有自己的账号时网关用它。和后端 BASIC_AUTH_SECRET 一致。 */
const LEGACY = "BASIC_AUTH";

/** 域名自己的登录保护账号存在这个密钥里，和后端 route_auth_secret 一致。 */
export const authSecret = (hostname: string) => `${LEGACY}_${hostname.replaceAll(".", "_")}`;

/** 保存账号：密码只发给控制面，控制面只保存 bcrypt 哈希。 */
export async function saveAuth(hostname: string, user: string, password: string) {
  await api.put(`/api/secrets/${authSecret(hostname)}`, { value: `${user.trim()}:${password}` });
}

/** 域名的账号什么时候设的：自己的、旧的全局账号。还在查是 undefined。 */
export function useAuthSetAt(hostname: string | null) {
  const [at, setAt] = useState<{ own: string | null; legacy: string | null } | undefined>(undefined);
  useEffect(() => {
    if (!hostname) return;
    api
      .get<{ name: string; updated_at: string }[]>("/api/secrets")
      .then((list) => {
        const find = (n: string) => list.find((s) => s.name === n)?.updated_at ?? null;
        setAt({ own: find(authSecret(hostname)), legacy: find(LEGACY) });
      })
      .catch(() => setAt({ own: null, legacy: null }));
  }, [hostname]);
  return at;
}

/** 用户名、密码两个输入框。 */
export function AuthFields({ user, password, onUser, onPassword }: { user: string; password: string; onUser: (v: string) => void; onPassword: (v: string) => void }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <Field label="用户名" htmlFor="ba-user">
        <Input id="ba-user" value={user} onChange={(e) => onUser(e.target.value)} autoComplete="username" />
      </Field>
      <Field label="密码" htmlFor="ba-pass" help="至少 8 位">
        <Input id="ba-pass" type="password" value={password} onChange={(e) => onPassword(e.target.value)} autoComplete="new-password" />
      </Field>
    </div>
  );
}

export const authReady = (user: string, password: string) => !!user.trim() && password.length >= 8;

/** 设置某个域名的登录保护账号：打开这个域名时浏览器要求输入的用户名和密码。 */
export function BasicAuthDialog({ hostname, enable, onClose, onSaved }: { hostname: string | null; enable: boolean; onClose: () => void; onSaved: () => void }) {
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const at = useAuthSetAt(hostname);

  useEffect(() => {
    setPassword("");
    setError(null);
  }, [hostname]);

  const save = async () => {
    if (!hostname) return;
    setSaving(true);
    setError(null);
    try {
      await saveAuth(hostname, user, password);
      toast.success(`已设置 ${hostname} 的登录账号`);
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={!!hostname} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{enable ? `开启 ${hostname} 的登录保护` : `${hostname} 的登录账号`}</DialogTitle>
          <DialogDescription>
            打开这个域名时浏览器会要求输入这组账号密码。
            {at?.own ? `上次设置于 ${ago(at.own)}。` : at?.legacy ? "现在用的是以前全部域名共用的账号，保存后这个域名改用自己的。" : ""}
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />
          <ErrorNote error={error} />
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              取消
            </Button>
            <Button type="submit" disabled={saving || !authReady(user, password)}>
              {enable ? "保存并生成计划" : "保存并更新网关"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
