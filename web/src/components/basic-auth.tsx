import { useEffect, useState } from "react";
import { api } from "@/api";
import { Input } from "@/components/ui/input";
import { Field } from "./fields";

/** 域名的登录保护账号存在这个密钥里，和后端 route_auth_secret 一致。 */
export const authSecret = (hostname: string) => `BASIC_AUTH_${hostname.replaceAll(".", "_")}`;

/** 保存账号：密码只发给控制面，控制面只保存 bcrypt 哈希。 */
export async function saveAuth(hostname: string, user: string, password: string) {
  await api.put(`/api/secrets/${authSecret(hostname)}`, { value: `${user.trim()}:${password}` });
}

/** 域名的账号什么时候设的，没设是 null，还在查是 undefined。 */
export function useAuthSetAt(hostname: string | null) {
  const [at, setAt] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    if (!hostname) return;
    api
      .get<{ name: string; updated_at: string }[]>("/api/secrets")
      .then((list) => setAt(list.find((s) => s.name === authSecret(hostname))?.updated_at ?? null))
      .catch(() => setAt(null));
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
