import { useState } from "react";
import { api, type Session } from "@/api";
import { Logo } from "@/components/app-sidebar";
import { ErrorNote } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import * as vault from "@/lib/vault";

/**
 * 登录页。两种情况：
 * - 还没有管理员账号：凭服务器上的一次性初始化码设置账号密码，设置完直接进入；
 * - 已有账号：账号密码登录。
 */
export function Login({ session, onDone }: { session: Session; onDone: (s: Session) => void }) {
  return (
    <div className="grid min-h-svh place-items-center bg-[radial-gradient(800px_400px_at_50%_0%,color-mix(in_oklch,var(--primary)_10%,transparent),transparent_70%)] p-4">
      <div className="grid w-full max-w-sm gap-6">
        <div className="flex items-center gap-2.5 self-center text-lg font-semibold">
          <Logo />
          Wharf
        </div>
        <CredentialsForm mode={session.setup_needed ? "setup" : "login"} onDone={onDone} />
      </div>
    </div>
  );
}

function CredentialsForm({ mode, onDone }: { mode: "login" | "setup"; onDone: (s: Session) => void }) {
  const setup = mode === "setup";
  const [username, setUsername] = useState(setup ? "admin" : "");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState<{ session: Session; password: string } | null>(null);

  const mismatch = setup && !!again && again !== password;
  const tooShort = setup && !!password && password.length < 8;
  const ready = !!username.trim() && !!password && (!setup || (password === again && !tooShort && !!code.trim()));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await api.post<Session>(setup ? "/api/setup" : "/api/login", setup ? { username: username.trim(), password, code: code.trim() } : { username: username.trim(), password });
      // 用登录密码解开备注私密内容的数据密钥；密码重置过时先让用户同步一次。
      if ((await vault.afterLogin(password)) === "stale") setStale({ session, password });
      else onDone(session);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  if (stale) return <SyncVault password={stale.password} onDone={() => onDone(stale.session)} />;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">{setup ? "设置管理员账号" : "登录"}</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" onSubmit={submit}>
          {setup && (
            <Field
              label="初始化码"
              htmlFor="setup-code"
              help={
                <>
                  在服务器上执行 <code className="font-mono">docker exec wharf-core cat /var/lib/wharf-core/setup.code</code>
                </>
              }
            >
              <Input id="setup-code" autoFocus autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
          )}
          <Field label="账号" htmlFor="username">
            <Input id="username" autoFocus={!setup} autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label="密码" htmlFor="password" help={setup ? "至少 8 位" : undefined}>
            <Input
              id="password"
              type="password"
              autoComplete={setup ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              aria-invalid={tooShort || undefined}
            />
          </Field>
          {setup && (
            <Field label="再输入一次" htmlFor="again" help={mismatch ? <span className="text-destructive">两次输入的密码不一样</span> : undefined}>
              <Input id="again" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} aria-invalid={mismatch || undefined} />
            </Field>
          )}
          <ErrorNote error={error} />
          <Button type="submit" className="w-full" disabled={!ready || busy}>
            {busy ? "请稍候…" : setup ? "设置并进入" : "登录"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

/** 密码重置过：备注私密内容的数据密钥还是旧密码包的，输一次旧密码换成新密码包。 */
function SyncVault({ password, onDone }: { password: string; onDone: () => void }) {
  const [old, setOld] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await vault.migrate(old, password);
      onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">同步私密备注</CardTitle>
        <CardDescription>登录密码改过了。备注里的私密内容是用旧密码保护的，输一次旧密码，换成现在的密码。</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" onSubmit={submit}>
          <Field label="旧密码" htmlFor="old-password">
            <Input id="old-password" type="password" autoFocus autoComplete="off" value={old} onChange={(e) => setOld(e.target.value)} />
          </Field>
          <ErrorNote error={error} />
          <Button type="submit" disabled={!old || busy}>
            {busy ? "同步中…" : "同步并进入"}
          </Button>
          <Button type="button" variant="ghost" onClick={onDone}>
            先跳过（私密内容暂时打不开，下次登录还会问）
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
