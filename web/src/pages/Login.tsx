import { useState } from "react";
import { api, type Session } from "@/api";
import { Logo } from "@/components/app-sidebar";
import { ErrorNote, Notice } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

/**
 * 登录页。三种情况：
 * - 还没有管理员账号、在启动后 30 分钟内：设置账号密码，设置完直接进入；
 * - 还没有管理员账号、已超过 30 分钟：提示重启控制面或在服务器上重置；
 * - 已有账号：账号密码登录。
 */
export function Login({ session, onDone, onRetry }: { session: Session; onDone: (s: Session) => void; onRetry: () => void }) {
  return (
    <div className="grid min-h-svh place-items-center bg-[radial-gradient(800px_400px_at_50%_0%,color-mix(in_oklch,var(--primary)_10%,transparent),transparent_70%)] p-4">
      <div className="grid w-full max-w-sm gap-6">
        <div className="flex items-center gap-2.5 self-center text-lg font-semibold">
          <Logo />
          Wharf
        </div>
        {!session.setup_needed ? (
          <CredentialsForm mode="login" onDone={onDone} />
        ) : session.setup_open ? (
          <CredentialsForm mode="setup" onDone={onDone} />
        ) : (
          <SetupClosed onRetry={onRetry} />
        )}
      </div>
    </div>
  );
}

function CredentialsForm({ mode, onDone }: { mode: "login" | "setup"; onDone: (s: Session) => void }) {
  const setup = mode === "setup";
  const [username, setUsername] = useState(setup ? "admin" : "");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = setup && !!again && again !== password;
  const tooShort = setup && !!password && password.length < 8;
  const ready = !!username.trim() && !!password && (!setup || (password === again && !tooShort));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await api.post<Session>(setup ? "/api/setup" : "/api/login", { username: username.trim(), password }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">{setup ? "设置管理员账号" : "登录"}</CardTitle>
        <CardDescription>
          {setup ? "第一次使用，先设置页面登录用的账号密码。控制面启动后 30 分钟内可以设置。" : "用管理员账号登录。CLI 和 AI 继续用 API token。"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" onSubmit={submit}>
          <Field label="账号" htmlFor="username">
            <Input id="username" autoFocus={!setup} autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label="密码" htmlFor="password" help={setup ? "至少 8 个字符。" : undefined}>
            <Input
              id="password"
              type="password"
              autoFocus={setup}
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
          {!setup && (
            <p className="text-xs text-muted-foreground">
              忘记密码：在服务器上执行 <code className="font-mono">docker exec -it wharf-core wharf-core reset-password</code>
            </p>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

function SetupClosed({ onRetry }: { onRetry: () => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">还没有管理员账号</CardTitle>
        <CardDescription>为了防止别人抢先设置，只有控制面启动后 30 分钟内可以在页面上设置，现在已经过了。</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Notice>
          二选一：
          <ul className="mt-1.5 list-disc space-y-1 pl-4">
            <li>
              重启控制面（<code className="font-mono">docker restart wharf-core</code>）后刷新这个页面；
            </li>
            <li>
              在服务器上执行 <code className="font-mono">docker exec -it wharf-core wharf-core reset-password</code> 直接设置。
            </li>
          </ul>
        </Notice>
        <Button variant="outline" onClick={onRetry}>
          已处理，刷新
        </Button>
      </CardContent>
    </Card>
  );
}
