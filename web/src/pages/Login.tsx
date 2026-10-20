import { useState } from "react";
import { api, setToken } from "@/api";
import { Logo } from "@/components/app-sidebar";
import { ErrorNote } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function Login({ onDone }: { onDone: () => void }) {
  const [token, setValue] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setToken(token.trim());
    try {
      await api.get("/api/servers");
      onDone();
    } catch (err) {
      setToken(null);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-svh place-items-center bg-[radial-gradient(800px_400px_at_50%_0%,color-mix(in_oklch,var(--primary)_10%,transparent),transparent_70%)] p-4">
      <div className="grid w-full max-w-sm gap-6">
        <div className="flex items-center gap-2.5 self-center text-lg font-semibold">
          <Logo />
          Wharf
        </div>
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">登录</CardTitle>
            <CardDescription>粘贴 API token。token 只保存在这个浏览器里。</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-4" onSubmit={submit}>
              <Field
                label="API token"
                htmlFor="token"
                help={
                  <>
                    管理员 token 在控制面数据目录的 <code className="font-mono">admin.token</code>；也可以用{" "}
                    <code className="font-mono">wharf token create</code> 新建一个。
                  </>
                }
              >
                <Input id="token" type="password" autoFocus autoComplete="off" value={token} onChange={(e) => setValue(e.target.value)} />
              </Field>
              <ErrorNote error={error} />
              <Button type="submit" className="w-full" disabled={!token.trim() || busy}>
                {busy ? "验证中…" : "进入"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
