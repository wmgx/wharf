import { useState } from "react";
import { api, setToken } from "../api";
import { ErrorNote } from "../components/ui";

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
    <div className="gate">
      <form className="card" onSubmit={submit}>
        <h1>WHARF</h1>
        <p>粘贴 API token 进入。token 只保存在这个浏览器里。</p>
        <div className="field">
          <label htmlFor="token">API token</label>
          <input id="token" type="password" autoFocus autoComplete="off" value={token} onChange={(e) => setValue(e.target.value)} />
          <span className="help">
            管理员 token 在控制面数据目录的 <span className="mono">admin.token</span>；也可以用{" "}
            <span className="mono">wharf token create</span> 新建一个。
          </span>
        </div>
        <ErrorNote error={error} />
        <button className="btn primary" disabled={!token.trim() || busy} style={{ width: "100%", justifyContent: "center" }}>
          {busy ? "验证中…" : "进入"}
        </button>
      </form>
    </div>
  );
}
