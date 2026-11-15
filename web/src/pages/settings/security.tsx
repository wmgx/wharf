import { useState } from "react";
import { api, usePoll } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { TotpView } from "@/types.gen";

type Mode = "begin" | "recovery" | "disable";
type Pending = { secret: string; uri: string; qr_svg: string };

export function Security() {
  const { data, error, refresh } = usePoll<TotpView>("/api/totp", 30000);
  const [mode, setMode] = useState<Mode | null>(null);
  return <>
    <SectionTitle>两步验证</SectionTitle>
    <ErrorNote error={error} />
    {data && <Panel className="flex flex-wrap items-center gap-3 p-4">
      <span className="flex-1 text-sm">{data.enabled ? `已开启 · 恢复码剩 ${data.recovery_left} 个` : "没开"}</span>
      <Button variant="outline" size="sm" onClick={() => setMode("begin")}>{data.enabled ? "换认证器" : "开启"}</Button>
      {data.enabled && <>
        <Button variant="outline" size="sm" onClick={() => setMode("recovery")}>重新生成恢复码</Button>
        <Button variant="outline" size="sm" onClick={() => setMode("disable")}>关闭</Button>
      </>}
    </Panel>}
    {mode && <TotpDialog mode={mode} onClose={() => { setMode(null); refresh(); }} onChanged={refresh} />}
  </>;
}

function TotpDialog({ mode, onClose, onChanged }: { mode: Mode; onClose: () => void; onChanged: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      if (mode === "begin" && !pending) {
        setPending(await api.post<Pending>("/api/totp/begin", { password }));
        setPassword("");
      } else {
        const result = await api.post<{ recovery_codes: string[] }>(`/api/totp/${mode === "begin" ? "enable" : mode}`, { password, code });
        setPassword(""); setCode(""); setPending(null); onChanged();
        if (mode === "disable") onClose();
        else setCodes(result.recovery_codes);
      }
    } catch (err) { setError(err); } finally { setBusy(false); }
  };
  const copy = async (text: string) => {
    try { await navigator.clipboard.writeText(text); } catch (err) { setError(err); }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([codes!.join("\n") + "\n"], { type: "text/plain" }));
    const a = document.createElement("a"); a.href = url; a.download = "wharf-recovery-codes.txt"; a.click(); URL.revokeObjectURL(url);
  };
  return <Dialog open onOpenChange={(open) => { if (!open && !codes) onClose(); }}>
    <DialogContent showCloseButton={!codes} className="max-h-[90svh] overflow-y-auto" onEscapeKeyDown={(e) => { if (codes) e.preventDefault(); }} onPointerDownOutside={(e) => { if (codes) e.preventDefault(); }}>
      <DialogHeader><DialogTitle>{codes ? "恢复码" : mode === "begin" ? "开启两步验证" : mode === "disable" ? "关闭两步验证" : "重新生成恢复码"}</DialogTitle></DialogHeader>
      <form className="grid gap-4 min-w-0" onSubmit={submit}>
        {codes ? <>
          <div className="grid grid-cols-2 gap-2 font-mono text-sm" data-recovery-codes>{codes.map((c) => <span key={c}>{c}</span>)}</div>
          <div className="flex gap-2"><Button type="button" variant="outline" onClick={() => copy(codes.join("\n"))}>复制</Button><Button type="button" variant="outline" onClick={download}>下载</Button></div>
          <label className="flex items-center gap-2 text-sm"><Checkbox checked={saved} onCheckedChange={(v) => setSaved(v === true)} />我已经保存好了</label>
        </> : pending ? <>
          {/* SVG 由后端 qrcode 生成，不含用户提供的标记。 */}
          <div className="mx-auto w-56 max-w-full bg-white p-3 [&_svg]:h-auto [&_svg]:w-full" dangerouslySetInnerHTML={{ __html: pending.qr_svg }} />
          <div className="flex min-w-0 items-center gap-2"><code className="min-w-0 break-all text-xs">{pending.secret}</code><Button type="button" variant="ghost" size="sm" onClick={() => copy(pending.secret)}>复制</Button></div>
          <Field label="验证码" htmlFor="totp-code"><Input id="totp-code" autoFocus inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} /></Field>
        </> : <>
          <Field label="登录密码" htmlFor="totp-password"><Input id="totp-password" autoFocus type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          {mode !== "begin" && <Field label="验证码" htmlFor="totp-code"><Input id="totp-code" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} /></Field>}
        </>}
        <ErrorNote error={error} />
        <DialogFooter>
          {codes ? <Button type="button" disabled={!saved} onClick={onClose}>完成</Button> : <Button type="submit" disabled={busy || (pending ? !code.trim() : !password || (mode !== "begin" && !code.trim()))}>{busy ? "请稍候…" : pending ? "确认" : mode === "begin" ? "下一步" : "确认"}</Button>}
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}
