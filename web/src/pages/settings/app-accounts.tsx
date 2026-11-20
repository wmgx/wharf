import { EllipsisIcon, PlusIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { ConfirmDialog, Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { AppAccountView } from "@/types.gen";

const endpoint = "/api/sso/accounts";
const accountPath = (name: string) => `${endpoint}/${encodeURIComponent(name)}`;

export function AppAccounts({ selected, hostname }: { selected: string | null; hostname: string | null }) {
  const { status } = useStatus();
  const { data, error, refresh } = usePoll<AppAccountView[]>(endpoint, null);
  const [editing, setEditing] = useState<AppAccountView | "new" | null>(null);
  const [removing, setRemoving] = useState<AppAccountView | null>(null);
  const [revealed, setRevealed] = useState<{ name: string; password: string } | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const selectedExists = data?.some((account) => account.name === selected);
  useEffect(() => {
    if (selectedExists) document.getElementById(`app-account-${selected}`)?.scrollIntoView({ block: "nearest" });
  }, [selected, selectedExists]);

  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value);
    toast.success(`已复制${label}`);
  };
  const readPassword = async (name: string, copyOnly: boolean) => {
    setFailure(null);
    try {
      const { password } = await api.post<{ password: string }>(`${accountPath(name)}/password`, {});
      if (copyOnly) await copy(password, "密码");
      else setRevealed({ name, password });
    } catch (e) { setFailure(e); }
  };
  const remove = async (account: AppAccountView) => {
    setRemoving(null);
    setFailure(null);
    try {
      await api.del(accountPath(account.name));
      refresh();
    } catch (e) { setFailure(e); }
  };

  return <>
    <SectionTitle count={data?.length} action={<Button variant="ghost" size="sm" onClick={() => setEditing("new")}><PlusIcon />添加</Button>}>应用账号</SectionTitle>
    <ErrorNote error={error || failure} />
    {data?.length === 0 && <Empty>还没有应用账号</Empty>}
    {!!data?.length && <Panel className="divide-y">
      {data.map((account) => <div key={account.name} id={`app-account-${account.name}`} className={`grid gap-2 px-4 py-3 ${selected === account.name ? "bg-muted/50" : ""}`}>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
          <span className="font-mono">{account.name}</span>
          <span className="break-all">{account.username}</span>
          <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-muted-foreground">{account.note}</span>
          <span className="text-xs text-muted-foreground" title={new Date(account.updated_at).toLocaleString("zh-CN")}>{ago(account.updated_at)}</span>
          <DropdownMenu>
            <DropdownMenuTrigger asChild><Button aria-label={`${account.name} 的操作`} variant="ghost" size="icon-xs"><EllipsisIcon /></Button></DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => setEditing(account)}>编辑</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => { setFailure(null); void copy(account.username, "用户名").catch(setFailure); }}>复制用户名</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => void readPassword(account.name, false)}>显示密码</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => void readPassword(account.name, true)}>复制密码</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onSelect={() => setRemoving(account)}>删除</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <AccountDomains key={hostname ?? ""} account={account} preferred={hostname} hostnames={status?.routes.map((route) => route.spec.hostname) ?? []} refresh={refresh} />
      </div>)}
    </Panel>}
    {editing && <AccountEditor account={editing === "new" ? undefined : editing} names={data?.map((a) => a.name) ?? []} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />}
    <ConfirmDialog open={!!removing} title={`删除应用账号 ${removing?.name}？`} onCancel={() => setRemoving(null)} onConfirm={() => removing && remove(removing)}>
      {!!removing?.domains.length && `关联域名 ${removing.domains.map((d) => d.hostname).join("、")}`}
    </ConfirmDialog>
    {revealed && <Dialog open onOpenChange={(open) => !open && setRevealed(null)}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>{revealed.name} 的密码</DialogTitle></DialogHeader>
        <code className="whitespace-pre-wrap break-all text-sm">{revealed.password}</code>
      </DialogContent>
    </Dialog>}
  </>;
}

function AccountDomains({ account, preferred, hostnames, refresh }: { account: AppAccountView; preferred: string | null; hostnames: string[]; refresh: () => Promise<void> }) {
  const [host, setHost] = useState(preferred ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const available = hostnames.filter((hostname) => !account.domains.some((d) => d.hostname === hostname));
  const update = async (hostname: string, action: "link" | "default" | "unlink") => {
    setBusy(true);
    setError(null);
    const path = `${accountPath(account.name)}/domains/${encodeURIComponent(hostname)}`;
    try {
      if (action === "unlink") await api.del(path);
      else await api.put(path, { is_default: action === "default" });
      setHost("");
      await refresh();
    } catch (e) { setError(e); }
    finally { setBusy(false); }
  };
  return <>
    {account.domains.map((domain) => <div key={domain.hostname} className="flex flex-wrap items-center gap-2 text-xs">
      <span className={domain.exists ? "font-mono" : "font-mono text-muted-foreground"}>{domain.hostname}</span>
      {!domain.exists && <span className="text-muted-foreground">域名不存在</span>}
      {domain.is_default ? <span className="text-muted-foreground">默认账号</span> : domain.exists && <Button variant="ghost" size="xs" disabled={busy} onClick={() => update(domain.hostname, "default")}>设为默认</Button>}
      <Button variant="ghost" size="xs" disabled={busy} onClick={() => update(domain.hostname, "unlink")}>取消关联</Button>
    </div>)}
    {!!available.length && <div className="flex flex-wrap items-center gap-2">
      <div className="min-w-40 flex-1 sm:max-w-64">
        <Picker value={host} onChange={setHost} options={available.map((hostname) => ({ value: hostname, label: hostname }))} placeholder="选择域名" />
      </div>
      <Button variant="outline" size="sm" disabled={busy || !available.includes(host)} onClick={() => update(host, "link")}>关联</Button>
    </div>}
    <ErrorNote error={error} />
  </>;
}

function AccountEditor({ account, names, onClose, onSaved }: { account?: AppAccountView; names: string[]; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(account?.name ?? "");
  const [username, setUsername] = useState(account?.username ?? "");
  const [password, setPassword] = useState("");
  const [note, setNote] = useState(account?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const duplicate = !account && names.includes(name);
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(accountPath(name), { username, password: password || undefined, note });
      onSaved();
    } catch (e) { setError(e); }
    finally { setSaving(false); }
  };
  return <Dialog open onOpenChange={(open) => !open && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>{account ? `编辑 ${account.name}` : "添加应用账号"}</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        <Field label="名称" htmlFor="app-account-name"><Input id="app-account-name" value={name} readOnly={!!account} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="用户名" htmlFor="app-account-user"><Input id="app-account-user" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="密码" htmlFor="app-account-password"><Input id="app-account-password" type="password" autoComplete="new-password" placeholder={account ? "留空保留现有密码" : undefined} value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <Field label="备注" htmlFor="app-account-note"><Textarea id="app-account-note" value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        <ErrorNote error={duplicate ? new Error("应用账号名称已存在") : error} />
      </div>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>取消</Button>
        <Button disabled={!name || duplicate || !username || (!account && !password) || saving} onClick={save}>{saving ? "保存中…" : "保存"}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
