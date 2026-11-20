import { CopyIcon, EllipsisIcon, EyeIcon, EyeOffIcon, LinkIcon, PencilIcon, PlusIcon, Trash2Icon, XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { api, ApiError, usePoll } from "@/api";
import { ago, CopyButton, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { ConfirmDialog, Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { AppAccountView } from "@/types.gen";

const endpoint = "/api/sso/accounts";
const accountPath = (name: string) => `${endpoint}/${encodeURIComponent(name)}`;
const domainPath = (name: string, host: string) => `${accountPath(name)}/domains/${encodeURIComponent(host)}`;
const defaultAccount = (accounts: AppAccountView[], host: string) =>
  accounts.find((account) => account.domains.some((d) => d.is_default && d.hostname === host));
const domainTag = "rounded-md bg-muted px-1.5 py-0.5 text-xs";
type PasswordAction = { account: AppAccountView; copyOnly: boolean };
type Revealed = { account: AppAccountView; password: string };

export function AppAccounts({ selected, hostname }: { selected: string | null; hostname: string | null }) {
  const { status } = useStatus();
  const { data, error, refresh } = usePoll<AppAccountView[]>(endpoint, null);
  const [, setParams] = useSearchParams();
  const [editing, setEditing] = useState<{ account?: AppAccountView; hostname?: string } | null>(null);
  const [associating, setAssociating] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [removeBusy, setRemoveBusy] = useState(false);
  const [removeError, setRemoveError] = useState<unknown>(null);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [verification, setVerification] = useState<PasswordAction | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const selectedExists = data?.some((account) => account.name === selected);
  useEffect(() => {
    if (selectedExists) document.getElementById(`app-account-${selected}`)?.scrollIntoView({ block: "nearest" });
  }, [selected, selectedExists]);

  const clearHostname = () => setParams((params) => {
    const next = new URLSearchParams(params);
    next.delete("hostname");
    return next;
  }, { replace: true });
  const setDefault = async (name: string, host: string) => {
    await api.put(domainPath(name, host), { is_default: true });
    toast.success(`已把 ${name} 设为 ${host} 的默认账号`);
    clearHostname();
    await refresh();
  };

  const readPassword = async ({ account, copyOnly }: PasswordAction, wharfPassword?: string) => {
    const { password } = await api.post<{ password: string }>(`${accountPath(account.name)}/password`, { password: wharfPassword });
    if (copyOnly) {
      try {
        await navigator.clipboard.writeText(password);
        toast.success(`已复制 ${account.name} 的密码`);
        return;
      } catch {
        toast("浏览器不允许自动复制，请点复制按钮");
      }
    }
    setRevealed({ account, password });
  };
  const requestPassword = async (account: AppAccountView, copyOnly: boolean) => {
    setFailure(null);
    const action = { account, copyOnly };
    try {
      await readPassword(action);
    } catch (e) {
      if (e instanceof ApiError && e.body.code === "PasswordRequired") setVerification(action);
      else setFailure(e);
    }
  };
  const remove = async (account: AppAccountView) => {
    setRemoveBusy(true);
    setRemoveError(null);
    const unlinked: string[] = [];
    try {
      for (const { hostname } of account.domains) {
        await api.del(domainPath(account.name, hostname));
        unlinked.push(hostname);
      }
      await api.del(accountPath(account.name));
      setRemoving(null);
      toast.success(`已删除 ${account.name}`);
    } catch (e) {
      setRemoveError(unlinked.length ? new Error(`${(e as Error).message}。已取消 ${unlinked.join("、")} 的关联。`) : e);
    } finally {
      await refresh();
      setRemoveBusy(false);
    }
  };
  const linked = data?.find((a) => a.name === associating);
  const deleting = data?.find((a) => a.name === removing);
  const hostnames = status?.routes.filter((r) => r.spec.expires_at == null).map((r) => r.spec.hostname).sort() ?? [];

  return <>
    <SectionTitle count={data?.length} action={<Button variant="ghost" size="sm" onClick={() => setEditing({})}><PlusIcon />添加</Button>}>应用账号</SectionTitle>
    <p className="mb-3 text-sm text-muted-foreground">
      登录应用用的账号和密码。代登录使用域名的默认账号；服务配置里写 <code className="font-mono">[[account.名称.password]]</code> 引用。和「密钥」不同，密码可以查看，查看前需要验证 Wharf 登录密码。
    </p>
    {hostname && <ChooseDefault key={hostname} hostname={hostname} accounts={data ?? []} onSelect={(name) => setDefault(name, hostname)} onAdd={() => setEditing({ hostname })} onClose={clearHostname} />}
    <ErrorNote error={error || failure} />
    {data?.length === 0 && <Empty>还没有应用账号。添加后关联到域名，代登录会使用域名的默认账号。</Empty>}
    {!!data?.length && <Panel className="divide-y">
      {data.map((account) => <div key={account.name} id={`app-account-${account.name}`} className={`grid gap-1 px-4 py-2.5 ${selected === account.name ? "bg-muted/50" : ""}`}>
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1 flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="min-w-32 break-all font-mono text-xs">{account.name}</span>
            <span className="inline-flex min-w-0 items-center gap-1">
              <span className="shrink-0 text-xs text-muted-foreground">用户名</span>
              <span className="break-all text-sm">{account.username}</span>
              <CopyButton text={account.username} />
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <span className="text-xs text-muted-foreground" title={new Date(account.updated_at).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}>{ago(account.updated_at)}</span>
            <DropdownMenu modal={false}>
              <Tip text="账号操作"><DropdownMenuTrigger asChild><Button aria-label={`${account.name} 的操作`} variant="ghost" size="icon-xs"><EllipsisIcon /></Button></DropdownMenuTrigger></Tip>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => setEditing({ account })}><PencilIcon />编辑</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setAssociating(account.name)}><LinkIcon />关联域名…</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void requestPassword(account, false)}><EyeIcon />显示密码</DropdownMenuItem>
                <DropdownMenuItem onSelect={() => void requestPassword(account, true)}><CopyIcon />复制密码</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => { setRemoveError(null); setRemoving(account.name); }}><Trash2Icon />删除</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        {account.note && <p className="line-clamp-2 whitespace-pre-wrap break-words text-xs text-muted-foreground">{account.note}</p>}
        <div className="flex flex-wrap gap-1.5">
          {account.domains.length ? account.domains.map((domain) => {
            const label = domain.hostname + (domain.is_default ? " · 默认" : "");
            return domain.exists
              ? <Link key={domain.hostname} className={`${domainTag} break-all hover:bg-accent`} to={`/domains?open=${encodeURIComponent(domain.hostname)}`}>{label}</Link>
              : <span key={domain.hostname} className={`${domainTag} break-all text-muted-foreground line-through`} title="域名不存在">{label}</span>;
          }) : <span className="text-xs text-muted-foreground">没有关联域名</span>}
        </div>
      </div>)}
    </Panel>}
    {editing && <AccountEditor account={editing.account} names={data?.map((a) => a.name) ?? []} onClose={() => setEditing(null)} onSaved={async (name) => {
      await refresh();
      if (editing.hostname) await setDefault(name, editing.hostname);
      setEditing(null);
    }} />}
    {linked && <AccountDomains account={linked} accounts={data ?? []} hostnames={hostnames} refresh={refresh} onClose={() => setAssociating(null)} />}
    <ConfirmDialog open={!!deleting} title={`删除应用账号 ${deleting?.name}？`} busy={removeBusy} confirmText={deleting?.domains.length ? "取消关联并删除" : "删除"} onCancel={() => !removeBusy && setRemoving(null)} onConfirm={() => deleting && void remove(deleting)}>
      {!!deleting?.domains.length && <p>还关联着 {deleting.domains.map((d) => d.hostname + (d.is_default ? "（默认）" : "")).join("、")}。删除会先取消这些关联。</p>}
      {removeError != null && <ErrorNote error={removeError} />}
    </ConfirmDialog>
    {verification && <VerifyPassword onClose={() => setVerification(null)} onVerify={async (password) => {
      await readPassword(verification, password);
      setVerification(null);
    }} />}
    {revealed && <RevealedPassword revealed={revealed} onClose={() => setRevealed(null)} />}
  </>;
}

function ChooseDefault({ hostname, accounts, onSelect, onAdd, onClose }: { hostname: string; accounts: AppAccountView[]; onSelect: (name: string) => Promise<void>; onAdd: () => void; onClose: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const select = async () => {
    setBusy(true);
    setError(null);
    try { await onSelect(name); }
    catch (e) { setError(e); }
    finally { setBusy(false); }
  };
  return <Panel className="relative mb-3 grid gap-2 px-4 py-3">
    <div className="flex flex-wrap items-center gap-2 pr-7 text-sm">
      <span>为 <strong className="break-all">{hostname}</strong> 选择默认账号：</span>
      <div className="min-w-40 max-w-64 flex-1">
        <Picker value={name} onChange={setName} options={accounts.map((a) => ({ value: a.name, label: `${a.name}（${a.username}）` }))} placeholder="选择账号" />
      </div>
      <Button size="sm" disabled={busy || !accounts.some((a) => a.name === name)} onClick={select}>设为默认</Button>
      <Button variant="ghost" size="sm" disabled={busy} onClick={onAdd}>添加新账号</Button>
    </div>
    <Button className="absolute top-2 right-2" variant="ghost" size="icon-xs" aria-label="关闭默认账号提示" disabled={busy} onClick={onClose}><XIcon /></Button>
    <ErrorNote error={error} />
  </Panel>;
}

function VerifyPassword({ onClose, onVerify }: { onClose: () => void; onVerify: (password: string) => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  return <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
    <DialogContent>
      <DialogHeader>
        <DialogTitle>验证 Wharf 登录密码</DialogTitle>
        <DialogDescription>查看应用账号密码前需要再验证一次，验证后 5 分钟内不用重复输入。</DialogDescription>
      </DialogHeader>
      <form className="grid gap-4" onSubmit={async (e) => {
        e.preventDefault();
        if (busy || !password) return;
        setBusy(true);
        setError(null);
        try { await onVerify(password); }
        catch (e) { setError(e); setPassword(""); }
        finally { setBusy(false); }
      }}>
        <Input type="password" autoComplete="current-password" aria-label="Wharf 登录密码" placeholder="Wharf 登录密码" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        <ErrorNote error={error} />
        <DialogFooter>
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>取消</Button>
          <Button disabled={busy || !password}>验证</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}

function RevealedPassword({ revealed, onClose }: { revealed: Revealed; onClose: () => void }) {
  const [seconds, setSeconds] = useState(30);
  useEffect(() => {
    const until = Date.now() + 30_000;
    const tick = window.setInterval(() => setSeconds(Math.max(0, Math.ceil((until - Date.now()) / 1000))), 1000);
    return () => window.clearInterval(tick);
  }, []);
  useEffect(() => { if (seconds === 0) onClose(); }, [seconds, onClose]);
  return <Dialog open onOpenChange={(open) => !open && onClose()}>
    <DialogContent>
      <DialogHeader>
        <DialogTitle>{revealed.account.name} 的密码</DialogTitle>
        <DialogDescription>用户名 {revealed.account.username}</DialogDescription>
      </DialogHeader>
      <div className="flex items-center gap-2 rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all">
        <code className="min-w-0 flex-1 whitespace-pre-wrap">{revealed.password}</code>
        <CopyButton text={revealed.password} />
      </div>
      <p className="text-xs text-muted-foreground">{seconds} 秒后自动隐藏</p>
      <DialogFooter><Button onClick={onClose}>关闭</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}

function AccountDomains({ account, accounts, hostnames, refresh, onClose }: { account: AppAccountView; accounts: AppAccountView[]; hostnames: string[]; refresh: () => Promise<void>; onClose: () => void }) {
  const [host, setHost] = useState("");
  const [makeDefault, setMakeDefault] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const available = hostnames.filter((hostname) => !account.domains.some((d) => d.hostname === hostname));
  const currentDefault = defaultAccount(accounts, host);
  const update = async (hostname: string, isDefault: boolean | null) => {
    setBusy(true);
    setError(null);
    try {
      if (isDefault === null) await api.del(domainPath(account.name, hostname));
      else await api.put(domainPath(account.name, hostname), { is_default: isDefault });
      setHost((value) => value === hostname ? "" : value);
      await refresh();
    } catch (e) { setError(e); }
    finally { setBusy(false); }
  };
  return <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>关联域名 · {account.name}</DialogTitle></DialogHeader>
      {!!account.domains.length && <div className="grid gap-1">
        {account.domains.map((domain) => <div key={domain.hostname} className="flex items-center gap-2 text-xs">
          <span className={`min-w-0 flex-1 break-all font-mono text-xs ${domain.exists ? "" : "text-muted-foreground line-through"}`} title={domain.exists ? undefined : "域名不存在"}>{domain.hostname}</span>
          {domain.exists && (domain.is_default
            ? <span className={domainTag}>默认</span>
            : <Button variant="ghost" size="xs" disabled={busy} onClick={() => void update(domain.hostname, true)}>设为默认</Button>)}
          <Button variant="ghost" size="xs" disabled={busy} onClick={() => void update(domain.hostname, null)}>取消关联</Button>
        </div>)}
      </div>}
      <div className={`grid gap-2 ${account.domains.length ? "border-t pt-3" : ""}`}>
        <div className="flex gap-2">
          <div className="min-w-0 flex-1">
            <Picker value={host} onChange={setHost} options={available.map((hostname) => ({ value: hostname, label: hostname }))} placeholder="选择域名" />
          </div>
          <Button variant="outline" size="sm" disabled={busy || !available.includes(host)} onClick={() => void update(host, makeDefault)}>关联</Button>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={makeDefault} disabled={busy} onCheckedChange={(checked) => setMakeDefault(checked === true)} />设为这个域名的默认账号
        </label>
        {currentDefault && <p className="text-xs text-muted-foreground">当前默认是 {currentDefault.name}，勾选会替换</p>}
      </div>
      <ErrorNote error={error} />
      <DialogFooter><Button disabled={busy} onClick={onClose}>完成</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}

function AccountEditor({ account, names, onClose, onSaved }: { account?: AppAccountView; names: string[]; onClose: () => void; onSaved: (name: string) => Promise<void> }) {
  const [name, setName] = useState(account?.name ?? "");
  const [username, setUsername] = useState(account?.username ?? "");
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [note, setNote] = useState(account?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [created, setCreated] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const nameError = account ? null : name.length > 48 ? "名称不能超过 48 个字符"
    : name.startsWith("-") || name.endsWith("-") ? "名称不能以 - 开头或结尾"
    : !created && names.includes(name) ? "应用账号名称已存在" : null;
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(accountPath(name), { username, password: password || undefined, note });
      if (!account) setCreated(true);
      toast.success(`已保存 ${name}`);
      await onSaved(name);
    } catch (e) { setError(e); }
    finally { setSaving(false); }
  };
  return <Dialog open onOpenChange={(open) => !open && !saving && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>{account ? `编辑 ${account.name}` : "添加应用账号"}</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        {!account && <Field label="名称" htmlFor="app-account-name" help={<>引用时写 <code className="font-mono">[[account.{name || "名称"}.password]]</code></>}>
          <Input id="app-account-name" className="font-mono" aria-invalid={!!nameError} value={name} readOnly={created} onChange={(e) => setName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} />
          {nameError && <p className="text-xs text-destructive">{nameError}</p>}
        </Field>}
        <Field label="用户名" htmlFor="app-account-user"><Input id="app-account-user" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="密码" htmlFor="app-account-password">
          <div className="relative">
            <Input id="app-account-password" className="pr-10" type={visible ? "text" : "password"} autoComplete="new-password" placeholder={account || created ? "留空保留现有密码" : undefined} value={password} onChange={(e) => setPassword(e.target.value)} />
            <Button className="absolute top-1/2 right-1 -translate-y-1/2" variant="ghost" size="icon-sm" aria-label={visible ? "隐藏密码" : "显示密码"} onClick={() => setVisible(!visible)}>{visible ? <EyeOffIcon /> : <EyeIcon />}</Button>
          </div>
        </Field>
        <Field label="备注" htmlFor="app-account-note"><Textarea id="app-account-note" value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        <ErrorNote error={error} />
      </div>
      <DialogFooter>
        <Button variant="ghost" disabled={saving} onClick={onClose}>取消</Button>
        <Button disabled={!name || !!nameError || !username.trim() || (!account && !created && !password) || saving} onClick={save}>{saving ? "保存中…" : "保存"}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
