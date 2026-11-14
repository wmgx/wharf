import { CopyIcon, EyeIcon, EyeOffIcon, LockIcon, LockOpenIcon, PencilIcon, PlusIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import * as vault from "@/lib/vault";
import type { ServiceView } from "@/types";

const SHOW_MS = 60_000;
const box = "w-full rounded-md border bg-card px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50";

/**
 * 服务备注：放在页头标题下面。公开部分直接显示；私密部分在浏览器里用口令加密，服务器只存密文。
 * 直接保存，不走计划、不影响部署。
 */
export function ServiceNote({ svc }: { svc: ServiceView }) {
  // 保存后先显示本地值，等轮询拿到新数据。
  const [saved, setSaved] = useState<string | undefined>(undefined);
  const note = saved ?? svc.note ?? "";
  const { plain, sealed } = vault.splitNote(note);
  const [editing, setEditing] = useState(false);

  if (editing) return <Editor name={svc.name} plain={plain} sealed={sealed} onDone={(n) => (n !== null && setSaved(n), setEditing(false))} />;

  if (!note) {
    return (
      <button type="button" onClick={() => setEditing(true)} className="mt-1.5 inline-flex items-center gap-1 text-xs text-muted-foreground/70 hover:text-foreground">
        <PlusIcon className="size-3" />
        备注
      </button>
    );
  }

  return (
    <div className="group/note mt-2 grid max-w-2xl gap-1.5 border-l-2 border-border py-0.5 pl-3 hover:border-primary/60">
      {plain && <div className="text-sm break-words whitespace-pre-wrap text-foreground/80 select-text">{plain}</div>}
      {sealed && <Sealed sealed={sealed} />}
      <button type="button" onClick={() => setEditing(true)} className="inline-flex w-fit items-center gap-1 text-xs text-muted-foreground opacity-0 group-hover/note:opacity-100 hover:text-foreground focus-visible:opacity-100">
        <PencilIcon className="size-3" />
        编辑备注
      </button>
    </div>
  );
}

/** 私密内容：默认遮住，点"显示"解密，一分钟后自动遮回去。 */
function Sealed({ sealed }: { sealed: string }) {
  const [text, setText] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    if (text === null) return;
    const t = setTimeout(() => setText(null), SHOW_MS);
    return () => clearTimeout(t);
  }, [text]);

  const reveal = async (copy = false) => {
    if (!vault.isUnlocked()) return setAsking(true);
    try {
      const t = await vault.open(sealed);
      if (copy) {
        await navigator.clipboard.writeText(t);
        toast.success("已复制私密内容");
      } else setText(t);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <div className="grid gap-1.5">
      <div className="flex items-start gap-2 text-sm">
        <LockIcon className="mt-1 size-3.5 shrink-0 text-violet-600 dark:text-violet-400" />
        {text === null ? (
          <span className="text-muted-foreground tracking-widest">••••••</span>
        ) : (
          <span className="min-w-0 rounded bg-violet-500/10 px-1.5 break-words whitespace-pre-wrap select-text">{text}</span>
        )}
        <span className="ml-1 flex shrink-0 items-center">
          <Button size="xs" variant="ghost" onClick={() => (text === null ? reveal() : setText(null))}>
            {text === null ? <EyeIcon /> : <EyeOffIcon />}
            {text === null ? "显示" : "隐藏"}
          </Button>
          <Button size="xs" variant="ghost" onClick={() => reveal(true)}>
            <CopyIcon />
            复制
          </Button>
        </span>
      </div>
      {asking && <Unlock onDone={(ok) => (setAsking(false), ok && reveal())} />}
    </div>
  );
}

/** 查看、复制、编辑私密内容前的二次验证：输登录密码，5 分钟内有效。 */
function Unlock({ onDone }: { onDone: (ok: boolean) => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  if (!vault.supported()) return <div className="text-xs text-destructive">加密需要用 https 打开 Wharf，当前地址不支持</div>;

  const submit = async () => {
    setBusy(true);
    try {
      await vault.unlock(pass);
      onDone(true);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="grid max-w-sm gap-1.5 rounded-md border bg-muted/30 p-2.5"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <div className="text-xs text-muted-foreground">查看私密内容需要再验证一次登录密码，5 分钟内不用重复输入</div>
      <Input type="password" autoFocus autoComplete="current-password" placeholder="登录密码" value={pass} onChange={(e) => setPass(e.target.value)} className="h-8" />
      <div className="flex gap-2">
        <Button size="sm" type="submit" disabled={busy || !pass}>
          {busy ? "解锁中…" : "解锁"}
        </Button>
        <Button size="sm" type="button" variant="ghost" onClick={() => onDone(false)}>
          取消
        </Button>
      </div>
    </form>
  );
}

function Editor({ name, plain, sealed, onDone }: { name: string; plain: string; sealed: string | null; onDone: (note: string | null) => void }) {
  const [text, setText] = useState(plain);
  // null：私密部分没动（可能还没解锁），保存时原样保留密文。
  const [secret, setSecret] = useState<string | null>(sealed ? null : "");
  const [unlocked, setUnlocked] = useState(vault.isUnlocked());
  const [busy, setBusy] = useState(false);
  const [wantSecret, setWantSecret] = useState(!!sealed);

  useEffect(() => {
    if (sealed && unlocked && secret === null) vault.open(sealed).then(setSecret, (e) => toast.error((e as Error).message));
  }, [sealed, unlocked, secret]);

  const save = async () => {
    setBusy(true);
    try {
      let nextSealed = sealed;
      if (secret !== null) nextSealed = secret.trim() ? await vault.seal(secret.trim()) : null;
      const note = vault.joinNote(text, nextSealed);
      await api.put(`/api/services/${encodeURIComponent(name)}/note`, { note });
      onDone(note);
    } catch (e) {
      // 编辑时超过了 5 分钟：先验证，已填的内容保留。
      if (!vault.isUnlocked()) setUnlocked(false);
      toast.error("备注没有保存", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const keys = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) save();
    if (e.key === "Escape") onDone(null);
  };
  const needSecretInput = secret !== null && unlocked;

  return (
    <div className="mt-2 grid w-[min(40rem,80vw)] gap-2">
      <textarea
        autoFocus
        rows={Math.min(8, Math.max(2, text.split("\n").length))}
        placeholder="公开备注：用途、注意事项……"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={keys}
        className={cn(box, "resize-none")}
      />
      {!wantSecret ? (
        <button type="button" onClick={() => setWantSecret(true)} className="inline-flex w-fit items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          <LockIcon className="size-3" />
          加私密内容（账号、密码等，加密保存）
        </button>
      ) : (
      <div className="grid gap-1.5">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <LockIcon className="size-3 text-violet-600 dark:text-violet-400" />
          私密内容
          <span className="text-muted-foreground/70">用登录密码保护，在浏览器里加密，服务器只存密文</span>
          {unlocked && (
            <button
              type="button"
              className="ml-auto inline-flex items-center gap-1 hover:text-foreground"
              onClick={() => {
                vault.lock();
                setUnlocked(false);
                if (sealed) setSecret(null);
              }}
            >
              <LockOpenIcon className="size-3" />
              已验证 · 锁上
            </button>
          )}
        </div>
        {needSecretInput ? (
          <textarea
            rows={Math.min(8, Math.max(2, secret.split("\n").length))}
            placeholder="账号、密码、密钥……"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            onKeyDown={keys}
            spellCheck={false}
            className={cn(box, "resize-none border-violet-500/30 bg-violet-500/5 font-mono text-xs")}
          />
        ) : unlocked ? (
          <div className="text-xs text-muted-foreground">解密中…</div>
        ) : (
          <Unlock onDone={(ok) => (ok ? setUnlocked(true) : !sealed && setWantSecret(false))} />
        )}
      </div>
      )}
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={busy} onClick={save}>
          保存
        </Button>
        <Button size="sm" variant="ghost" onClick={() => onDone(null)}>
          取消
        </Button>
        <span className="ml-auto text-xs text-muted-foreground">⌘/Ctrl + Enter 保存 · Esc 取消 · 不影响部署</span>
      </div>
    </div>
  );
}
