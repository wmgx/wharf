import { CloudIcon, KeyRoundIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, CardsSkeleton, Empty, ErrorNote, Notice, PageHeader, SectionTitle } from "@/components/common";
import { Field, toName } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { AccountView } from "@/types";
import { CoreBackup } from "./core-backup";
import { EdgeImport } from "./edge-import";
import { Secrets } from "./secrets";
import { Tokens } from "./tokens";

/** 账号与密钥：厂商账号、密钥、API token、控制面备份。都只写不读。 */
export function Accounts() {
  const { data, error, refresh } = usePoll<AccountView[]>("/api/accounts", 30000);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [importing, setImporting] = useState<string | null>(null);

  const rediscover = async (name: string) => {
    setBusy(name);
    try {
      const a = await api.post<AccountView>(`/api/accounts/${encodeURIComponent(name)}/discover`, {});
      toast.success(`${name}：发现 ${a.zones.length} 个域名`);
      refresh();
    } catch (e) {
      toast.error(`重新发现失败`, { description: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };

  const remove = async (name: string) => {
    setRemoving(null);
    try {
      await api.del(`/api/accounts/${encodeURIComponent(name)}`);
      toast.success(`已删除账号 ${name}`);
      refresh();
    } catch (e) {
      toast.error(`不能删除 ${name}`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <PageHeader title="账号与密钥" />
      <div className="mb-3 flex items-center justify-between [&>h2]:mb-0">
        <SectionTitle count={data?.length}>厂商账号</SectionTitle>
        <Button variant="ghost" size="sm" onClick={() => setAdding(true)}>
          <PlusIcon />
          添加
        </Button>
      </div>
      <ErrorNote error={error} />
      {!data ? (
        <CardsSkeleton count={1} />
      ) : data.length === 0 ? (
        <Empty>还没有厂商账号</Empty>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] gap-3">
          {data.map((a) => (
            <div key={a.name} className="flex flex-col gap-3 rounded-xl border bg-card p-4 shadow-xs">
              <div className="flex items-center gap-3">
                <span className="grid size-9 place-items-center rounded-lg border bg-muted text-muted-foreground">
                  <KeyRoundIcon className="size-4" />
                </span>
                <div className="min-w-0">
                  <div className="font-semibold">{a.name}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {a.kind} · {a.token}
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {a.zones.length ? (
                  a.zones.map((z) => (
                    <Badge key={z} variant="secondary" className="font-mono">
                      {z}
                    </Badge>
                  ))
                ) : (
                  <span className="text-sm text-muted-foreground">没有发现域名</span>
                )}
              </div>
              {a.warnings?.map((w) => (
                <Notice key={w} kind="warn">
                  {w}
                </Notice>
              ))}
              <div className="mt-auto flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                <span className="whitespace-nowrap">更新于 {ago(a.updated_at)}</span>
                {a.kind === "cloudflare" && (
                  <Button variant="ghost" size="xs" className="ml-auto" onClick={() => setImporting(a.name)}>
                    <CloudIcon />
                    Workers / Pages
                  </Button>
                )}
                <Button variant="ghost" size="xs" className={a.kind === "cloudflare" ? undefined : "ml-auto"} disabled={busy === a.name} onClick={() => rediscover(a.name)}>
                  <RefreshCwIcon className={busy === a.name ? "animate-spin" : undefined} />
                  重新发现
                </Button>
                <Button variant="ghost" size="xs" className="text-destructive" onClick={() => setRemoving(a.name)}>
                  <Trash2Icon />
                  删除
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="mt-8 grid gap-8">
        <div>
          <Secrets />
        </div>
        <div>
          <Tokens />
        </div>
        <div>
          <CoreBackup />
        </div>
      </div>
      {importing && <EdgeImport account={importing} onClose={() => setImporting(null)} />}
      {adding && (
        <AddAccount
          taken={(data ?? []).map((a) => a.name)}
          onClose={() => setAdding(false)}
          onAdded={() => {
            setAdding(false);
            refresh();
          }}
        />
      )}
      <Dialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>删除账号 {removing}？</DialogTitle>
            <DialogDescription>只删除 Wharf 保存的 token</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRemoving(null)}>
              取消
            </Button>
            <Button variant="destructive" onClick={() => removing && remove(removing)}>
              删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** 只在打开时挂载，关掉就丢弃输入的 token。 */
function AddAccount({ taken, onClose, onAdded }: { taken: string[]; onClose: () => void; onAdded: () => void }) {
  const [name, setName] = useState(() => (taken.includes("cf") ? "" : "cf"));
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const a = await api.post<AccountView>("/api/accounts", { name, kind: "cloudflare", token: token.trim() });
      setToken("");
      toast.success(`已添加 ${a.name}`, { description: a.zones.length ? `发现域名：${a.zones.join("、")}` : "没有发现域名，检查 token 权限" });
      onAdded();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>添加 Cloudflare 账号</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <Field label="名称" htmlFor="acc-name">
            <Input id="acc-name" value={name} onChange={(e) => setName(toName(e.target.value))} />
          </Field>
          <Field
            label="API token"
            htmlFor="acc-token"
            help={
              <>权限：Zone.DNS 编辑、Zone 读取；可选 Cloudflare Tunnel、Workers Scripts、Cloudflare Pages、Workers Routes 编辑</>
            }
          >
            <Input id="acc-token" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} className="font-mono" />
          </Field>
          {name && taken.includes(name) && <Notice kind="warn">会替换同名账号的 token</Notice>}
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!name || !token.trim() || saving} onClick={save}>
            {saving ? "验证中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
