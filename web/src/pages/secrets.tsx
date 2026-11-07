import { PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Link } from "react-router-dom";
import { Textarea } from "@/components/ui/textarea";
import type { SecretView } from "@/types";

/** 密钥汇总：只写不读。Wharf 自己生成的只显示，不能改删。 */
export function Secrets() {
  const { data, error, refresh } = usePoll<SecretView[]>("/api/secrets", 30000);
  const [editing, setEditing] = useState<{ name: string; fresh: boolean } | null>(null);
  const [removing, setRemoving] = useState<SecretView | null>(null);
  const apps = (data ?? []).filter((x) => !x.system && !x.managed);
  const systemCount = (data ?? []).length - apps.length;

  const remove = async (s: SecretView) => {
    setRemoving(null);
    try {
      await api.del(`/api/secrets/${encodeURIComponent(s.name)}`);
      toast.success(`已删除 ${s.name}`);
      refresh();
    } catch (e) {
      toast.error(`不能删除 ${s.name}`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <div className="mb-3 flex items-center justify-between [&>h2]:mb-0">
        <SectionTitle count={apps.length}>应用密钥</SectionTitle>
        <Button variant="ghost" size="sm" onClick={() => setEditing({ name: "", fresh: true })}>
          <PlusIcon />
          添加
        </Button>
      </div>
      <p className="mb-3 text-sm text-muted-foreground">
        服务的环境变量和 compose 里写 <code className="font-mono">[[名称]]</code> 引用，部署时替换。值只能写入、不能读出。
      </p>
      <ErrorNote error={error} />
      {data &&
        (apps.length === 0 ? (
          <Empty>还没有应用密钥</Empty>
        ) : (
          <div className="divide-y rounded-xl border bg-card">
            {apps.map((x) => (
              <div key={x.name} className="group flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5">
                <span className="min-w-48 font-mono text-[13px]">{x.name}</span>
                <span className="flex flex-1 flex-wrap gap-1.5 text-sm">
                  {x.used_by?.length ? (
                    x.used_by.map((u) => (
                      <Link key={u} to={`/services/${encodeURIComponent(u)}`} className="rounded-md bg-muted px-1.5 py-0.5 text-xs hover:bg-accent">
                        {u}
                      </Link>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">没有服务在用</span>
                  )}
                </span>
                <span className="text-xs text-muted-foreground">{ago(x.updated_at)}</span>
                <span className="flex">
                  <Button variant="ghost" size="icon-xs" title="替换值" onClick={() => setEditing({ name: x.name, fresh: false })}>
                    <PencilIcon />
                  </Button>
                  <Button variant="ghost" size="icon-xs" title="删除" className="text-destructive" onClick={() => setRemoving(x)}>
                    <Trash2Icon />
                  </Button>
                </span>
              </div>
            ))}
          </div>
        ))}
      {systemCount > 0 && (
        <p className="mt-3 text-xs text-muted-foreground">另有 {systemCount} 个由 Wharf 自己的功能使用（登录保护、组网、通知、备份等），在对应功能里设置，这里不显示。</p>
      )}
      {editing && (
        <SetSecret
          initial={editing.name}
          fresh={editing.fresh}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}
      <Dialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>删除密钥 {removing?.name}？</DialogTitle>
            {removing?.used_by?.length ? <DialogDescription>还在用：{removing.used_by.join("、")}</DialogDescription> : null}
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

/** 只在打开时挂载，关掉就丢弃输入的值。 */
export function SetSecret({ initial, fresh, onClose, onSaved }: { initial: string; fresh: boolean; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(initial);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await api.put(`/api/secrets/${encodeURIComponent(name)}`, { value });
      setValue("");
      toast.success(`已保存 ${name}`);
      onSaved();
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
          <DialogTitle>{fresh ? "添加密钥" : `替换 ${initial}`}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          {fresh && (
            <Field label="名称" htmlFor="secret-name" help={<>环境变量里写 [[{name || "名称"}]] 引用</>}>
              <Input id="secret-name" value={name} onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_-]/g, ""))} className="font-mono" />
            </Field>
          )}
          <Field label="值" htmlFor="secret-value">
            <Textarea id="secret-value" autoComplete="off" spellCheck={false} value={value} onChange={(e) => setValue(e.target.value)} className="min-h-20 font-mono text-xs" />
          </Field>
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!name || !value || saving} onClick={save}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
