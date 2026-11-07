import { LockIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import { Textarea } from "@/components/ui/textarea";
import type { SecretView } from "@/types";

/** 密钥汇总：只写不读。Wharf 自己生成的只显示，不能改删。 */
export function Secrets() {
  const { data, error, refresh } = usePoll<SecretView[]>("/api/secrets", 30000);
  const [editing, setEditing] = useState<{ name: string; fresh: boolean } | null>(null);
  const [removing, setRemoving] = useState<SecretView | null>(null);
  const { status } = useStatus();
  const serviceNames = new Set([...(status?.services ?? []).map((x) => x.name), ...(status?.edge_apps ?? []).map((x) => x.name)]);

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
        <SectionTitle count={data?.length}>密钥</SectionTitle>
        <Button variant="ghost" size="sm" onClick={() => setEditing({ name: "", fresh: true })}>
          <PlusIcon />
          添加
        </Button>
      </div>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>还没有密钥</Empty>
      ) : (
        data && (
          <div className="grid gap-6">
            {groups(data, serviceNames).map((g) => (
              <div key={g.title}>
                <h3 className="mb-2 text-sm font-medium text-muted-foreground">{g.title}</h3>
                <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-3">
                  {g.cards.map((c) => (
                    <div key={c.label} className="rounded-xl border bg-card p-3 shadow-xs">
                      {c.label && <div className="mb-1.5 px-1 text-sm font-semibold">{c.label}</div>}
                      {c.secrets.map((x) => (
                        <SecretRow key={x.name} s={x} onEdit={() => setEditing({ name: x.name, fresh: false })} onRemove={() => setRemoving(x)} />
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )
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

type Group = { title: string; cards: { label: string; secrets: SecretView[] }[] };

/** 按用途分组：每个服务一张卡；系统功能按功能名一张卡；没在用的放最后。 */
function groups(data: SecretView[], services: Set<string>): Group[] {
  const by = (keyOf: (u: string) => boolean) => {
    const m = new Map<string, SecretView[]>();
    for (const s of data) for (const u of s.used_by ?? []) if (keyOf(u)) m.set(u, [...(m.get(u) ?? []), s]);
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([label, secrets]) => ({ label, secrets }));
  };
  const unused = data.filter((s) => !s.used_by?.length);
  return [
    { title: "服务", cards: by((u) => services.has(u)) },
    { title: "系统功能", cards: by((u) => !services.has(u)) },
    { title: "没在用", cards: unused.length ? [{ label: "", secrets: unused }] : [] },
  ].filter((g) => g.cards.length);
}

function SecretRow({ s, onEdit, onRemove }: { s: SecretView; onEdit: () => void; onRemove: () => void }) {
  return (
    <div className="group flex items-center gap-2 rounded-md px-1 py-1 hover:bg-accent/50">
      <span className="min-w-0 flex-1 truncate font-mono text-xs" title={s.used_by?.length ? `用在 ${s.used_by.join("、")}` : undefined}>
        {s.name}
      </span>
      <span className="text-xs text-muted-foreground">{ago(s.updated_at)}</span>
      {s.managed ? (
        <span title="Wharf 自动生成，不能改删">
          <LockIcon className="size-3 text-muted-foreground" />
        </span>
      ) : (
        <span className="flex opacity-60 group-hover:opacity-100">
          <Button variant="ghost" size="icon-xs" title="替换" onClick={onEdit}>
            <PencilIcon />
          </Button>
          <Button variant="ghost" size="icon-xs" title="删除" className="text-destructive" onClick={onRemove}>
            <Trash2Icon />
          </Button>
        </span>
      )}
    </div>
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
