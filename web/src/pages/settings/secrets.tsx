import { ConfirmDialog, Tip } from "@/components/kit";
import { Panel } from "@/components/kit";
import { EllipsisIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Link } from "react-router-dom";
import { Textarea } from "@/components/ui/textarea";
import type { SecretView } from "@/types";

/** 密钥汇总：只写不读。Wharf 自己生成的只显示，不能改删。 */
export function Secrets() {
  const { data, error, refresh } = usePoll<SecretView[]>("/api/secrets", 30000);
  const [editing, setEditing] = useState<{ name: string; fresh: boolean } | null>(null);
  const [removing, setRemoving] = useState<SecretView | null>(null);
  const [previous, setPrevious] = useState<{ secret: SecretView; rollback: boolean } | null>(null);
  const apps = (data ?? []).filter((x) => !x.system && !x.managed);

  const remove = async (s: SecretView) => {
    setRemoving(null);
    try {
      await api.del(`/api/secrets/${encodeURIComponent(s.name)}`);
      toast.success(`已删除 ${s.name}`);
      refresh();
    } catch (e) {
      toast.error(`删除 ${s.name} 失败`, { description: (e as Error).message });
    }
  };

  const changePrevious = async () => {
    if (!previous) return;
    const { secret, rollback } = previous;
    setPrevious(null);
    try {
      if (rollback) {
        const result = await api.post<{ needs_plan: boolean }>(`/api/secrets/${encodeURIComponent(secret.name)}/rollback`, {});
        toast.success(result.needs_plan ? "密钥已回退，待应用变更" : "密钥已回退");
      } else {
        await api.del(`/api/secrets/${encodeURIComponent(secret.name)}/previous`);
        toast.success("已清除旧值");
      }
      refresh();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <>
      <SectionTitle count={apps.length} action={ <Button variant="ghost" size="sm" onClick={() => setEditing({ name: "", fresh: true })}>
          <PlusIcon />
          添加
        </Button> }>应用密钥</SectionTitle>
      <p className="mb-3 text-sm text-muted-foreground">
        服务的环境变量和 compose 里写 <code className="font-mono">[[名称]]</code> 引用，部署时替换。值只能写入、不能读出。
      </p>
      <ErrorNote error={error} />
      {data &&
        (apps.length === 0 ? (
          <Empty>还没有应用密钥</Empty>
        ) : (
          <Panel className="divide-y">
            {apps.map((x) => (
              <div key={x.name} className="group flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5">
                <span className="min-w-48 font-mono text-xs">{x.name}</span>
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
                {x.other_refs?.map((ref) => <span className="text-xs text-muted-foreground" key={ref}>{ref}</span>)}
                {x.fingerprint && <span className="font-mono text-xs text-muted-foreground">{x.fingerprint}</span>}
                {x.has_previous && x.prev_expires_at && (
                  <span className="rounded-md bg-muted px-1.5 py-0.5 text-xs">
                    已留旧值（至 {new Date(x.prev_expires_at).toLocaleString("zh-CN", {
                      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
                    })}）
                  </span>
                )}
                {x.allowed_services && (
                  <span className="text-xs text-muted-foreground">仅限 {x.allowed_services.join("、")}</span>
                )}
                <span className="text-xs text-muted-foreground">{ago(x.updated_at)}</span>
                <DropdownMenu>
                  <Tip text="密钥操作"><DropdownMenuTrigger asChild><Button aria-label={`${x.name} 的操作`} variant="ghost" size="icon-xs"><EllipsisIcon /></Button></DropdownMenuTrigger></Tip>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onSelect={() => setEditing({ name: x.name, fresh: false })}><PencilIcon />替换</DropdownMenuItem>
                    {x.has_previous && (
                      <>
                        <DropdownMenuItem onSelect={() => setPrevious({ secret: x, rollback: true })}>回退到旧值</DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => setPrevious({ secret: x, rollback: false })}>清除旧值</DropdownMenuItem>
                      </>
                    )}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem variant="destructive" onSelect={() => setRemoving(x)}><Trash2Icon />删除</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            ))}
          </Panel>
        ))}
      {editing && (
        <SetSecret
          initial={editing.name}
          fresh={editing.fresh}
          rotate={!editing.fresh}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}
      <ConfirmDialog open={!!previous} title={previous?.rollback ? "回退到旧值？" : "清除旧值？"} confirmText={previous?.rollback ? "回退" : "清除"} onCancel={() => setPrevious(null)} onConfirm={changePrevious} />
      <ConfirmDialog open={!!removing} title={`删除密钥 ${removing?.name}？`} onCancel={() => setRemoving(null)} onConfirm={() => removing && remove(removing)}>{removing?.used_by?.length ? `还在用：${removing.used_by.join("、")}` : null}</ConfirmDialog>
    </>
  );
}

/** 只在打开时挂载，关掉就丢弃输入的值。 */
export function SetSecret({ initial, fresh, rotate = false, onClose, onSaved }: { initial: string; fresh: boolean; rotate?: boolean; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(initial);
  const [value, setValue] = useState("");
  const [keep, setKeep] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const body = { value, keep_days: keep ? 7 : 0 };
      const result = rotate
        ? await api.post<{ needs_plan: boolean }>(`/api/secrets/${encodeURIComponent(name)}/rotate`, body)
        : await api.put<SecretView>(`/api/secrets/${encodeURIComponent(name)}`, body);
      setValue("");
      toast.success("needs_plan" in result && result.needs_plan ? "密钥已更新，待应用变更" : `已保存 ${name}`);
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
          {!fresh && (
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
              保留旧值 7 天
            </label>
          )}
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
