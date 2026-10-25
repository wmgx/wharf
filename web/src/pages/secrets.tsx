import { LockIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import type { SecretView } from "@/types";

/** 密钥汇总：只写不读。Wharf 自己生成的只显示，不能改删。 */
export function Secrets() {
  const { data, error, refresh } = usePoll<SecretView[]>("/api/secrets", 30000);
  const [editing, setEditing] = useState<{ name: string; fresh: boolean } | null>(null);
  const [removing, setRemoving] = useState<SecretView | null>(null);

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
      <div className="flex items-center justify-between">
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
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>用在</TableHead>
                  <TableHead>更新</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((s) => (
                  <TableRow key={s.name}>
                    <TableCell className="font-mono text-xs">{s.name}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {s.used_by?.length ? (
                          s.used_by.map((u) => (
                            <Badge key={u} variant="secondary">
                              {u}
                            </Badge>
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">没在用</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ago(s.updated_at)}</TableCell>
                    <TableCell>
                      {s.managed ? (
                        <span className="flex items-center gap-1 px-2 text-xs text-muted-foreground">
                          <LockIcon className="size-3" />
                          自动生成
                        </span>
                      ) : (
                        <div className="flex">
                          <Button variant="ghost" size="xs" onClick={() => setEditing({ name: s.name, fresh: false })}>
                            <PencilIcon />
                            替换
                          </Button>
                          <Button variant="ghost" size="xs" className="text-destructive" onClick={() => setRemoving(s)}>
                            <Trash2Icon />
                          </Button>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
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

/** 只在打开时挂载，关掉就丢弃输入的值。 */
function SetSecret({ initial, fresh, onClose, onSaved }: { initial: string; fresh: boolean; onClose: () => void; onSaved: () => void }) {
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
