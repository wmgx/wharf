import { CopyIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, CodeBlock, Empty, ErrorNote, Notice, SectionTitle } from "@/components/common";
import { Field, Segmented, toName } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CreatedToken, TokenScope, TokenView } from "@/types";

const SCOPES: [TokenScope, string][] = [
  ["read", "只读"],
  ["plan", "出计划"],
  ["apply_safe", "执行安全项"],
  ["apply_all", "全部"],
];
const SCOPE_LABEL = Object.fromEntries(SCOPES) as Record<TokenScope, string>;

/** API token：CLI 和 AI 用。新建后只显示一次。 */
export function Tokens() {
  const { data, error, refresh } = usePoll<TokenView[]>("/api/tokens", 30000);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  const remove = async (name: string) => {
    setRemoving(null);
    try {
      await api.del(`/api/tokens/${encodeURIComponent(name)}`);
      toast.success(`已删除 token ${name}`);
      refresh();
    } catch (e) {
      toast.error(`不能删除 ${name}`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <div className="flex items-center justify-between">
        <SectionTitle count={data?.length}>API token</SectionTitle>
        <Button variant="ghost" size="sm" onClick={() => setCreating(true)}>
          <PlusIcon />
          新建
        </Button>
      </div>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>还没有 token</Empty>
      ) : (
        data && (
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>权限</TableHead>
                  <TableHead>最近使用</TableHead>
                  <TableHead>创建</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="font-mono text-xs">{t.name}</TableCell>
                    <TableCell>
                      <Badge variant={t.scope === "apply_all" ? "default" : "secondary"}>{SCOPE_LABEL[t.scope]}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{t.last_used_at ? ago(t.last_used_at) : "没用过"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ago(t.created_at)}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="xs" className="text-destructive" onClick={() => setRemoving(t.name)}>
                        <Trash2Icon />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )
      )}
      {creating && (
        <CreateToken
          taken={(data ?? []).map((t) => t.name)}
          onClose={() => {
            setCreating(false);
            refresh();
          }}
        />
      )}
      <Dialog open={!!removing} onOpenChange={(o) => !o && setRemoving(null)}>
        <DialogContent aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>删除 token {removing}？</DialogTitle>
          </DialogHeader>
          <Notice kind="warn">用它的 CLI 和 AI 会立刻失去权限</Notice>
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

/** 只在打开时挂载：关掉后新 token 就再也看不到了。 */
function CreateToken({ taken, onClose }: { taken: string[]; onClose: () => void }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<TokenScope>("apply_safe");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const create = async () => {
    setSaving(true);
    setError(null);
    try {
      setCreated(await api.post<CreatedToken>("/api/tokens", { name, scope }));
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  const copy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      toast.success("已复制");
    } catch {
      toast.error("复制失败，手动选中复制");
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>{created ? `token ${created.name}` : "新建 API token"}</DialogTitle>
        </DialogHeader>
        {created ? (
          <div className="grid gap-3">
            <CodeBlock className="break-all whitespace-pre-wrap select-all">{created.token}</CodeBlock>
            <Notice kind="warn">只显示这一次</Notice>
          </div>
        ) : (
          <div className="grid gap-4">
            <Field label="名称" htmlFor="token-name">
              <Input id="token-name" value={name} onChange={(e) => setName(toName(e.target.value))} placeholder="laptop" />
            </Field>
            <Field label="权限">
              <Segmented value={scope} options={SCOPES} onChange={setScope} />
            </Field>
            {name && taken.includes(name) && <Notice kind="warn">已有同名 token</Notice>}
            <ErrorNote error={error} />
          </div>
        )}
        <DialogFooter>
          {created ? (
            <>
              <Button variant="ghost" onClick={onClose}>
                关闭
              </Button>
              <Button onClick={copy}>
                <CopyIcon />
                复制
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" onClick={onClose}>
                取消
              </Button>
              <Button disabled={!name || taken.includes(name) || saving} onClick={create}>
                {saving ? "创建中…" : "创建"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
