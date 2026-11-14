import { ArrowDownIcon, ArrowUpIcon, PlusIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { ConfirmDialog, Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { BookmarkSpec, BookmarkView, Change } from "@/types";

export function bookmarkGroups(bookmarks: BookmarkView[]) {
  const groups = new Map<string, BookmarkView[]>();
  for (const b of [...bookmarks].sort((a, b) => a.spec.order - b.spec.order || a.spec.title.localeCompare(b.spec.title))) {
    const name = b.spec.group ?? "书签";
    groups.set(name, [...(groups.get(name) ?? []), b]);
  }
  return [...groups].sort(([a, x], [b, y]) => x[0].spec.order - y[0].spec.order || a.localeCompare(b));
}

export function HomeBookmarks({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { status, refresh } = useStatus();
  const actions = useActions();
  const bookmarks = status?.bookmarks ?? [];
  const groups = bookmarkGroups(bookmarks);
  const [editing, setEditing] = useState<{ id?: string; spec: BookmarkSpec }>();
  const [removing, setRemoving] = useState<BookmarkView>();
  const [busy, setBusy] = useState(false);
  let validUrl = !!editing && /^https?:\/\//.test(editing.spec.url) && editing.spec.url.length <= 2048 && !/\s/.test(editing.spec.url);
  if (editing && validUrl) {
    try { new URL(editing.spec.url); } catch { validUrl = false; }
  }
  const patch = (spec: Partial<BookmarkSpec>) => setEditing((b) => b && { ...b, spec: { ...b.spec, ...spec } });
  const save = async (title: string, changes: Change[]) => {
    setBusy(true);
    try {
      const plan = await api.plan(changes);
      if (plan.items.length) {
        if (!plan.items.every((item) => item.address.startsWith("bookmark/"))) {
          setEditing(undefined);
          setRemoving(undefined);
          onClose();
          actions.plan({ title: `保存书签 ${title}`, changes });
          return false;
        }
        await api.apply(plan.plan_id, []);
      }
      await refresh();
      toast.success(`已保存书签 ${title}`);
      return true;
    } catch (e) {
      toast.error(`不能保存书签 ${title}`, { description: (e as Error).message });
      return false;
    } finally { setBusy(false); }
  };
  const move = (items: BookmarkView[], index: number, direction: number) => {
    const duplicates = new Set(items.map((b) => b.spec.order)).size !== items.length;
    const rows = items.map((b, i) => ({ ...b, spec: { ...b.spec, order: duplicates ? (i + 1) * 10 : b.spec.order } }));
    const other = index + direction;
    [rows[index].spec.order, rows[other].spec.order] = [rows[other].spec.order, rows[index].spec.order];
    const changes: Change[] = rows.filter((b, i) => b.spec.order !== items[i].spec.order).map(({ id, spec }) => ({ op: "upsert_bookmark", id, spec }));
    void save(items[index].spec.title, changes);
  };
  return <>
    <Sheet open={open} onOpenChange={(v) => { if (!v && !busy) onClose(); }}>
      <SheetContent className="w-full sm:max-w-xl">
        <SheetHeader><SheetTitle>管理书签</SheetTitle></SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
          <Button disabled={busy} onClick={() => setEditing({ spec: { title: "", url: "", order: 0 } })}><PlusIcon />加书签</Button>
          {groups.map(([name, items]) => <section key={name}>
            <SectionTitle>{name}</SectionTitle>
            <Panel>
              <div className="divide-y">{items.map((b, i) => <div key={b.id} className="flex flex-wrap items-center gap-2 p-3 text-sm">
                <div className="min-w-0 flex-1 basis-36"><div className="truncate font-medium">{b.spec.title}</div><div className="truncate font-mono text-xs text-muted-foreground">{b.spec.url}</div><div className="text-xs text-muted-foreground">{b.spec.group ?? "书签"}</div></div>
                <div className="flex shrink-0 items-center gap-1">
                  <Tip text="上移"><Button size="icon-sm" variant="ghost" aria-label={`上移 ${b.spec.title}`} disabled={busy || i === 0} onClick={() => move(items, i, -1)}><ArrowUpIcon /></Button></Tip>
                  <Tip text="下移"><Button size="icon-sm" variant="ghost" aria-label={`下移 ${b.spec.title}`} disabled={busy || i === items.length - 1} onClick={() => move(items, i, 1)}><ArrowDownIcon /></Button></Tip>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => setEditing({ id: b.id, spec: { ...b.spec } })}>编辑</Button>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => setRemoving(b)}>删除</Button>
                </div>
              </div>)}</div>
            </Panel>
          </section>)}
        </div>
      </SheetContent>
    </Sheet>
    <Dialog open={!!editing} onOpenChange={(v) => { if (!v && !busy) setEditing(undefined); }}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>{editing?.id ? "编辑书签" : "加书签"}</DialogTitle></DialogHeader>
        {editing && <form className="grid gap-4" onSubmit={async (e) => { e.preventDefault(); if (await save(editing.spec.title, [{ op: "upsert_bookmark", ...editing }])) setEditing(undefined); }}>
          <Field label="标题" htmlFor="bookmark-title"><Input id="bookmark-title" value={editing.spec.title} disabled={busy} onChange={(e) => patch({ title: e.target.value })} /></Field>
          <Field label="网址" htmlFor="bookmark-url"><Input id="bookmark-url" value={editing.spec.url} disabled={busy} onChange={(e) => patch({ url: e.target.value })} />{!validUrl && <p className="text-xs text-destructive">要以 http:// 或 https:// 开头</p>}</Field>
          <Field label="分组" htmlFor="bookmark-group"><Input id="bookmark-group" list="bookmark-groups" value={editing.spec.group ?? ""} disabled={busy} onChange={(e) => patch({ group: e.target.value || undefined })} /><datalist id="bookmark-groups">{[...new Set(bookmarks.flatMap((b) => b.spec.group ? [b.spec.group] : []))].map((g) => <option key={g} value={g} />)}</datalist></Field>
          <DialogFooter><Button type="submit" disabled={busy || !validUrl || !editing.spec.title.trim()}>{busy ? "保存中…" : "保存"}</Button></DialogFooter>
        </form>}
      </DialogContent>
    </Dialog>
    <ConfirmDialog open={!!removing} title={`删除书签 ${removing?.spec.title}？`} busy={busy} onCancel={() => { if (!busy) setRemoving(undefined); }} onConfirm={async () => { if (removing && await save(removing.spec.title, [{ op: "remove_bookmark", id: removing.id }])) setRemoving(undefined); }}>只删这条书签，不影响那个网址本身。</ConfirmDialog>
  </>;
}
