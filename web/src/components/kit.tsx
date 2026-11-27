import { Children, Fragment, useEffect, useState, type ReactElement, type ReactNode } from "react";
import { useClickable } from "@/components/common";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("overflow-hidden rounded-xl border bg-card shadow-xs", className)}>{children}</div>;
}

export function Rows({ children, limit }: { children: ReactNode; limit?: number }) {
  const [all, setAll] = useState(false);
  const rows = Children.toArray(children);
  return <Panel><div className="divide-y">{limit && !all ? rows.slice(0, limit) : children}</div>{limit && rows.length > limit && <Button variant="ghost" size="sm" className="m-2" onClick={() => setAll(!all)}>{all ? "收起" : `查看全部（${rows.length}）`}</Button>}</Panel>;
}

export function Row({ to, onClick, className, children }: { to?: string; onClick?: () => void; className?: string; children: ReactNode }) {
  const clickable = useClickable();
  const button = onClick && {
    role: "button",
    tabIndex: 0,
    onClick: (e: React.MouseEvent) => {
      if (window.getSelection()?.toString() || (e.target as HTMLElement).closest("a,button,input,label,[role=menuitem]")) return;
      onClick();
    },
    onKeyDown: (e: React.KeyboardEvent) => {
      if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) { e.preventDefault(); onClick(); }
    },
  };
  return (
    <div
      className={cn("flex flex-wrap items-center gap-3 px-4 py-3 text-sm", (to || onClick) && "cursor-pointer hover:bg-accent/50", className)}
      {...(to ? clickable({ to }) : button || {})}
    >
      {children}
    </div>
  );
}

export function Facts({ items, className }: { items: [ReactNode, ReactNode | null | undefined | false][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[96px_minmax(0,1fr)] gap-x-4 gap-y-2.5 text-sm", className)}>
      {items.filter(([, v]) => v !== null && v !== undefined && v !== false && v !== "").map(([k, v], i) => (
        <Fragment key={i}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd>{v}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function Tip({ text, children }: { text: ReactNode; children: ReactElement }) {
  if (!text) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  );
}

export function ConfirmDialog({ open, title, children, confirmText = "删除", danger = true, typed, busy, onConfirm, onCancel }: {
  open: boolean;
  title: string;
  children?: ReactNode;
  confirmText?: string;
  danger?: boolean;
  typed?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState("");
  useEffect(() => { if (open) setValue(""); }, [open]);
  return (
    <AlertDialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          {children && <AlertDialogDescription asChild><div>{children}</div></AlertDialogDescription>}
        </AlertDialogHeader>
        {typed && (
          <>
            <div className="text-sm text-muted-foreground">输入 <code className="font-mono text-foreground">{typed}</code> 确认</div>
            <Input autoFocus className="font-mono" value={value} onChange={(e) => setValue(e.target.value)} />
          </>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel variant="ghost">取消</AlertDialogCancel>
          <Button variant={danger ? "destructive" : "default"} disabled={busy || (!!typed && value.trim() !== typed)} onClick={onConfirm}>
            {busy ? "处理中…" : confirmText}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function SaveBar({ changed, onReset, onSubmit, submitText = "预览改动", disabled }: {
  changed: string[];
  onReset: () => void;
  onSubmit: () => void;
  submitText?: string;
  disabled?: string;
}) {
  if (!changed.length) return null;
  return (
    <div className="sticky bottom-4 z-10 mt-6 flex flex-wrap items-center gap-3 rounded-xl border bg-card px-4 py-3 shadow-md">
      <span className="mr-auto text-sm">改了：{changed.join("、")}</span>
      {disabled && <span className="text-sm text-muted-foreground">{disabled}</span>}
      <Button variant="ghost" onClick={onReset}>放弃</Button>
      <Button disabled={!!disabled} onClick={onSubmit}>{submitText}</Button>
    </div>
  );
}

const norm = (v: unknown) => v === undefined || v === "" || (Array.isArray(v) && !v.length) || (v && typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length) ? null : v;

const sameField = (a: unknown, b: unknown) => JSON.stringify(norm(a)) === JSON.stringify(norm(b));

function draftPatch<T extends object>(base: T, edits: Partial<T>): Partial<T> {
  const patch = { ...edits };
  for (const key of Object.keys(patch) as (keyof T)[]) {
    if (sameField(patch[key], base[key])) delete patch[key];
  }
  return patch;
}

export function useDraft<T extends object>(current: T) {
  const [edits, setEdits] = useState<Partial<T>>({});
  useEffect(() => {
    setEdits((prev) => {
      const next = draftPatch(current, prev);
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
  }, [current]);
  const patch = draftPatch(current, edits);
  return {
    draft: { ...current, ...patch },
    set: (next: Partial<T>) => setEdits((prev) => draftPatch(current, { ...prev, ...next })),
    reset: () => setEdits({}),
    dirty: (keys: (keyof T)[]) => keys.some((key) => Object.hasOwn(patch, key)),
    mergeInto: (base: T): T => ({ ...base, ...patch }),
  };
}
