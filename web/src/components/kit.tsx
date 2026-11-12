import { Fragment, useEffect, useRef, useState, type ReactElement, type ReactNode } from "react";
import { useClickable } from "@/components/common";
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("overflow-hidden rounded-xl border bg-card shadow-xs", className)}>{children}</div>;
}

export function Rows({ children }: { children: ReactNode }) {
  return <Panel><div className="divide-y">{children}</div></Panel>;
}

export function Row({ to, onClick, className, children }: { to?: string; onClick?: () => void; className?: string; children: ReactNode }) {
  const clickable = useClickable();
  const button = onClick && {
    role: "button",
    tabIndex: 0,
    onClick,
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && e.target === e.currentTarget) onClick();
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

export function useDraft<T>(current: T): {
  draft: T;
  set: (patch: Partial<T>) => void;
  reset: () => void;
  dirty: (keys: (keyof T)[]) => boolean;
} {
  const [draft, setDraft] = useState(current);
  const previous = useRef(current);
  useEffect(() => {
    const prev = previous.current;
    setDraft((d) => JSON.stringify(d) === JSON.stringify(prev) ? current : d);
    previous.current = current;
  }, [current]);
  return {
    draft,
    set: (patch) => setDraft((d) => ({ ...d, ...patch })),
    reset: () => setDraft(current),
    dirty: (keys) => keys.some((k) => JSON.stringify(norm(draft[k])) !== JSON.stringify(norm(current[k]))),
  };
}
