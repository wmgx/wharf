import { useEffect, useState, type ReactNode } from "react";
import { ApiError } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { LiveState, NetworkMode, ServerView, ServiceView, Source } from "@/types";

export type Tone = "ok" | "warn" | "bad" | "idle";

/** 现状 → 颜色和文字。 */
/** 服务状态：按配置停下的服务停着是正常的，不标红。 */
export function serviceTone(svc?: Pick<ServiceView, "spec" | "live" | "status">): { tone: Tone; text: string } {
  if (svc?.status) return { tone: svc.status.tone, text: svc.status.summary };
  if (svc?.spec.stopped) {
    return svc.live?.state === "stopped" ? { tone: "idle", text: "已停止" } : { tone: "warn", text: "应停止 · 还在运行" };
  }
  return liveTone(svc?.live);
}

export function liveTone(live?: LiveState | null): { tone: Tone; text: string } {
  if (!live) return { tone: "idle", text: "未知" };
  switch (live.state) {
    case "running":
      return live.in_sync === false ? { tone: "warn", text: "运行中 · 和配置不一致" } : { tone: "ok", text: "运行中" };
    case "partial":
      return { tone: "warn", text: "部分运行" };
    case "stopped":
      return { tone: "bad", text: "已停止" };
    case "missing":
      return { tone: "bad", text: "未部署" };
    default:
      return { tone: "idle", text: live.error ? "查不到现状" : "未知" };
  }
}

export function serverTone(s: ServerView): Tone {
  return !s.joined ? "idle" : s.online ? "ok" : "bad";
}

export function serverText(s: ServerView): string {
  if (!s.joined) return "未加入";
  if (!s.online) return "离线";
  return s.rtt_ms != null ? `${s.rtt_ms} ms` : "在线";
}

/** 接入方式的显示名。 */
export const MODES: Record<NetworkMode, string> = { tailscale: "Tailscale", lan: "局域网", public: "公网" };

const GB = 1024 ** 3;

/** 磁盘余量，例如 `12.3G / 40G`；剩余不到 10% 或 5G 时 `low`。 */
export function diskText(s: ServerView): { text: string; low: boolean } | null {
  const d = s.report?.disk;
  if (!d) return null;
  const g = (n: number) => `${(n / GB).toFixed(n < 10 * GB ? 1 : 0)}G`;
  return { text: `${g(d.free)} / ${g(d.total)}`, low: d.free < d.total / 10 || d.free < 5 * GB };
}

const DOT: Record<Tone, string> = {
  ok: "bg-success",
  warn: "bg-warning",
  bad: "bg-destructive",
  idle: "bg-muted-foreground/40",
};

export function Dot({ tone, className }: { tone: Tone; className?: string }) {
  return <span className={cn("inline-block size-2 shrink-0 rounded-full", DOT[tone], className)} />;
}

const BADGE: Record<Tone, string> = {
  ok: "bg-success/10 text-success",
  warn: "bg-warning/10 text-warning",
  bad: "bg-destructive/10 text-destructive",
  idle: "bg-muted text-muted-foreground",
};

export function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <Badge variant="outline" className={cn("gap-1.5 border-transparent font-medium", BADGE[tone])}>
      <Dot tone={tone} className="size-1.5" />
      {children}
    </Badge>
  );
}

/** 服务器名：等宽小标签。 */
export function ServerTag({ name }: { name: string }) {
  return (
    <Badge variant="outline" className="font-mono text-[11px] font-normal text-muted-foreground">
      {name}
    </Badge>
  );
}

export function imageOf(s: ServiceView): string {
  return sourceLabel(s.spec.source, "compose");
}

/** 来源的一行说明：镜像名、git 仓库@分支，或本机代码。 */
export function sourceLabel(source: Source, compose = "compose 文件"): string {
  if ("image" in source) return source.image;
  if ("compose" in source) return compose;
  const { git, upload, path } = source.build;
  const sub = path ? ` /${path}` : "";
  if (git) return `${git.repo.replace(/^https:\/\//, "")}@${git.ref}${sub}`;
  return `本机代码 ${upload?.slice(0, 12) ?? ""}${sub}`;
}

/** 服务图标：先试站点的 favicon，失败就用首字母。 */
export function Mark({ name, url, className }: { name: string; url?: string; className?: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [url]);
  const letter = name.replace(/[^a-z0-9]/gi, "").slice(0, 1).toUpperCase() || "?";
  return (
    <span
      className={cn(
        "grid size-9 shrink-0 place-items-center overflow-hidden rounded-lg border bg-muted text-sm font-semibold text-muted-foreground",
        className,
      )}
    >
      {url && !failed ? (
        <img className="size-5 object-contain" src={new URL("/favicon.ico", url).toString()} alt="" onError={() => setFailed(true)} />
      ) : (
        letter
      )}
    </span>
  );
}

type Note = "info" | "warn" | "bad" | "ok";

const NOTE: Record<Note, string> = {
  info: "border-border bg-muted/50",
  warn: "border-warning/30 bg-warning/10",
  bad: "border-destructive/30 bg-destructive/10 text-destructive",
  ok: "border-success/30 bg-success/10 text-success",
};

export function Notice({ kind = "info", children, className }: { kind?: Note; children: ReactNode; className?: string }) {
  return <div className={cn("rounded-md border px-3 py-2.5 text-sm", NOTE[kind], className)}>{children}</div>;
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const body =
    error instanceof ApiError ? error.body : { message: String((error as Error)?.message ?? error), hint: undefined, suggest: [] };
  return (
    <Notice kind="bad">
      {body.message}
      {body.hint && <div className="mt-1 text-foreground/70">{body.hint}</div>}
      {body.suggest?.map((s) => (
        <code className="mt-1.5 block font-mono text-xs text-foreground/70" key={s}>
          $ {s}
        </code>
      ))}
    </Notice>
  );
}

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="flex items-center gap-3 text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <div className="mt-1 text-sm text-muted-foreground">{description}</div>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function SectionTitle({ children, count }: { children: ReactNode; count?: number }) {
  return (
    <h2 className="mt-8 mb-3 flex items-baseline gap-2 text-sm font-medium text-muted-foreground first:mt-0">
      {children}
      {count != null && <span className="font-normal text-muted-foreground/70">{count}</span>}
    </h2>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed px-6 py-10 text-center text-sm text-muted-foreground">{children}</div>;
}

export function CodeBlock({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <pre className={cn("max-h-[460px] overflow-auto rounded-lg border bg-muted/40 p-4 font-mono text-xs leading-relaxed", className)}>
      {children}
    </pre>
  );
}

/** 卡片墙载入时的占位。 */
export function CardsSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-3">
      {Array.from({ length: count }, (_, i) => (
        <Skeleton key={i} className="h-[104px] rounded-xl" />
      ))}
    </div>
  );
}

export function ago(iso?: string): string {
  if (!iso) return "-";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "刚刚";
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return new Date(iso).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}
