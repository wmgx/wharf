import { useEffect, useState, type ReactNode } from "react";
import { ApiError } from "../api";
import type { LiveState, ServiceView } from "../types";

export type Tone = "go" | "signal" | "stop" | "fog";

/** 现状 → 信号灯颜色和文字。 */
export function liveTone(live?: LiveState | null): { tone: Tone; text: string } {
  if (!live) return { tone: "fog", text: "未知" };
  switch (live.state) {
    case "running":
      return live.in_sync === false ? { tone: "signal", text: "运行中 · 和配置不一致" } : { tone: "go", text: "运行中" };
    case "partial":
      return { tone: "signal", text: "部分运行" };
    case "stopped":
      return { tone: "stop", text: "已停止" };
    case "missing":
      return { tone: "stop", text: "未部署" };
    default:
      return { tone: "fog", text: live.error ? "查不到现状" : "未知" };
  }
}

export function crateClass(tone: Tone) {
  return tone === "go" ? "ok" : tone === "signal" ? "warn" : tone === "stop" ? "bad" : "";
}

export function Light({ tone, title }: { tone: Tone; title?: string }) {
  return <span className={`light ${tone === "fog" ? "" : tone}`} title={title} />;
}

export function imageOf(s: ServiceView): string {
  return "image" in s.spec.source ? s.spec.source.image : "compose";
}

/** 服务图标：先试站点的 favicon，失败就用首字母。 */
export function Mark({ name, url }: { name: string; url?: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [url]);
  const letter = name.replace(/[^a-z0-9]/gi, "").slice(0, 1) || "?";
  return (
    <span className="mark">
      {url && !failed ? (
        <img src={new URL("/favicon.ico", url).toString()} alt="" onError={() => setFailed(true)} />
      ) : (
        letter
      )}
    </span>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const body =
    error instanceof ApiError ? error.body : { message: String((error as Error)?.message ?? error), hint: undefined, suggest: [] };
  return (
    <div className="note bad">
      {body.message}
      {body.hint && <div style={{ color: "var(--ink-2)", marginTop: 4 }}>{body.hint}</div>}
      {body.suggest?.map((s) => (
        <code className="cmd" key={s}>
          $ {s}
        </code>
      ))}
    </div>
  );
}

export function Drawer({
  title,
  zh,
  onClose,
  children,
  footer,
}: {
  title: string;
  zh?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={zh ?? title}>
        <header>
          <h3>
            {title}
            {zh && <span className="zh">{zh}</span>}
          </h3>
          <button className="x" onClick={onClose} aria-label="关闭">
            ×
          </button>
        </header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </aside>
    </>
  );
}

export function PageHead({ en, zh, sub, action }: { en: string; zh: string; sub?: ReactNode; action?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>
          {en}
          <span className="zh">{zh}</span>
        </h1>
        {sub && <p>{sub}</p>}
      </div>
      {action}
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
