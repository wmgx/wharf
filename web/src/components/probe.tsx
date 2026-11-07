import { Dot, ago } from "@/components/common";
import type { ProbeView } from "@/types";

/** 域名探测结果：圆点加悬停说明；连续失败时显示文字。 */
export function Probe({ probe }: { probe?: ProbeView }) {
  if (!probe) return null;
  const tone = probe.ok ? "ok" : probe.fails >= 3 ? "bad" : "warn";
  const text = probe.ok
    ? `${probe.detail} · ${probe.ms} ms`
    : `${probe.detail}${probe.fails > 1 ? `（连续 ${probe.fails} 次）` : ""}`;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 text-xs text-muted-foreground"
      title={`${ago(new Date(probe.at).toISOString())}探测：${text}`}
    >
      <Dot tone={tone} />
      {!probe.ok && (
        <span className={probe.fails >= 3 ? "text-destructive" : ""}>
          {text}
        </span>
      )}
    </span>
  );
}
