import { Tip } from "@/components/kit";
import { Dot, ago } from "@/components/common";
import type { ProbeView } from "@/types";

/** 域名行只显示状态，探测原文留在悬停提示中。 */
export function Probe({ probe }: { probe?: ProbeView }) {
  if (!probe) return null;
  const tone = probe.ok ? "ok" : probe.fails >= 3 ? "bad" : "warn";
  const text = probe.ok
    ? probe.detail
    : `${probe.detail}${probe.fails > 1 ? `（连续 ${probe.fails} 次）` : ""}`;
  const cert =
    probe.cert_days === undefined ? "" : ` · 证书剩 ${probe.cert_days} 天`;
  return (
    <Tip text={<span className="block max-w-[min(28rem,calc(100vw-2rem))] break-words">{`${ago(new Date(probe.at).toISOString())}探测：${text}${cert}`}</span>}><span className="inline-flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
      <Dot tone={tone} />
      <span className={probe.fails >= 3 && !probe.ok ? "text-destructive" : undefined}>
        {probe.ok ? "能打开" : "打不开"}
      </span>
    </span></Tip>
  );
}
