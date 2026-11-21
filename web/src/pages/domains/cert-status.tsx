import { Loader2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { Facts, Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { CertStatus } from "@/types.gen";

const clock = (ms: number) => new Date(ms).toLocaleTimeString("zh-CN", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

function until(ms: number): string {
  const s = Math.round((ms - Date.now()) / 1000);
  if (s <= 0) return "马上";
  if (s < 60) return `${s} 秒后`;
  if (s < 3600) return `${Math.round(s / 60)} 分钟后`;
  return `${Math.round(s / 3600)} 小时后`;
}

function since(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return "刚刚";
  if (s < 3600) return `${Math.round(s / 60)} 分钟前`;
  return `${Math.round(s / 3600)} 小时前`;
}

const STATE = {
  ok: <span>已签好，下一轮检查（2 分钟内）后显示到期时间</span>,
  obtaining: <span className="inline-flex items-center gap-1.5"><Loader2Icon className="size-3.5 animate-spin" />申请中</span>,
  failed: <span className="text-destructive">申请失败，入口会自动重试</span>,
  unknown: <span className="text-muted-foreground">最近的日志里没有申请记录</span>,
};

/** 还没有有效证书时：申请进度、失败原因、下次自动重试的时间，以及立刻重新申请。 */
export function CertProgress({ hostname }: { hostname: string }) {
  const path = `/api/routes/${encodeURIComponent(hostname)}/cert`;
  const { data, error, refresh } = usePoll<CertStatus>(path, 15000);
  const [busy, setBusy] = useState(false);
  const [retryError, setRetryError] = useState<unknown>(null);
  const retry = async () => {
    setBusy(true); setRetryError(null);
    try {
      const r = await api.post<{ gateway: string }>(`${path}/retry`, {});
      toast.success(`已让入口 ${r.gateway} 重新申请证书`, { description: "一般 1 到 3 分钟" });
      refresh();
    } catch (e) { setRetryError(e); }
    finally { setBusy(false); }
  };
  const failed = data && data.state !== "ok" && data.attempts > 0;
  return <>
    <SectionTitle action={data && (data.state === "failed" || data.state === "unknown") && <Button variant="outline" size="xs" disabled={busy} onClick={retry}>重新申请</Button>}>证书</SectionTitle>
    <Panel className="grid gap-3 p-4 text-sm">
      <ErrorNote error={error ?? retryError} />
      {!data && !error && <span className="text-muted-foreground">读取中…</span>}
      {data && <Facts items={[
        ["状态", STATE[data.state]],
        ["开始申请", data.since != null && data.state !== "ok" && since(data.since)],
        ["上次失败", failed && data.failed_at != null && `${since(data.failed_at)}，已失败 ${data.attempts} 次`],
        ["原因", failed && (data.reason ?? "见下面的报错")],
        ["下次重试", data.state === "failed" && data.next_retry_at != null && `${clock(data.next_retry_at)}（${until(data.next_retry_at)}）`],
      ]} />}
      {failed && data.error && <details className="text-xs">
        <summary className="cursor-pointer text-muted-foreground">报错</summary>
        <pre className="mt-2 whitespace-pre-wrap break-all font-mono">{data.error}</pre>
      </details>}
    </Panel>
  </>;
}
