import { usePoll } from "@/api";
import { SectionTitle } from "@/components/common";
import type { NetworkView } from "@/types";
import { Quality } from "./Network";

/** 服务器"网络"标签顶部：这台到其他机器、其他机器到这台的延迟和丢包。 */
export function ServerLinks({ server }: { server: string }) {
  const { data } = usePoll<NetworkView>("/api/network", 30000);
  const others = (data?.servers ?? []).map((s) => s.name).filter((n) => n !== server);
  const find = (from: string, to: string) => data?.links?.find((l) => l.from === from && l.to === to);
  const relays = (data?.relays ?? []).filter((h) => h.from === server || h.to === server);
  if (!others.length) return null;
  return (
    <div className="mb-6">
      <SectionTitle>链路</SectionTitle>
      <div className="grid max-w-2xl grid-cols-[auto_1fr_1fr] gap-x-6 gap-y-1.5 text-sm">
        <span />
        <span className="text-xs text-muted-foreground">{server} → 它</span>
        <span className="text-xs text-muted-foreground">它 → {server}</span>
        {others.map((o) => (
          <div key={o} className="contents">
            <span>{o}</span>
            <Quality l={find(server, o)} />
            <Quality l={find(o, server)} />
          </div>
        ))}
      </div>
      {relays.map((h) => (
        <p key={`${h.from}>${h.to}`} className="mt-2 text-xs text-warning">
          {h.from} → {h.to} 直连丢包 {h.direct_loss.toFixed(0)}%，经 {h.via} 中转约 {h.via_loss.toFixed(0)}%
        </p>
      ))}
    </div>
  );
}
