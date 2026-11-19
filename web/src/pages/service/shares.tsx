import { useState } from "react";
import { AccessProtection } from "@/components/access-protection";
import { SectionTitle } from "@/components/common";
import { ShareDialog } from "@/components/share-dialog";
import { ShareList } from "@/components/share-list";
import { Button } from "@/components/ui/button";
import type { RouteView } from "@/types";

/** 服务的临时分享：新建、续期、改访问保护、停止；已失效的也在这里，可以续期或删除。 */
export function SharesTab({ service, shares }: { service: string; shares: RouteView[] }) {
  const [sharing, setSharing] = useState(false);
  const [protecting, setProtecting] = useState<RouteView | null>(null);
  return <div>
    {protecting && <AccessProtection route={protecting} onClose={() => setProtecting(null)} />}
    <ShareDialog service={service} open={sharing} onClose={() => setSharing(false)} />
    <SectionTitle count={shares.length} action={<Button variant="outline" size="sm" onClick={() => setSharing(true)}>新建分享</Button>}>临时分享</SectionTitle>
    <ShareList routes={shares} empty="还没有分享。新建一个随机地址给别人临时访问，到期自动失效" onProtect={setProtecting} />
  </div>;
}
