import { lazy, Suspense } from "react";
import { PageHeader } from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { Data } from "./Data";
import { GatewaysPanel } from "./Gateways";
import { NetworkPanel } from "./Network";

// 拓扑图依赖的 @xyflow/react 比较大，只在打开网络页时加载。
const Topology = lazy(() => import("./Topology").then((m) => ({ default: m.Topology })));

/** 入口：域名从哪进来，以及每个入口上挂的域名。 */
export function Entries() {
  return (
    <>
      <PageHeader title="入口" description="域名从哪进来：有公网 IP 的机器直连，或 Cloudflare 隧道" />
      <GatewaysPanel />
    </>
  );
}

/** 网络：机器之间怎么连，以及入口、服务器、服务的连接图。 */
export function NetworkPage() {
  return (
    <>
      <PageHeader title="网络" description="机器之间怎么连：Tailscale、内网地址" />
      <NetworkPanel />
      <h2 className="mt-10 mb-3 font-medium">拓扑</h2>
      <Suspense fallback={<Skeleton className="h-[480px] rounded-xl" />}>
        <Topology />
      </Suspense>
    </>
  );
}

export function DataPage() {
  return (
    <>
      <PageHeader title="数据与备份" description="每个服务的数据目录和备份" />
      <Data />
    </>
  );
}
