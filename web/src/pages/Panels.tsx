import { lazy, Suspense } from "react";
import { PageHeader, SectionTitle } from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { Data } from "./Data";
import { NetworkPanel } from "./Network";

// 拓扑图依赖的 @xyflow/react 比较大，只在打开网络页时加载。
const Topology = lazy(() => import("./Topology").then((m) => ({ default: m.Topology })));

/** 网络：机器之间怎么连，以及入口、服务器、服务的连接图。 */
export function NetworkPage() {
  return (
    <>
      <PageHeader title="网络" />
      <NetworkPanel />
      <SectionTitle>拓扑</SectionTitle>
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
