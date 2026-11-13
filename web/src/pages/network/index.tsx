import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { CardsSkeleton, ErrorNote, PageHeader } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useStatus } from "@/status";
import type { NetworkView } from "@/types";
import { Egress } from "./egress";
import { LinkSheet } from "./link-sheet";
import { Machines } from "./machines";
import { Paths } from "./paths";

const Topology = lazy(() => import("./topology").then((m) => ({ default: m.Topology })));
const TABS = ["machines", "paths", "egress", "map"] as const;

export function NetworkPage() {
  const { status } = useStatus();
  const { data: net, error, refresh } = usePoll<NetworkView>("/api/network", 30000);
  const [params, setParams] = useSearchParams();
  const [tab] = useTab(TABS, "machines");
  const [a, b] = (params.get("link") ?? "").split("~");
  const close = () => { const next = new URLSearchParams(params); next.delete("link"); setParams(next); };
  return <>
    <PageHeader title="网络" />
    <ErrorNote error={error} />
    <Tabs value={tab} onValueChange={(v) => { const next = new URLSearchParams(params); if (v === "machines") next.delete("tab"); else next.set("tab", v); setParams(next); }}>
      <TabsList>
        <TabsTrigger value="machines">机器</TabsTrigger>
        <TabsTrigger value="paths">路径</TabsTrigger>
        <TabsTrigger value="egress">出口</TabsTrigger>
        <TabsTrigger value="map">拓扑</TabsTrigger>
      </TabsList>
      <TabsContent value="machines" className="mt-4">
        {net ? <Machines net={net} refresh={refresh} /> : <CardsSkeleton />}
      </TabsContent>
      <TabsContent value="paths" className="mt-4">
        {net && status ? <Paths net={net} status={status} /> : <CardsSkeleton />}
      </TabsContent>
      <TabsContent value="egress" className="mt-4">
        {status ? <Egress status={status} /> : <CardsSkeleton />}
      </TabsContent>
      <TabsContent value="map" className="mt-4">
        <Suspense fallback={<CardsSkeleton />}>
          <Topology />
        </Suspense>
      </TabsContent>
    </Tabs>
    {a && b && net && status && <LinkSheet key={`${a}~${b}`} a={a} b={b} net={net} status={status} onClose={close} />}
  </>;
}
