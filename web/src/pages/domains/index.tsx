import { PlusIcon } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { AddRoute } from "@/components/add-route";
import { CardsSkeleton, PageHeader } from "@/components/common";
import { Tip } from "@/components/kit";
import { useTab } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useStatus } from "@/status";
import { DomainDetail } from "./detail";
import { Entries } from "./entries";
import { DomainList } from "./list";

const TABS = ["domains", "entries"] as const;

export function Domains() {
  const { status } = useStatus();
  const [tab, setTab] = useTab(TABS, "domains");
  const [params, setParams] = useSearchParams();
  const selected = status?.routes.find((r) => r.spec.hostname === params.get("open"));
  const available = !!status?.services.length;
  const add = <Button disabled={!available} onClick={() => setParams({ add: "1" })}>
    <PlusIcon />加域名</Button>;
  const action = available ? add : <Tip text="先部署一个服务">
    <span>
      {add}
    </span>
  </Tip>;
  const close = (key: string) => { const next = new URLSearchParams(params); next.delete(key); setParams(next); };
  return <>
    <PageHeader title="域名" count={status ? status.routes.length + (status.edge_apps ?? []).reduce((n, a) => n + (a.spec.domains?.length ?? 0), 0) : undefined} actions={tab === "domains" ? action : undefined} />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList>
        <TabsTrigger value="domains">域名</TabsTrigger>
        <TabsTrigger value="entries">入口</TabsTrigger>
      </TabsList>
      <TabsContent value="domains" className="mt-4">
        {status ? <DomainList status={status} add={action} /> : <CardsSkeleton />}
      </TabsContent>
      <TabsContent value="entries" className="mt-4">
        <Entries />
      </TabsContent>
    </Tabs>
    <Sheet open={!!selected} onOpenChange={(open) => !open && close("open")}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        {selected && status && <DomainDetail key={selected.id} route={selected} status={status} onClose={() => close("open")} />}
      </SheetContent>
    </Sheet>
    <AddRoute open={params.get("add") === "1"} onClose={() => close("add")} />
  </>;
}
