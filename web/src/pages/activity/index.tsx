import { PageHeader } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AuditLog } from "./audit";
import { Runs } from "./runs";
import { Shell } from "./shell";

const TABS = ["runs", "audit", "shell"] as const;

export function Activity() {
  const [tab, setTab] = useTab(TABS, "runs");
  return <>
    <PageHeader title="活动" />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList className="mb-4">
        <TabsTrigger value="runs">执行</TabsTrigger>
        <TabsTrigger value="audit">操作记录</TabsTrigger>
        <TabsTrigger value="shell">宿主机命令</TabsTrigger>
      </TabsList>
      <TabsContent value="runs">
        {tab === "runs" && <Runs />}
      </TabsContent>
      <TabsContent value="audit">
        {tab === "audit" && <AuditLog />}
      </TabsContent>
      <TabsContent value="shell">
        {tab === "shell" && <Shell />}
      </TabsContent>
    </Tabs>
  </>;
}
