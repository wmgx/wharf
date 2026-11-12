import { PageHeader } from "@/components/common";
import { issueCount, useIssues } from "@/components/issues";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Notify } from "./channels";
import { History } from "./history";
import { Open } from "./open";
import { Rules } from "./rules";

const TABS = ["open", "rules", "channels", "history"] as const;
export function InboxPage() {
  const [tab, setTab] = useTab(TABS, "open");
  const issues = useIssues();
  return <>
    <PageHeader title="待处理" count={issueCount(issues)} />
    <Tabs value={tab} onValueChange={(value) => setTab(value as (typeof TABS)[number])}>
      <TabsList className="max-w-full justify-start overflow-x-auto"><TabsTrigger value="open">待处理</TabsTrigger><TabsTrigger value="rules">告警规则</TabsTrigger><TabsTrigger value="channels">通知渠道</TabsTrigger><TabsTrigger value="history">推送记录</TabsTrigger></TabsList>
      <TabsContent value="open">{tab === "open" && <Open />}</TabsContent>
      <TabsContent value="rules">{tab === "rules" && <Rules />}</TabsContent>
      <TabsContent value="channels">{tab === "channels" && <Notify />}</TabsContent>
      <TabsContent value="history">{tab === "history" && <History />}</TabsContent>
    </Tabs>
  </>;
}
