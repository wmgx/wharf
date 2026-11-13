import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Accounts } from "./accounts";
import { Core } from "./core";
import { Secrets } from "./secrets";
import { Tokens } from "./tokens";

const TABS = ["accounts", "secrets", "tokens", "core"] as const;

export function Settings() {
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useTab(TABS, "accounts");
  useEffect(() => { if (params.get("tab") === "backup") { const next = new URLSearchParams(params); next.set("tab", "core"); setParams(next, { replace: true }); } }, [params, setParams]);
  return <>
    <PageHeader title="设置" />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList className="max-w-full overflow-x-auto">
        <TabsTrigger value="accounts">厂商账号</TabsTrigger>
        <TabsTrigger value="secrets">密钥</TabsTrigger>
        <TabsTrigger value="tokens">访问令牌</TabsTrigger>
        <TabsTrigger value="core">控制面</TabsTrigger>
      </TabsList>
      <TabsContent value="accounts" className="mt-4">
        <Accounts />
      </TabsContent>
      <TabsContent value="secrets" className="mt-4">
        <Secrets />
      </TabsContent>
      <TabsContent value="tokens" className="mt-4">
        <Tokens />
      </TabsContent>
      <TabsContent value="core" className="mt-4">
        <Core />
      </TabsContent>
    </Tabs>
  </>;
}
