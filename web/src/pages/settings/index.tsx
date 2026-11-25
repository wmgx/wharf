import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Accounts } from "./accounts";
import { AppAccounts } from "./app-accounts";
import { Core } from "./core";
import { ExternalServices } from "./external-status";
import { Secrets } from "./secrets";
import { Security } from "./security";
import { ShareDomains } from "./share-domains";
import { Tokens } from "./tokens";

const TABS = ["accounts", "secrets", "app-accounts", "tokens", "security", "core"] as const;

export function Settings() {
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useTab(TABS, "accounts");
  useEffect(() => { if (params.get("tab") === "backup") { const next = new URLSearchParams(params); next.set("tab", "core"); setParams(next, { replace: true }); } }, [params, setParams]);
  return <>
    <PageHeader title="设置" />
    <Tabs value={tab} onValueChange={(v) => setTab(v as typeof TABS[number])}>
      <TabsList className="max-sm:grid max-sm:h-auto! max-sm:w-full max-sm:grid-cols-3 max-sm:overflow-visible max-sm:[&>button]:h-auto">
        <TabsTrigger value="accounts">厂商账号</TabsTrigger>
        <TabsTrigger value="secrets">密钥</TabsTrigger>
        <TabsTrigger value="app-accounts">应用账号</TabsTrigger>
        <TabsTrigger value="tokens">访问令牌</TabsTrigger>
        <TabsTrigger value="security">登录与安全</TabsTrigger>
        <TabsTrigger value="core">控制面</TabsTrigger>
      </TabsList>
      <TabsContent value="accounts" className="mt-4">
        <Accounts />
        <ExternalServices />
        <ShareDomains />
      </TabsContent>
      <TabsContent value="secrets" className="mt-4">
        <Secrets />
      </TabsContent>
      <TabsContent value="app-accounts" className="mt-4">
        <AppAccounts selected={params.get("account")} hostname={params.get("hostname")} />
      </TabsContent>
      <TabsContent value="tokens" className="mt-4">
        <Tokens />
      </TabsContent>
      <TabsContent value="security" className="mt-4"><Security /></TabsContent>
      <TabsContent value="core" className="mt-4">
        <Core />
      </TabsContent>
    </Tabs>
  </>;
}
