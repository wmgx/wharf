import { ArrowUpRightIcon, CloudIcon, LockIcon, PlusIcon, RadarIcon } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/api";
import { Lamps, diagnosisOf, routeTone } from "@/components/health";
import { useState } from "react";
import { Link } from "react-router-dom";
import { AddRoute } from "@/components/add-route";
import { CardsSkeleton, Empty, PageHeader, StatusBadge, ago, type Tone } from "@/components/common";
import { useTab } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useStatus } from "@/status";
import type { RouteDiagnosis, Status } from "@/types";
import { edgeTone } from "./edge";
import { GatewaysPanel } from "./Gateways";

const TABS = ["list", "entries"] as const;

/** 页面上的一行域名：代理路由和边缘应用的域名放在一起，人只关心网址。 */
interface Row {
  hostname: string;
  url: string;
  target: string;
  to: string;
  entry: string;
  auth: boolean;
  tone: Tone;
  text: string;
  detail?: string;
  diag?: RouteDiagnosis;
  edge?: boolean;
}

function rowsOf(status: Status): Row[] {
  const gateways = new Map(status.gateways.map((g) => [g.name, g]));
  const routes: Row[] = status.routes.map((r) => {
    const g = r.gateway ? gateways.get(r.gateway) : undefined;
    const diag = diagnosisOf(status, r.spec.hostname);
    const { tone, text, detail } = routeTone(diag);
    return {
      hostname: r.spec.hostname,
      url: r.url,
      target: r.spec.service ?? r.spec.upstream ?? "-",
      to: r.spec.service ? `/services/${r.spec.service}` : "",
      entry: !g ? "-" : g.spec.kind === "cloudflare_tunnel" ? "Cloudflare 隧道" : `${g.spec.server} 直连`,
      auth: !!r.spec.auth,
      tone,
      text,
      detail,
      diag,
    };
  });
  const edge: Row[] = (status.edge_apps ?? []).flatMap((a) =>
    (a.spec.domains ?? []).map((d) => {
      const { tone, text } = edgeTone(a.live, a.drift);
      return { hostname: d, url: `https://${d}`, target: a.name, to: `/edge/${a.name}`, entry: "Cloudflare", auth: false, tone, text, edge: true };
    }),
  );
  return [...routes, ...edge].sort((x, y) => x.hostname.localeCompare(y.hostname));
}

/** 域名：所有网址；"入口"标签管理网关。 */
export function Domains() {
  const { status, refresh } = useStatus();
  const [tab, setTab] = useTab(TABS, "list");
  const [checking, setChecking] = useState(false);
  const checkNow = async () => {
    setChecking(true);
    try {
      await api.get("/api/doctor");
      refresh();
    } catch (e) {
      toast.error("检查失败", { description: (e as Error).message });
    } finally {
      setChecking(false);
    }
  };
  const [adding, setAdding] = useState(false);
  const rows = status ? rowsOf(status) : [];

  return (
    <>
      <PageHeader
        title="域名"
        description={
          status ? `${rows.length} 个域名 · ${status.gateways.length} 个入口 · ${status.health ? `${ago(status.health.checked_at)}检查过` : "还没检查"}` : "载入中…"
        }
        actions={
          <>
          <Button variant="outline" onClick={checkNow} disabled={checking || !status?.routes.length}>
            <RadarIcon className={checking ? "animate-pulse" : undefined} />
            {checking ? "检查中…" : "立即检查"}
          </Button>
          <Button onClick={() => setAdding(true)} disabled={!status?.services.length}>
            <PlusIcon />
            加域名
          </Button>
          </>
        }
      />
      <Tabs value={tab} onValueChange={(v) => setTab(v as (typeof TABS)[number])}>
        <TabsList className="mb-4">
          <TabsTrigger value="list">域名</TabsTrigger>
          <TabsTrigger value="entries">入口</TabsTrigger>
        </TabsList>
        <TabsContent value="list">
          {!status ? (
            <CardsSkeleton count={2} />
          ) : rows.length === 0 ? (
            <Empty>{status.services.length ? "还没有域名。点右上角“加域名”给服务一个网址。" : "先部署一个服务，再给它加域名。"}</Empty>
          ) : (
            <>
              <div className="hidden overflow-hidden rounded-xl border bg-card shadow-xs md:block">
                <Table>
                  <TableHeader className="bg-muted/50">
                    <TableRow>
                      <TableHead className="pl-4">域名</TableHead>
                      <TableHead>指向</TableHead>
                      <TableHead>入口</TableHead>
                      <TableHead>状态</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((r) => (
                      <TableRow key={r.hostname}>
                        <TableCell className="pl-4">
                          <HostLink r={r} />
                        </TableCell>
                        <TableCell>
                          <Target r={r} />
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{r.entry}</TableCell>
                        <TableCell>
                          <Health r={r} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-2 md:hidden">
                {rows.map((r) => (
                  <div key={r.hostname} className="grid gap-2 rounded-xl border bg-card p-3 shadow-xs">
                    <HostLink r={r} />
                    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <Health r={r} />
                      <Target r={r} />
                      <span>· {r.entry}</span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </TabsContent>
        <TabsContent value="entries">{tab === "entries" && <GatewaysPanel />}</TabsContent>
      </Tabs>
      <AddRoute open={adding} onClose={() => setAdding(false)} />
    </>
  );
}

function HostLink({ r }: { r: Row }) {
  return (
    <a href={r.url} target="_blank" rel="noreferrer" className="group inline-flex min-w-0 items-center gap-1.5 font-mono text-sm hover:text-primary">
      {r.auth && <LockIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="登录保护" />}
      <span className="truncate">{r.hostname}</span>
      <ArrowUpRightIcon className="size-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
    </a>
  );
}

function Target({ r }: { r: Row }) {
  const icon = r.entry === "Cloudflare" ? <CloudIcon className="size-3.5 text-muted-foreground" /> : null;
  if (!r.to) return <span className="font-mono text-xs text-muted-foreground">{r.target}</span>;
  return (
    <Link to={r.to} className="inline-flex items-center gap-1 text-sm font-medium hover:underline">
      {icon}
      {r.target}
    </Link>
  );
}

function Health({ r }: { r: Row }) {
  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-2">
        <StatusBadge tone={r.tone}>{r.text}</StatusBadge>
        {!r.edge && <Lamps d={r.diag} />}
      </div>
      {r.detail && r.tone !== "ok" && <span className="max-w-72 truncate text-xs text-muted-foreground" title={r.detail}>{r.detail}</span>}
    </div>
  );
}
