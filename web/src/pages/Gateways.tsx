import { PlusIcon, Trash2Icon, WaypointsIcon } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CardsSkeleton, CodeBlock, Empty, Notice, ServerTag, StatusBadge, liveTone } from "@/components/common";
import { Field, Picker, Segmented, serverOptions, toName } from "@/components/fields";
import { LogStream } from "@/components/LogStream";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CertDays, diagnosisOf } from "@/components/health";
import { useStatus } from "@/status";
import type { AccountView, GatewaySpec, GatewayTls, GatewayView } from "@/types";

type GatewayKind = GatewaySpec["kind"];

const TLS_TEXT: Record<GatewayTls, string> = {
  auto: "自动签证书",
  internal: "自签证书",
  off: "只走 HTTP",
};

/** 域名页的"入口"标签：网关列表、详情和新建。人加域名时选的是入口，这里只在需要管理时用。 */
export function GatewaysPanel() {
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const open = params.get("open");
  const creating = params.get("new") === "1";
  const gateways = status?.gateways ?? [];
  const selected = gateways.find((g) => g.name === open);

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-end gap-3">
        <Button variant="outline" size="sm" onClick={() => setParams({ tab: "entries", new: "1" })}>
          <PlusIcon />
          新建入口
        </Button>
      </div>
      {!status ? (
        <CardsSkeleton count={2} />
      ) : gateways.length === 0 ? (
        <Empty>还没有入口。加域名时会提示新建，也可以在这里先建好。</Empty>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-3">
          {gateways.map((g, i) => {
            const { tone, text } = liveTone(g.live);
            const tls = g.spec.tls ?? "auto";
            return (
              <button
                key={g.name}
                style={{ animationDelay: `${i * 30}ms` }}
                onClick={() => setParams({ tab: "entries", open: g.name })}
                className="flex flex-col gap-3 rounded-xl border bg-card p-4 text-left shadow-xs transition-all animate-in fade-in slide-in-from-bottom-1 fill-mode-both hover:-translate-y-px hover:border-foreground/15 hover:shadow-md"
              >
                <div className="flex items-center gap-3">
                  <span className="grid size-9 place-items-center rounded-lg border bg-muted text-muted-foreground">
                    <WaypointsIcon className="size-4" />
                  </span>
                  <div className="min-w-0">
                    <div className="font-semibold">{g.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {g.spec.kind === "cloudflare_tunnel"
                        ? `Cloudflare 隧道 · 账号 ${g.spec.account}`
                        : `Caddy · ${TLS_TEXT[tls]} · ${tls === "off" ? `HTTP ${g.spec.http_port ?? 80}` : `HTTPS ${g.spec.https_port ?? 443}`}`}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <StatusBadge tone={tone}>{text}</StatusBadge>
                  <ServerTag name={g.spec.server} />
                  {g.spec.default && <Badge variant="secondary">默认</Badge>}
                  <span className="ml-auto">{g.routes.length} 个域名</span>
                </div>
              </button>
            );
          })}
        </div>
      )}

      <Sheet open={!!selected} onOpenChange={(o) => !o && setParams({ tab: "entries" })}>
        <SheetContent className="w-full gap-0 sm:max-w-xl" onOpenAutoFocus={(e) => e.preventDefault()}>
          {selected && <GatewayDetail g={selected} onDone={() => setParams({ tab: "entries" })} />}
        </SheetContent>
      </Sheet>
      <Sheet open={creating} onOpenChange={(o) => !o && setParams({ tab: "entries" })}>
        <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
          <SheetHeader className="border-b">
            <SheetTitle>新建入口</SheetTitle>
          </SheetHeader>
          {creating && <NewGateway onDone={() => setParams({ tab: "entries" })} />}
        </SheetContent>
      </Sheet>
    </>
  );
}

/** 域名的备用入口：只能选另一台机器上的网关。 */
function BackupPicker({ g, hostname }: { g: GatewayView; hostname: string }) {
  const actions = useActions();
  const { status } = useStatus();
  const route = status?.routes.find((r) => r.spec.hostname === hostname);
  if (!route) return null;
  const choices = (status?.gateways ?? []).filter((x) => x.spec.server !== g.spec.server);
  if (!choices.length && !route.spec.backup_gateway) return null;
  const set = (v: string) =>
    actions.plan({
      title: v ? `${hostname} 的备用入口改为 ${v}` : `去掉 ${hostname} 的备用入口`,
      changes: [{ op: "upsert_route", spec: { ...route.spec, backup_gateway: v || undefined } }],
    });
  return (
    <span className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
      {route.on_backup && <Badge variant="destructive">正走备用</Badge>}
      备用
      <select
        className="rounded-md border bg-background px-1.5 py-1 text-xs text-foreground"
        value={route.spec.backup_gateway ?? ""}
        onChange={(e) => set(e.target.value)}
        title="主网关所在机器离线 5 分钟后，DNS 自动切到备用入口，恢复 5 分钟后切回"
      >
        <option value="">无</option>
        {choices.map((x) => (
          <option key={x.name} value={x.name}>
            {x.name}（{x.spec.server}）
          </option>
        ))}
      </select>
    </span>
  );
}

function GatewayDetail({ g, onDone }: { g: GatewayView; onDone: () => void }) {
  const actions = useActions();
  const { status } = useStatus();
  const { data: config } = usePoll<{ config: string; compose: string }>(`/api/gateways/${encodeURIComponent(g.name)}/config`, 30000);
  return (
    <>
      <SheetHeader className="border-b">
        <SheetTitle>{g.name}</SheetTitle>
        <SheetDescription>入口（网关）</SheetDescription>
      </SheetHeader>
      <div className="flex-1 overflow-auto p-4">
        <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-4 gap-y-3 text-sm">
          <dt className="text-muted-foreground">服务器</dt>
          <dd>
            <ServerTag name={g.spec.server} />
          </dd>
          {g.spec.kind === "cloudflare_tunnel" ? (
            <>
              <dt className="text-muted-foreground">类型</dt>
              <dd>Cloudflare 隧道（wharf-{g.name}）</dd>
              <dt className="text-muted-foreground">厂商账号</dt>
              <dd>{g.spec.account}</dd>
            </>
          ) : (
            <>
              <dt className="text-muted-foreground">证书</dt>
              <dd>{TLS_TEXT[g.spec.tls ?? "auto"]}</dd>
              <dt className="text-muted-foreground">端口</dt>
              <dd className="font-mono text-[13px]">
                HTTP {g.spec.http_port ?? 80} · HTTPS {g.spec.https_port ?? 443}
              </dd>
            </>
          )}
        </dl>
        <Tabs defaultValue="routes" className="mt-6">
          <TabsList>
            <TabsTrigger value="routes">域名</TabsTrigger>
            <TabsTrigger value="config">生成的配置</TabsTrigger>
            <TabsTrigger value="logs">日志</TabsTrigger>
          </TabsList>
          <TabsContent value="routes" className="mt-3">
            {g.routes.length ? (
              <div className="divide-y rounded-lg border">
                {g.routes.map((h) => {
                  const redirect = status?.routes.find((r) => r.spec.hostname === h)?.spec.redirect;
                  return (
                    <div className="flex flex-wrap items-center gap-3 px-3.5 py-2.5 text-[13px]" key={h}>
                      <span className="font-mono">{h}</span>
                      {redirect && <span className="text-muted-foreground">→ {redirect}</span>}
                      <CertDays d={diagnosisOf(status, h)} />
                      <BackupPicker g={g} hostname={h} />
                    </div>
                  );
                })}
              </div>
            ) : (
              <Empty>没有域名</Empty>
            )}
          </TabsContent>
          <TabsContent value="config" className="mt-3">
            <CodeBlock>{config?.config ?? "载入中…"}</CodeBlock>
          </TabsContent>
          <TabsContent value="logs" className="mt-3">
            <LogStream path={`/api/gateways/${encodeURIComponent(g.name)}/logs/stream`} />
          </TabsContent>
        </Tabs>
      </div>
      <SheetFooter className="flex-row items-center justify-between border-t">
        <span className="text-xs text-muted-foreground">{g.routes.length ? "先移除这个网关上的域名才能删除。" : ""}</span>
        <Button
          variant="outline"
          className="text-destructive"
          disabled={g.routes.length > 0}
          onClick={() => {
            onDone();
            actions.plan({
              title: `删除网关 ${g.name}`,
              changes: [{ op: "remove_gateway", name: g.name }],
            });
          }}
        >
          <Trash2Icon />
          删除网关
        </Button>
      </SheetFooter>
    </>
  );
}

function NewGateway({ onDone }: { onDone: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const servers = status?.servers ?? [];
  const hasDefault = status?.gateways.some((g) => g.spec.default) ?? false;
  const [server, setServer] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<GatewayKind>("caddy");
  const { data: accounts } = usePoll<AccountView[]>(kind === "cloudflare_tunnel" ? "/api/accounts" : null, 30000);
  const [account, setAccount] = useState("");
  const chosenAccount = account || accounts?.[0]?.name || "";
  const tunnel = kind === "cloudflare_tunnel";
  const [tls, setTls] = useState<GatewayTls>("auto");
  const [httpPort, setHttpPort] = useState(80);
  const [httpsPort, setHttpsPort] = useState(443);
  const [isDefault, setDefault] = useState(!hasDefault);
  const chosen = server || serverOptions(servers)[0]?.value || "";
  const gwName = name || (chosen ? `${chosen}-${tunnel ? "tunnel" : "edge"}` : "");
  const options = serverOptions(servers).map((o) => {
    const ip = servers.find((s) => s.name === o.value)?.public_ip;
    return ip ? { ...o, hint: `${o.hint} · 公网 ${ip}` } : o;
  });

  const submit = () => {
    onDone();
    actions.plan({
      title: `新建网关 ${gwName}`,
      changes: [
        {
          op: "upsert_gateway",
          name: gwName,
          spec: tunnel
            ? {
                kind,
                server: chosen,
                default: isDefault || undefined,
                account: chosenAccount,
              }
            : {
                kind,
                server: chosen,
                default: isDefault || undefined,
                http_port: httpPort === 80 ? undefined : httpPort,
                https_port: httpsPort === 443 ? undefined : httpsPort,
                tls: tls === "auto" ? undefined : tls,
              },
        },
      ],
    });
  };

  return (
    <>
      <div className="grid flex-1 content-start gap-5 overflow-auto p-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="服务器" htmlFor="server">
            <Picker id="server" value={chosen} options={options} onChange={setServer} />
          </Field>
          <Field label="名称" htmlFor="name">
            <Input id="name" value={gwName} onChange={(e) => setName(toName(e.target.value))} />
          </Field>
        </div>
        <Field
          label="类型"
        >
          <Segmented
            value={kind}
            onChange={setKind}
            options={[
              ["caddy", "Caddy"],
              ["cloudflare_tunnel", "Cloudflare 隧道"],
            ]}
          />
        </Field>
        {tunnel ? (
          accounts && accounts.length === 0 ? (
            <Notice kind="warn">
              隧道要建在 Cloudflare 账号下，还没有账号。{" "}
              <Link to="/settings" className="font-medium underline underline-offset-2">
                去添加厂商账号
              </Link>
            </Notice>
          ) : (
            <Field label="厂商账号" htmlFor="account">
              <Picker
                id="account"
                value={chosenAccount}
                options={(accounts ?? []).map((a) => ({
                  value: a.name,
                  label: a.name,
                  hint: a.zones.join("、"),
                }))}
                onChange={setAccount}
                placeholder="载入中…"
              />
            </Field>
          )
        ) : (
          <>
            <Field
              label="证书"
            >
              <Segmented value={tls} onChange={setTls} options={(["auto", "internal", "off"] as GatewayTls[]).map((t) => [t, TLS_TEXT[t]])} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="HTTP 端口" htmlFor="http">
                <Input id="http" type="number" value={httpPort} onChange={(e) => setHttpPort(Number(e.target.value))} />
              </Field>
              <Field label="HTTPS 端口" htmlFor="https">
                <Input id="https" type="number" value={httpsPort} onChange={(e) => setHttpsPort(Number(e.target.value))} />
              </Field>
            </div>
          </>
        )}
        <label className="flex cursor-pointer items-center gap-2.5 text-sm">
          <Checkbox checked={isDefault} onCheckedChange={(v) => setDefault(v === true)} />
          设为默认网关（加域名时不选网关就用它）
        </label>
      </div>
      <SheetFooter className="flex-row justify-end border-t">
        <Button variant="ghost" onClick={onDone}>
          取消
        </Button>
        <Button disabled={!chosen || !gwName || (tunnel && !chosenAccount)} onClick={submit}>
          生成计划
        </Button>
      </SheetFooter>
    </>
  );
}
