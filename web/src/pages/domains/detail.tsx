import { Loader2Icon } from "lucide-react";
import { api, usePoll } from "@/api";
import { OidcClient } from "@/components/oidc-client";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AddAlias } from "@/components/add-alias";
import { AddRedirect } from "@/components/add-redirect";
import { AccessProtection } from "@/components/access-protection";
import { useActions } from "@/components/actions";
import { CodeBlock, Dot, ErrorNote, SectionTitle, StatusBadge, ago } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { LAYER, diagnosisOf, routeTone } from "@/components/health";
import { hopOf } from "@/components/hop";
import { ConfirmDialog, Facts, Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { sameTarget, targetText, type Target } from "@/components/target-fields";
import type { AppAccountView, SsoTestResult } from "@/types.gen";
import { CertProgress } from "./cert-status";
import { AddPathDialog, CaddyDialog, EditRedirectDialog, EditTargetDialog } from "./route-dialogs";
import type { GateKeyView, RouteSpec, RouteView, Status } from "@/types";

type PathRoute = NonNullable<RouteSpec["paths"]>[number];

function DomainDetail({ route, status, onClose, onDirty }: { route: RouteView; status: Status; onClose: () => void; onDirty: (dirty: boolean) => void }) {
  const actions = useActions();
  const [testOpen, setTestOpen] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<SsoTestResult>();
  const [testError, setTestError] = useState<unknown>(null);
  const testLogin = async () => {
    setTestOpen(true); setTesting(true); setTestResult(undefined); setTestError(null);
    try { setTestResult(await api.post<SsoTestResult>(`/api/routes/${encodeURIComponent(route.spec.hostname)}/sso/test`, {})); }
    catch (e) { setTestError(e); }
    finally { setTesting(false); }
  };
  const keys = usePoll<GateKeyView[]>("/api/gate/keys", 30000).data;
  const sso = route.spec.sso;
  const login = sso?.mode === "login" ? sso.login : undefined;
  const { data: accounts, error: accountError } = usePoll<AppAccountView[]>(sso?.mode === "login" ? "/api/sso/accounts" : null, null);
  const account = accounts?.find((a) => a.domains.some((d) => d.hostname === route.spec.hostname && d.is_default));
  const takeover = login?.takeover;
  const keyCount = keys?.filter((k) => k.hosts.includes(route.spec.hostname)).length ?? 0;
  const [gateOpen, setGateOpen] = useState(false);
  const [alias, setAlias] = useState(false);
  const [redirect, setRedirect] = useState(false);
  const [link, setLink] = useState(route.spec.link);
  const [rate, setRate] = useState<number | null>(route.spec.rate_limit ?? null);
  const [block, setBlock] = useState(!!route.spec.block_scanners);
  const [backup, setBackup] = useState(route.spec.backup_gateway ?? "");
  const isRedirect = route.spec.redirect != null;
  const savedTarget: Target = route.spec.upstream ? { kind: "upstream", upstream: route.spec.upstream } : { kind: "service", service: route.spec.service ?? "", port: route.spec.port };
  const [target, setTarget] = useState<Target>(savedTarget);
  const [redirectUrl, setRedirectUrl] = useState(route.spec.redirect ?? "");
  const [forwards, setForwards] = useState<PathRoute[]>(route.spec.paths ?? []);
  const [gw, setGw] = useState(route.gateway ?? "");
  const [internal, setInternal] = useState(!!route.spec.internal);
  const [coreMeshOnly, setCoreMeshOnly] = useState(!!route.spec.core_mesh_only);
  const [cfOriginOnly, setCfOriginOnly] = useState(!!route.spec.cf_origin_only);
  const [caddy, setCaddy] = useState(route.spec.caddy ?? "");
  const [dialog, setDialog] = useState<"target" | "path" | "caddy" | null>(null);
  const saved = status.gateways.find((g) => g.name === route.gateway);
  const gateway = status.gateways.find((g) => g.name === gw);
  const tunnel = gateway?.spec.kind === "cloudflare_tunnel";
  const choices = status.gateways.filter((g) => g.spec.server !== gateway?.spec.server);
  const backupNow = choices.some((g) => g.name === backup) ? backup : "";
  // 隧道入口不支持的设置，按改动后的状态算。
  const blockers = [
    (route.spec.sso || route.spec.auth) && "访问保护",
    rate !== null && "限速",
    block && "拦截常见扫描",
    internal && "只在内网访问",
    coreMeshOnly && "控制面页面只在组网内打开",
    cfOriginOnly && "仅允许 Cloudflare 回源",
    forwards.length > 0 && "按路径转发",
    caddy.trim() && "Caddy 配置",
    isRedirect && "跳转",
  ].filter(Boolean) as string[];
  const diagnosis = diagnosisOf(status, route.spec.hostname);
  const { tone, text } = routeTone(diagnosis);
  const cert = diagnosis?.cert_expires;
  const days = cert ? Math.floor((new Date(cert).getTime() - Date.now()) / 86400000) : 0;
  const diff: [string, boolean][] = [
    ["指向", isRedirect ? redirectUrl !== route.spec.redirect : !sameTarget(target, savedTarget)],
    ["路径", JSON.stringify(forwards) !== JSON.stringify(route.spec.paths ?? [])],
    ["入口", gw !== (route.gateway ?? "")],
    ["只在内网访问", internal !== !!route.spec.internal],
    ["控制面页面只在组网内打开", coreMeshOnly !== !!route.spec.core_mesh_only],
    ["仅允许 Cloudflare 回源", cfOriginOnly !== !!route.spec.cf_origin_only],
    ["走法", link !== route.spec.link],
    ["备用入口", backupNow !== (route.spec.backup_gateway ?? "")],
    ["限速", rate !== (route.spec.rate_limit ?? null)],
    ["拦截常见扫描", block !== !!route.spec.block_scanners],
    ["Caddy 配置", caddy !== (route.spec.caddy ?? "")],
  ];
  const changedList = diff.filter(([, v]) => v).map(([k]) => k);
  const changed = changedList.length > 0;
  useEffect(() => { onDirty(changed); }, [changed, onDirty]);
  const nextSpec = (): RouteSpec => ({
    ...route.spec,
    ...(isRedirect ? { redirect: redirectUrl } : target.kind === "service" ? { service: target.service, port: target.port, upstream: undefined } : { service: "", port: undefined, upstream: target.upstream.trim() }),
    paths: forwards.length ? forwards : undefined,
    gateway: gw === (route.gateway ?? "") ? route.spec.gateway : gw,
    internal: internal || undefined,
    core_mesh_only: coreMeshOnly || undefined,
    cf_origin_only: cfOriginOnly || undefined,
    link,
    backup_gateway: backupNow || undefined,
    rate_limit: rate ?? undefined,
    block_scanners: block || undefined,
    caddy: caddy.trim() ? caddy : undefined,
  });
  const pathText = (f: PathRoute) => f.service ? (f.port ? `${f.service}:${f.port}` : f.service) : f.upstream;
  return <>
    <SheetHeader className="border-b">
      <SheetTitle className="font-mono">
        {route.spec.hostname}
      </SheetTitle>
    </SheetHeader>
    <div className="flex-1 overflow-auto p-4">
      <SectionTitle>检查</SectionTitle>
      <StatusBadge tone={tone}>
        {text}
      </StatusBadge>
      {diagnosis ? <div className="mt-3">
        <Rows>
          {diagnosis.checks.map((c, i) => <Row key={`${c.layer}-${i}`}>
            <Dot tone={c.status === "skip" ? "idle" : c.status} />
            <span>
              {LAYER[c.layer] ?? c.layer}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              {c.subject}
            </span>
            <span className="min-w-0 flex-1">
              {c.detail}
            </span>
          </Row>)}
        </Rows>
      </div> : <p className="mt-3 text-sm text-muted-foreground">还没检查过，控制面启动后几分钟内会有结果</p>}
      {route.probe && <p className="mt-3 text-xs text-muted-foreground">
        {ago(new Date(route.probe.at).toISOString())}探测：{route.probe.detail}{!route.probe.ok && route.probe.fails > 1 ? `，连续 ${route.probe.fails} 次` : ""}
      </p>}
      <SectionTitle>指向</SectionTitle>
      <Panel className="p-4">
        <Facts items={[
          [isRedirect ? "跳转到" : "指向", isRedirect ? <span className="break-all font-mono text-xs">{redirectUrl}</span>
            : target.kind === "service" ? <span>
              <Link className="hover:underline" to={`/services/${encodeURIComponent(target.service)}`}>{target.service}</Link>
              {target.port && <span className="font-mono text-xs text-muted-foreground">:{target.port}</span>}
            </span> : <span className="break-all font-mono text-xs">{targetText(target)}</span>],
          ["地址", !isRedirect && sameTarget(target, savedTarget) && <span className="break-all font-mono text-xs">
            {route.upstream ?? "-"}
          </span>],
        ]} />
        <div className="mt-4 flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setDialog("target")}>{isRedirect ? "修改跳转" : "修改指向"}</Button>
          {!isRedirect && <Button variant="outline" onClick={() => setAlias(true)}>加别名</Button>}
          <Button variant="outline" onClick={() => setRedirect(true)}>跳转到这里</Button>
        </div>
      </Panel>
      {!isRedirect && <>
        <SectionTitle count={forwards.length || undefined} action={!tunnel && <Button variant="outline" size="xs" onClick={() => setDialog("path")}>加路径</Button>}>按路径转发</SectionTitle>
        {tunnel ? <p className="text-sm text-muted-foreground">隧道入口不支持按路径转发</p>
          : forwards.length ? <Rows>
            {[...forwards].sort((a, b) => a.path.localeCompare(b.path)).map((f) => <Row key={f.path}>
              <span className="shrink-0 font-mono text-xs">{f.path}</span>
              <span className="text-muted-foreground">→</span>
              <span className="min-w-0 flex-1 break-all font-mono text-xs">{pathText(f)}</span>
              <Button variant="outline" size="xs" onClick={() => setForwards(forwards.filter((v) => v.path !== f.path))}>移除</Button>
            </Row>)}
          </Rows> : <p className="text-sm text-muted-foreground">所有路径都转给{target.kind === "service" ? "这个服务" : "这个地址"}</p>}
      </>}
      <SectionTitle>入口</SectionTitle>
      <Panel className="grid gap-4 p-4">
        <Field label="入口" htmlFor="route-gateway">
          <Picker id="route-gateway" value={gw} onChange={setGw} options={status.gateways.map((g) => {
            const off = g.spec.kind === "cloudflare_tunnel" && g.name !== route.gateway && blockers.length > 0;
            return { value: g.name, label: g.name, disabled: off, hint: off ? `不支持：${blockers.join("、")}` : `${g.spec.kind === "cloudflare_tunnel" ? "Cloudflare 隧道" : "Caddy"} · ${g.spec.server}${g.spec.default ? " · 默认" : ""}` };
          })} />
        </Field>
        <Facts items={[["走法", hopOf(route, status).text]]} />
        {!isRedirect && <label className={`flex items-center gap-2 text-sm ${tunnel ? "text-muted-foreground" : ""}`}>
          <Checkbox checked={internal} disabled={tunnel} onCheckedChange={(v) => setInternal(v === true)} />只在内网访问
          {tunnel && <span className="text-xs text-muted-foreground">隧道入口不支持</span>}
        </label>}
        {(route.core || coreMeshOnly) && <label className={`flex items-center gap-2 text-sm ${tunnel ? "text-muted-foreground" : ""}`}>
          <Checkbox checked={coreMeshOnly} disabled={tunnel && !coreMeshOnly} onCheckedChange={(v) => setCoreMeshOnly(v === true)} />控制面页面只在组网内打开
        </label>}
        <label className={`flex items-center gap-2 text-sm ${tunnel ? "text-muted-foreground" : ""}`}>
          <Checkbox checked={cfOriginOnly} disabled={tunnel && !cfOriginOnly} onCheckedChange={(v) => setCfOriginOnly(v === true)} />仅允许 Cloudflare 回源
        </label>
        {target.kind === "service" && !isRedirect && !tunnel && <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={link === "tunnel"} onCheckedChange={(v) => setLink(v === true ? "tunnel" : undefined)} />总是走反向隧道</label>}
        {(choices.length > 0 || route.spec.backup_gateway) && <Field label="备用入口" htmlFor="backup-gateway" help="入口所在的机器离线 5 分钟后，DNS 自动切到备用入口，恢复 5 分钟后切回。">
          <Picker id="backup-gateway" value={backupNow} onChange={setBackup} options={[{ value: "", label: "无" }, ...choices.map((g) => {
            const off = g.spec.kind === "cloudflare_tunnel" && g.name !== route.spec.backup_gateway && blockers.length > 0;
            return { value: g.name, label: `${g.name}（${g.spec.server}）`, disabled: off, hint: off ? `不支持：${blockers.join("、")}` : undefined };
          })]} />
        </Field>}
      </Panel>
      <SectionTitle>访问保护</SectionTitle>
      <Panel className="flex flex-col gap-3 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex-1">{route.spec.sso?.mode === "oidc" ? (route.spec.sso.public ? "公开 · OIDC 登录" : "门禁 · OIDC 登录") : route.spec.sso?.public ? "公开 · 代登录入口" : route.spec.sso ? "门禁 · 用 Wharf 登录" : route.spec.auth ? "账号密码" : "不保护"}</span>
          {saved?.spec.kind === "cloudflare_tunnel" ? <span className="text-muted-foreground">隧道入口暂不支持访问保护</span> : <Button variant="outline" size="sm" onClick={() => setGateOpen(true)}>设置访问保护</Button>}
        </div>
        {route.spec.sso && !route.spec.sso.public && <Link className="text-primary hover:underline" to="/settings?tab=security#gate-keys">访问凭证（{keyCount}）</Link>}
        {login && <div className="grid gap-1 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="flex-1">{login.script ? `代登录 · 脚本（${login.script.runtime}）` : `代登录 · ${login.steps.length} 步`}</span>
            <Button size="sm" variant="outline" disabled={testing} onClick={testLogin}>测试</Button>
            <a className="text-xs underline" href={`https://${route.spec.hostname}/_wharf/login`} target="_blank" rel="noreferrer">{sso?.public ? "进入后台" : "重新登录"}</a>
          </div>
          {login.use_account && <>
            <ErrorNote error={accountError} />
            {account ? <p className="break-all">使用账号 <Link className="text-primary hover:underline" to={`/settings?tab=app-accounts&account=${encodeURIComponent(account.name)}`}>{account.name}</Link>（{account.username}）</p>
              : accounts && !accountError && <p className="text-destructive">没有默认账号，代登录会失败 <Link className="text-primary hover:underline" to={`/settings?tab=app-accounts&hostname=${encodeURIComponent(route.spec.hostname)}`}>去关联</Link></p>}
          </>}
          {takeover && <p className="break-all">接管登录页 {takeover.paths.join("、")}{!!takeover.skip_query?.length && `（带 ${takeover.skip_query.join("、")} 参数时不接管）`}</p>}
          {route.sso_login && <span className="break-all text-xs text-muted-foreground">{route.sso_login.ok ? `上次登录 ${ago(new Date(route.sso_login.at).toISOString())}，成功` : `上次登录失败：${route.sso_login.error ?? "登录失败"}`}</span>}
        </div>}
        {route.spec.sso?.mode === "oidc" && <OidcClient hostname={route.spec.hostname} />}
        {route.spec.sso?.mode === "header" && <span className="break-all text-xs text-muted-foreground">传用户名（{route.spec.sso.header ?? "Remote-User"}）</span>}
        {route.spec.sso?.trust_internal && <span className="text-xs text-muted-foreground">组网内免登录</span>}
        {route.spec.sso && keyCount > 0 && <span className="text-xs text-muted-foreground">{keyCount} 个访问凭证</span>}
        {!!route.spec.sso?.skip_paths?.length && <span className="break-all font-mono text-xs text-muted-foreground">{route.spec.sso.skip_paths.join("、")}</span>}
      </Panel>
      <SectionTitle>防护</SectionTitle>
      <Panel className="grid gap-3 p-4 text-sm">
        {!isRedirect && (tunnel ? <span className="text-muted-foreground">隧道入口不支持限速和拦截扫描</span> : <>
          <label className="flex flex-wrap items-center gap-2">
            <Checkbox checked={rate !== null} onCheckedChange={(v) => setRate(v === true ? 600 : null)} />限速
            {rate !== null && <><Input aria-label="限速次数" className="w-24" type="number" min={10} max={100000} value={rate} onChange={(e) => setRate(Number(e.target.value))} /><span>次/分钟/IP</span></>}
          </label>
          <label className="flex items-center gap-2">
            <Checkbox checked={block} onCheckedChange={(v) => setBlock(v === true)} />拦截常见扫描
          </label>
        </>)}
      </Panel>
      {!isRedirect && <>
        <SectionTitle action={!tunnel && <Button variant="outline" size="xs" onClick={() => setDialog("caddy")}>{caddy.trim() ? "编辑" : "添加"}</Button>}>Caddy 配置</SectionTitle>
        {tunnel ? <p className="text-sm text-muted-foreground">隧道入口不支持 Caddy 配置</p>
          : caddy.trim() ? <CodeBlock>{caddy}</CodeBlock> : <p className="text-sm text-muted-foreground">没有自定义配置</p>}
      </>}
      {cert && <>
        <SectionTitle>证书</SectionTitle>
        <Panel className="p-4">
          <Facts items={[["到期", <span className={days < 14 ? "text-warning" : ""}>
            {new Date(cert).toLocaleDateString("zh-CN")}（剩 {days} 天）</span>]]} />
        </Panel>
      </>}
      {!cert && saved?.spec.kind === "caddy" && (saved.spec.tls ?? "auto") === "auto" && <CertProgress hostname={route.spec.hostname} />}
    </div>
    <SheetFooter className="flex-row justify-between border-t">
      <Button variant="outline" className="text-destructive" onClick={() => actions.removeRoute(route.spec.hostname)}>移除域名</Button>
      <div className="grid min-w-0 gap-2">{changed && <span className="text-xs text-muted-foreground">改了：{changedList.join("、")}</span>}
      <Button disabled={!changed || (rate !== null && (!Number.isInteger(rate) || rate < 10 || rate > 100000))} onClick={() => { onClose(); actions.plan({ title: `修改 ${route.spec.hostname}`, changes: [{ op: "upsert_route", spec: nextSpec() }] }); }}>预览改动</Button></div>
    </SheetFooter>
    {gateOpen && <AccessProtection route={route} onClose={() => setGateOpen(false)} />}
    {dialog === "target" && (isRedirect
      ? <EditRedirectDialog hostname={route.spec.hostname} url={redirectUrl} onSave={setRedirectUrl} onClose={() => setDialog(null)} />
      : <EditTargetDialog hostname={route.spec.hostname} target={target} onSave={setTarget} onClose={() => setDialog(null)} />)}
    {dialog === "path" && <AddPathDialog taken={forwards.map((f) => f.path)} onAdd={(path, t) => setForwards([...forwards, t.kind === "service" ? { path, service: t.service, port: t.port } : { path, upstream: t.upstream.trim() }])} onClose={() => setDialog(null)} />}
    {dialog === "caddy" && <CaddyDialog hostname={route.spec.hostname} value={caddy} onSave={setCaddy} onClose={() => setDialog(null)} />}
    <Dialog open={testOpen} onOpenChange={setTestOpen}>
      <DialogContent aria-describedby={undefined} className="max-h-[85vh] overflow-auto">
        <DialogHeader><DialogTitle>代登录测试</DialogTitle></DialogHeader>
        {testing && <p className="flex items-center gap-2 text-sm" role="status"><Loader2Icon className="size-4 animate-spin" />正在登录…（脚本方式通常 1–3 秒）</p>}
        <ErrorNote error={testError} />
        {testResult && <>
          <p>{testResult.ok ? "成功" : "失败"}</p>
          <Rows>{[...testResult.steps, ...(testResult.check ? [testResult.check] : [])].map((step, i) => {
            const script = step.method === "SCRIPT";
            const extracted = Object.entries(step.extracted).map(([name, n]) => `${name}（${n} 个字符）`).join("、");
            return <Row key={i} className="flex-wrap break-all">
              <span>{script ? "脚本" : `${step.method} ${step.path}`}</span>
              <span>{script ? (step.error ? "失败" : "成功") : step.status ?? "未响应"}</span>
              <span>{step.ms}ms</span>
              {extracted && <span>取到：{extracted}</span>}
              {step.error && <span className="text-destructive">{step.error}</span>}
            </Row>;
          })}</Rows>
          {testResult.would_write.length > 0 && <div className="grid gap-1">
            <p className="text-sm">会写入浏览器：</p>
            <ul className="grid gap-1 text-xs text-muted-foreground">
              {testResult.would_write.map((text, i) => <li className="break-all" key={i}>{text}</li>)}
            </ul>
          </div>}
          {testResult.script_log && <details className="text-sm">
            <summary className="cursor-pointer">脚本输出</summary>
            <pre className="max-h-60 overflow-auto text-xs">{testResult.script_log}</pre>
          </details>}
        </>}
        <DialogFooter><Button variant="outline" onClick={() => setTestOpen(false)}>关闭</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <AddAlias route={route} open={alias} onClose={() => setAlias(false)} />
    <AddRedirect open={redirect} onClose={() => setRedirect(false)} target={route.url} gateway={route.gateway} />
  </>;
}

export function DomainSheet({ route, status, onClose }: { route?: RouteView; status: Status; onClose: () => void }) {
  const [dirty, setDirty] = useState(false);
  const [discard, setDiscard] = useState(false);
  const close = () => { if (dirty) setDiscard(true); else onClose(); };
  return <>
    <Sheet open={!!route} onOpenChange={(open) => !open && close()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        {route && <DomainDetail key={route.id} route={route} status={status} onClose={() => { setDirty(false); onClose(); }} onDirty={setDirty} />}
      </SheetContent>
    </Sheet>
    <ConfirmDialog open={discard} title="放弃改动？" confirmText="放弃" onCancel={() => setDiscard(false)} onConfirm={() => { setDiscard(false); setDirty(false); onClose(); }}>未预览的改动不会保存。</ConfirmDialog>
  </>;
}
