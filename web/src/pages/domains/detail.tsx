import { usePoll } from "@/api";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AddAlias } from "@/components/add-alias";
import { AddRedirect } from "@/components/add-redirect";
import { useActions } from "@/components/actions";
import { Dot, SectionTitle, StatusBadge, ago } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { LAYER, diagnosisOf, routeTone } from "@/components/health";
import { hopOf } from "@/components/hop";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { GateKeyView, RouteView, Status } from "@/types";

export function DomainDetail({ route, status, onClose }: { route: RouteView; status: Status; onClose: () => void }) {
  const actions = useActions();
  const keys = usePoll<GateKeyView[]>("/api/gate/keys", 30000).data;
  const keyCount = keys?.filter((k) => k.hosts.includes(route.spec.hostname)).length ?? 0;
  const [trustInternal, setTrustInternal] = useState(!!route.spec.sso?.trust_internal);
  const [gateOpen, setGateOpen] = useState(false);
  const [skipPaths, setSkipPaths] = useState((route.spec.sso?.skip_paths ?? []).join("\n"));
  const [alias, setAlias] = useState(false);
  const [redirect, setRedirect] = useState(false);
  const [, setParams] = useSearchParams();
  const [link, setLink] = useState(route.spec.link);
  const [rate, setRate] = useState<number | null>(route.spec.rate_limit ?? null);
  const [block, setBlock] = useState(!!route.spec.block_scanners);
  const [backup, setBackup] = useState(route.spec.backup_gateway ?? "");
  const gateway = status.gateways.find((g) => g.name === route.gateway);
  const choices = status.gateways.filter((g) => g.spec.server !== gateway?.spec.server);
  const diagnosis = diagnosisOf(status, route.spec.hostname);
  const { tone, text } = routeTone(diagnosis);
  const cert = diagnosis?.cert_expires;
  const days = cert ? Math.floor((new Date(cert).getTime() - Date.now()) / 86400000) : 0;
  const changed = link !== route.spec.link || backup !== (route.spec.backup_gateway ?? "") || rate !== (route.spec.rate_limit ?? null) || block !== !!route.spec.block_scanners;
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
          ["指向", route.spec.service ? <Link className="hover:underline" to={`/services/${encodeURIComponent(route.spec.service)}`}>
            {route.spec.service}
          </Link> : <span className="break-all font-mono text-xs">
            {route.spec.redirect ?? route.spec.upstream}
          </span>],
          ["地址", !route.spec.redirect && <span className="break-all font-mono text-xs">
            {route.upstream ?? "-"}
          </span>],
        ]} />
        <div className="mt-4 flex flex-wrap gap-2">
          {!route.spec.redirect && <Button variant="outline" onClick={() => setAlias(true)}>加别名</Button>}
          <Button variant="outline" onClick={() => setRedirect(true)}>跳转到这里</Button>
        </div>
      </Panel>
      <SectionTitle>入口</SectionTitle>
      <Panel className="grid gap-4 p-4">
        <Facts items={[
          ["入口", gateway && <>
            <button className="hover:underline" onClick={() => setParams({ tab: "entries", entry: gateway.name })}>
              {gateway.name}
            </button> <span className="text-muted-foreground">
              {gateway.spec.server}
            </span>
          </>],
          ["走法", hopOf(route, status).text],
          ...(!route.spec.redirect ? [["访问范围", route.spec.internal ? "只在内网" : "公网"] as [string, string]] : []),
        ]} />
        {route.spec.service && gateway?.spec.kind === "caddy" && <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={link === "tunnel"} onCheckedChange={(v) => setLink(v === true ? "tunnel" : undefined)} />总是走反向隧道</label>}
        {(choices.length > 0 || route.spec.backup_gateway) && <Field label="备用入口" htmlFor="backup-gateway" help="入口所在的机器离线 5 分钟后，DNS 自动切到备用入口，恢复 5 分钟后切回。">
          <Picker id="backup-gateway" value={backup} onChange={setBackup} options={[{ value: "", label: "无" }, ...choices.map((g) => ({ value: g.name, label: `${g.name}（${g.spec.server}）` }))]} />
        </Field>}
      </Panel>
      <SectionTitle>保护</SectionTitle>
      <Panel className="flex flex-col gap-3 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex-1">登录保护：{route.spec.auth ? "已开启 · 账号密码" : "没开"}
          </span>
          {gateway?.spec.kind === "cloudflare_tunnel" ? <span className="text-muted-foreground">隧道入口暂不支持登录保护</span> : route.spec.auth ? <>
            <Button variant="outline" size="sm" onClick={() => actions.basicAuth(route.spec.hostname)}>改账号</Button>
            <Button variant="outline" size="sm" onClick={() => actions.plan({ title: `关闭 ${route.spec.hostname} 的登录保护`, changes: [{ op: "upsert_route", spec: { ...route.spec, auth: false } }] })}>关闭</Button>
          </> : <Button variant="outline" size="sm" onClick={() => actions.basicAuth(route.spec.hostname, true)}>开启</Button>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="min-w-0 flex-1">门禁：{route.spec.sso ? "已开启" : "没开"}</span>
          {gateway?.spec.kind === "cloudflare_tunnel" ? <span className="text-muted-foreground">隧道入口暂不支持门禁</span> : route.spec.sso ? <>
            <Button variant="outline" size="sm" onClick={() => setGateOpen(true)}>改</Button>
            <Button variant="outline" size="sm" onClick={() => actions.plan({ title: `关闭 ${route.spec.hostname} 的门禁`, changes: [{ op: "upsert_route", spec: { ...route.spec, sso: undefined } }] })}>关闭</Button>
          </> : <>
            {route.spec.auth && <span className="text-muted-foreground">先关掉登录保护</span>}
            <Button variant="outline" size="sm" disabled={route.spec.auth || !!route.spec.redirect} onClick={() => setGateOpen(true)}>开启</Button>
          </>}
        </div>
        {route.spec.sso?.trust_internal && <span className="text-xs text-muted-foreground">组网内免登录</span>}
        {route.spec.sso && keyCount > 0 && <span className="text-xs text-muted-foreground">{keyCount} 个访问凭证</span>}
        {!!route.spec.sso?.skip_paths?.length && <span className="break-all font-mono text-xs text-muted-foreground">{route.spec.sso.skip_paths.join("、")}</span>}
        {!route.spec.redirect && (gateway?.spec.kind === "cloudflare_tunnel" ? <span className="text-muted-foreground">隧道入口不支持限速和拦截扫描</span> : <>
          <label className="flex flex-wrap items-center gap-2">
            <Checkbox checked={rate !== null} onCheckedChange={(v) => setRate(v === true ? 600 : null)} />限速
            {rate !== null && <><Input aria-label="限速次数" className="w-24" type="number" min={10} max={100000} value={rate} onChange={(e) => setRate(Number(e.target.value))} /><span>次/分钟/IP</span></>}
          </label>
          <label className="flex items-center gap-2">
            <Checkbox checked={block} onCheckedChange={(v) => setBlock(v === true)} />拦截常见扫描
          </label>
        </>)}
      </Panel>
      {cert && <>
        <SectionTitle>证书</SectionTitle>
        <Panel className="p-4">
          <Facts items={[["到期", <span className={days < 14 ? "text-warning" : ""}>
            {new Date(cert).toLocaleDateString("zh-CN")}（剩 {days} 天）</span>]]} />
        </Panel>
      </>}
    </div>
    <SheetFooter className="flex-row justify-between border-t">
      <Button variant="outline" className="text-destructive" onClick={() => actions.removeRoute(route.spec.hostname)}>移除域名</Button>
      <Button disabled={!changed || (rate !== null && (!Number.isInteger(rate) || rate < 10 || rate > 100000))} onClick={() => { onClose(); actions.plan({ title: `修改 ${route.spec.hostname}`, changes: [{ op: "upsert_route", spec: { ...route.spec, link, backup_gateway: backup || undefined, rate_limit: rate ?? undefined, block_scanners: block || undefined } }] }); }}>预览改动</Button>
    </SheetFooter>
    <Dialog open={gateOpen} onOpenChange={setGateOpen}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>{route.spec.sso ? "修改门禁" : "开启门禁"}</DialogTitle></DialogHeader>
        <Field label="不用登录的路径（每行一个，可以不填）" htmlFor="gate-skip">
          <Textarea id="gate-skip" value={skipPaths} onChange={(e) => setSkipPaths(e.target.value)} />
        </Field>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={trustInternal} onCheckedChange={(v) => setTrustInternal(v === true)} />从组网内访问不用登录</label>
        {trustInternal && <p className="text-xs text-muted-foreground">只有经组网地址或这台机器的内网访问入口时才算；从别的网络访问公网入口仍然要登录。</p>}
        <DialogFooter>
          <Button variant="ghost" onClick={() => setGateOpen(false)}>取消</Button>
          <Button onClick={() => { setGateOpen(false); actions.plan({ title: `修改 ${route.spec.hostname} 的门禁`, changes: [{ op: "upsert_route", spec: { ...route.spec, sso: { mode: "gate", trust_internal: trustInternal, skip_paths: skipPaths.split("\n").map((p) => p.trim()).filter(Boolean) } } }] }); }}>预览改动</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    <AddAlias route={route} open={alias} onClose={() => setAlias(false)} />
    <AddRedirect open={redirect} onClose={() => setRedirect(false)} target={route.url} gateway={route.gateway} />
  </>;
}
