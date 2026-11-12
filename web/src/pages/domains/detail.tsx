import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useActions } from "@/components/actions";
import { Dot, SectionTitle, StatusBadge, ago } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { LAYER, diagnosisOf, routeTone } from "@/components/health";
import { hopOf } from "@/components/hop";
import { Facts, Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import type { RouteView, Status } from "@/types";

export function DomainDetail({ route, status, onClose }: { route: RouteView; status: Status; onClose: () => void }) {
  const actions = useActions();
  const [, setParams] = useSearchParams();
  const [link, setLink] = useState(route.spec.link);
  const [backup, setBackup] = useState(route.spec.backup_gateway ?? "");
  const gateway = status.gateways.find((g) => g.name === route.gateway);
  const choices = status.gateways.filter((g) => g.spec.server !== gateway?.spec.server);
  const diagnosis = diagnosisOf(status, route.spec.hostname);
  const { tone, text } = routeTone(diagnosis);
  const cert = diagnosis?.cert_expires;
  const days = cert ? Math.floor((new Date(cert).getTime() - Date.now()) / 86400000) : 0;
  const changed = link !== route.spec.link || backup !== (route.spec.backup_gateway ?? "");
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
        ]} />
        {route.spec.service && gateway?.spec.kind === "caddy" && <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={link === "tunnel"} onCheckedChange={(v) => setLink(v === true ? "tunnel" : undefined)} />总是走反向隧道</label>}
        {(choices.length > 0 || route.spec.backup_gateway) && <Field label="备用入口" htmlFor="backup-gateway" help="入口所在的机器离线 5 分钟后，DNS 自动切到备用入口，恢复 5 分钟后切回。">
          <Picker id="backup-gateway" value={backup} onChange={setBackup} options={[{ value: "", label: "无" }, ...choices.map((g) => ({ value: g.name, label: `${g.name}（${g.spec.server}）` }))]} />
        </Field>}
      </Panel>
      <SectionTitle>保护</SectionTitle>
      <Panel className="flex flex-wrap items-center gap-2 p-4 text-sm">
        <span className="flex-1">登录保护：{route.spec.auth ? "已开启 · 账号密码" : "没开"}
        </span>
        {gateway?.spec.kind === "cloudflare_tunnel" ? <span className="text-muted-foreground">隧道入口暂不支持登录保护</span> : route.spec.auth ? <>
          <Button variant="outline" size="sm" onClick={() => actions.basicAuth(route.spec.hostname)}>改账号</Button>
          <Button variant="outline" size="sm" onClick={() => actions.plan({ title: `关闭 ${route.spec.hostname} 的登录保护`, changes: [{ op: "upsert_route", spec: { ...route.spec, auth: false } }] })}>关闭</Button>
        </> : <Button variant="outline" size="sm" onClick={() => actions.basicAuth(route.spec.hostname, true)}>开启</Button>}
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
      <Button disabled={!changed} onClick={() => { onClose(); actions.plan({ title: `修改 ${route.spec.hostname}`, changes: [{ op: "upsert_route", spec: { ...route.spec, link, backup_gateway: backup || undefined } }] }); }}>预览改动</Button>
    </SheetFooter>
  </>;
}
