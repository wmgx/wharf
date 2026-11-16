import { useState } from "react";
import { useActions } from "@/components/actions";
import { AuthFields, authReady, saveAuth } from "@/components/basic-auth";
import { ErrorNote } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { RouteView } from "@/types";

export function AccessProtection({ route, onClose }: { route: RouteView; onClose: () => void }) {
  const actions = useActions();
  const { status } = useStatus();
  const gateway = status?.gateways.find((g) => g.name === route.gateway);
  const [trustInternal, setTrustInternal] = useState(!!route.spec.sso?.trust_internal);
  const [gateMode, setGateMode] = useState<"gate" | "header" | "login" | "oidc">(route.spec.sso?.mode ?? "gate");
  const [redirects, setRedirects] = useState((route.spec.sso?.oidc?.redirect_uris ?? []).join("\n"));
  const [userHeader, setUserHeader] = useState(route.spec.sso?.header ?? "Remote-User");
  const [protection, setProtection] = useState<"gate" | "basic" | "none">(route.spec.auth ? "basic" : "gate");
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [skipPaths, setSkipPaths] = useState((route.spec.sso?.skip_paths ?? []).join("\n"));
  const [dropLogin, setDropLogin] = useState(false);
  const [isPublic, setIsPublic] = useState(!!route.spec.sso?.public);
  const publicLogin = (gateMode === "login" || gateMode === "oidc") && isPublic;
  const redirectList = redirects.split("\n").map((p) => p.trim()).filter(Boolean);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent aria-describedby={undefined} className="max-h-[85svh] overflow-y-auto">
        <DialogHeader><DialogTitle>访问保护</DialogTitle></DialogHeader>
        <Picker value={protection} onChange={(v) => setProtection(v as typeof protection)} options={[{ value: "gate", label: "门禁（用 Wharf 登录，推荐）" }, { value: "basic", label: "账号密码" }, { value: "none", label: "不保护" }]} />
        {gateway?.spec.kind === "cloudflare_tunnel" && <p className="text-sm text-muted-foreground">隧道入口暂不支持访问保护</p>}
        {protection === "basic" && <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />}
        {protection === "gate" && !route.spec.redirect && <>
        <Field label="通过门禁后" htmlFor="gate-mode" help={gateMode === "gate" ? "仅检查 Wharf 登录，不替你登录应用。应用如果还有登录页，需要另外登录。" : gateMode === "header" ? "将 Wharf 用户名传给应用；应用需要支持并信任这个请求头。" : gateMode === "oidc" ? "应用用 Wharf 账号登录；应用需要支持 OIDC。" : "按已配置的登录步骤替你登录应用。"}>
          <Picker id="gate-mode" value={gateMode} options={[{ value: "gate", label: "仅检查 Wharf 登录" }, { value: "header", label: "向应用传递用户名" }, { value: "oidc", label: "用 Wharf 账号登录（OIDC）" }, ...(route.spec.sso?.mode === "login" ? [{ value: "login", label: "自动登录应用" }] : [])]} onChange={(v) => setGateMode(v as typeof gateMode)} />
        </Field>
        {gateMode === "header" && <Field label="请求头" htmlFor="gate-header"><Input id="gate-header" value={userHeader} onChange={(e) => setUserHeader(e.target.value)} /></Field>}
        {gateMode === "oidc" && <Field label="回调地址（每行一个）" htmlFor="oidc-redirects">
          <Textarea id="oidc-redirects" value={redirects} placeholder="/login/generic_oauth" onChange={(e) => setRedirects(e.target.value)} />
        </Field>}
        {(gateMode === "login" || gateMode === "oidc") && <label className="flex items-center gap-2 text-sm"><Checkbox checked={isPublic} onCheckedChange={(v) => setIsPublic(v === true)} />公开站点，访客不用登录</label>}
        {!publicLogin && <>
        <Field label="不用登录的路径（每行一个，可以不填）" htmlFor="gate-skip">
          <Textarea id="gate-skip" value={skipPaths} onChange={(e) => setSkipPaths(e.target.value)} />
        </Field>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={trustInternal} onCheckedChange={(v) => setTrustInternal(v === true)} />从组网内访问不用登录</label>
        {trustInternal && <p className="text-xs text-muted-foreground">只有经组网地址或这台机器的内网访问入口时才算；从别的网络访问公网入口仍然要登录。</p>}
        </>}
        </>}
        {protection === "gate" && route.spec.redirect && <p className="text-sm text-muted-foreground">跳转域名不支持门禁</p>}
        {route.spec.sso?.mode === "login" && (protection !== "gate" || gateMode !== "login") && <label className="flex items-center gap-2 text-sm"><Checkbox checked={dropLogin} onCheckedChange={(v) => setDropLogin(v === true)} />登录步骤会被删掉</label>}
        <DialogFooter>
          <Button variant="ghost" onClick={() => onClose()}>取消</Button>
          <Button disabled={saving || gateway?.spec.kind === "cloudflare_tunnel" || (protection === "gate" && !!route.spec.redirect) || (protection === "basic" && !authReady(user, password)) || (protection === "gate" && gateMode === "oidc" && !redirectList.length) || (route.spec.sso?.mode === "login" && (protection !== "gate" || gateMode !== "login") && !dropLogin)} onClick={async () => {
            setSaving(true); setSaveError(null);
            try {
              if (protection === "basic") await saveAuth(route.spec.hostname, user, password);
              setPassword(""); onClose();
              actions.plan({ title: `修改 ${route.spec.hostname} 的访问保护`, changes: [{ op: "upsert_route", spec: { ...route.spec, auth: protection === "basic", sso: protection === "gate" ? { mode: gateMode, login: gateMode === "login" ? route.spec.sso?.login : undefined, header: gateMode === "header" ? userHeader : undefined, oidc: gateMode === "oidc" ? { redirect_uris: redirectList } : undefined, trust_internal: !publicLogin && trustInternal, skip_paths: publicLogin ? [] : skipPaths.split("\n").map((p) => p.trim()).filter(Boolean), public: publicLogin || undefined } : undefined } }] });
            } catch (e) { setSaveError(e); } finally { setSaving(false); }
          }}>预览改动</Button>
        </DialogFooter>
        <ErrorNote error={saveError} />
      </DialogContent>
    </Dialog>
  );
}
