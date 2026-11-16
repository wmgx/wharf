import { useState } from "react";
import { useActions } from "@/components/actions";
import { AuthFields, authReady, saveAuth } from "@/components/basic-auth";
import { ErrorNote } from "@/components/common";
import { Field, Picker, Segmented } from "@/components/fields";
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
  const [gateMode, setGateMode] = useState<"gate" | "header" | "login">(route.spec.sso?.mode ?? "gate");
  const [userHeader, setUserHeader] = useState(route.spec.sso?.header ?? "Remote-User");
  const [protection, setProtection] = useState<"gate" | "basic" | "none">(route.spec.auth ? "basic" : "gate");
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [skipPaths, setSkipPaths] = useState((route.spec.sso?.skip_paths ?? []).join("\n"));
  const [dropLogin, setDropLogin] = useState(false);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent aria-describedby={undefined} className="max-h-[85svh] overflow-y-auto">
        <DialogHeader><DialogTitle>访问保护</DialogTitle></DialogHeader>
        <Picker value={protection} onChange={(v) => setProtection(v as typeof protection)} options={[{ value: "gate", label: "门禁（用 Wharf 登录，推荐）" }, { value: "basic", label: "账号密码" }, { value: "none", label: "不保护" }]} />
        {gateway?.spec.kind === "cloudflare_tunnel" && <p className="text-sm text-muted-foreground">隧道入口暂不支持访问保护</p>}
        {protection === "basic" && <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />}
        {protection === "gate" && !route.spec.redirect && <>
        <Segmented value={gateMode} options={[["gate", "只挡一道门"], ["header", "传用户名给应用"], ...(route.spec.sso?.mode === "login" ? [["login", "替我登录应用"] as ["login", string]] : [])]} onChange={setGateMode} />
        {gateMode === "header" && <Field label="请求头" htmlFor="gate-header"><Input id="gate-header" value={userHeader} onChange={(e) => setUserHeader(e.target.value)} /><p className="text-xs text-muted-foreground">应用要配置成信任这个请求头。</p></Field>}
        <Field label="不用登录的路径（每行一个，可以不填）" htmlFor="gate-skip">
          <Textarea id="gate-skip" value={skipPaths} onChange={(e) => setSkipPaths(e.target.value)} />
        </Field>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={trustInternal} onCheckedChange={(v) => setTrustInternal(v === true)} />从组网内访问不用登录</label>
        {trustInternal && <p className="text-xs text-muted-foreground">只有经组网地址或这台机器的内网访问入口时才算；从别的网络访问公网入口仍然要登录。</p>}
        </>}
        {protection === "gate" && route.spec.redirect && <p className="text-sm text-muted-foreground">跳转域名不支持门禁</p>}
        {route.spec.sso?.mode === "login" && (protection !== "gate" || gateMode !== "login") && <label className="flex items-center gap-2 text-sm"><Checkbox checked={dropLogin} onCheckedChange={(v) => setDropLogin(v === true)} />登录步骤会被删掉</label>}
        <DialogFooter>
          <Button variant="ghost" onClick={() => onClose()}>取消</Button>
          <Button disabled={saving || gateway?.spec.kind === "cloudflare_tunnel" || (protection === "gate" && !!route.spec.redirect) || (protection === "basic" && !authReady(user, password)) || (route.spec.sso?.mode === "login" && (protection !== "gate" || gateMode !== "login") && !dropLogin)} onClick={async () => {
            setSaving(true); setSaveError(null);
            try {
              if (protection === "basic") await saveAuth(route.spec.hostname, user, password);
              setPassword(""); onClose();
              actions.plan({ title: `修改 ${route.spec.hostname} 的访问保护`, changes: [{ op: "upsert_route", spec: { ...route.spec, auth: protection === "basic", sso: protection === "gate" ? { mode: gateMode, login: gateMode === "login" ? route.spec.sso?.login : undefined, header: gateMode === "header" ? userHeader : undefined, trust_internal: trustInternal, skip_paths: skipPaths.split("\n").map((p) => p.trim()).filter(Boolean) } : undefined } }] });
            } catch (e) { setSaveError(e); } finally { setSaving(false); }
          }}>预览改动</Button>
        </DialogFooter>
        <ErrorNote error={saveError} />
      </DialogContent>
    </Dialog>
  );
}
