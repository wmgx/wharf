import { useState } from "react";
import { useActions } from "@/components/actions";
import { AuthFields, authReady, saveAuth } from "@/components/basic-auth";
import { toast } from "sonner";
import { EntryField, useEntry } from "@/components/entry";
import { DomainChips, Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";

/** 加域名。给了 service 就固定给它加；不给时先选服务（域名页用）。 */
export function AddRoute({ service: fixed, open, onClose }: { service?: string; open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const [hostname, setHostname] = useState("");
  const [picked, setPicked] = useState("");
  const service = fixed ?? picked;
  const server = status?.services.find((s) => s.name === service)?.spec.server ?? "";
  const entry = useEntry(server);
  const [authWanted, setAuth] = useState(false);
  const [tunnel, setTunnel] = useState(false);
  const auth = authWanted && !entry.tunnel;
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  const submit = async () => {
    const host = hostname.trim().toLowerCase();
    if (auth) {
      try {
        await saveAuth(host, user, password);
      } catch (e) {
        toast.error("登录账号没保存上", { description: (e as Error).message });
        return;
      }
    }
    setPassword("");
    onClose();
    setHostname("");
    setAuth(false);
    setTunnel(false);
    const { gateway, changes } = entry.resolve();
    actions.plan({
      title: "加域名",
      changes: [...changes, { op: "upsert_route", spec: { hostname: host, service, gateway, auth: auth || undefined, link: tunnel ? "tunnel" : undefined } }],
    });
  };
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>{fixed ? `给 ${fixed} 加域名` : "加域名"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          {!fixed && (
            <Field label="服务" htmlFor="route-service">
              <Picker
                id="route-service"
                value={picked}
                placeholder="选一个服务"
                options={(status?.services ?? []).map((s) => ({ value: s.name, label: s.name, hint: s.spec.server }))}
                onChange={setPicked}
              />
            </Field>
          )}
          <Field label="域名" htmlFor="hostname">
            <Input id="hostname" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="app.example.com" />
            {!hostname && service && <DomainChips suggestions={suffixes.map((s) => `${service}.${s}`)} onPick={setHostname} />}
          </Field>
          <EntryField entry={entry} />
          <label className={`flex items-center gap-2.5 text-sm ${entry.tunnel ? "text-muted-foreground" : "cursor-pointer"}`}>
            <Checkbox checked={auth} disabled={entry.tunnel} onCheckedChange={(v) => setAuth(v === true)} />
            登录保护
            <span className="text-xs text-muted-foreground">{entry.tunnel ? "隧道入口暂不支持" : "访问时要输入账号密码"}</span>
          </label>
          <label className="flex cursor-pointer items-center gap-2.5 text-sm">
            <Checkbox checked={tunnel} onCheckedChange={(v) => setTunnel(v === true)} />
            总是走反向隧道
            <span className="text-xs text-muted-foreground">默认自动：能直连就直连</span>
          </label>
          {auth && <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!service || !hostname.trim() || !entry.ready || (auth && !authReady(user, password))} onClick={submit}>
            预览改动
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

