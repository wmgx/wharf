import { useState } from "react";
import { toast } from "sonner";
import { useActions } from "@/components/actions";
import { AuthFields, authReady, saveAuth } from "@/components/basic-auth";
import { DomainChips, Field } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { RouteView } from "@/types";

export function AddAlias({ route, open, onClose }: { route: RouteView; open: boolean; onClose: () => void }) {
  const actions = useActions();
  const [hostname, setHostname] = useState("");
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const host = hostname.trim().toLowerCase();
  const original = route.spec.hostname;
  const submit = async () => {
    if (route.spec.auth) {
      try {
        await saveAuth(host, user, password);
      } catch (e) {
        toast.error("登录账号没保存上", { description: (e as Error).message });
        return;
      }
    }
    const { expires_at: _, ...rest } = route.spec;
    actions.plan({ title: `给 ${original} 加别名`, changes: [{ op: "upsert_route", spec: { ...rest, hostname: host } }] });
    onClose();
    setHostname("");
    setPassword("");
  };
  return <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
    <DialogContent aria-describedby={undefined}>
      <DialogHeader><DialogTitle>给 {original} 加别名</DialogTitle></DialogHeader>
      <div className="grid gap-4">
        <Field label="域名" htmlFor="alias-hostname">
          <Input id="alias-hostname" autoFocus value={hostname} onChange={(e) => setHostname(e.target.value)} />
          <DomainChips suggestions={[original.startsWith("www.") ? original.slice(4) : `www.${original}`]} onPick={setHostname} />
        </Field>
        {route.spec.auth && <AuthFields user={user} password={password} onUser={setUser} onPassword={setPassword} />}
      </div>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose}>取消</Button>
        <Button disabled={!host || host === original || (!!route.spec.auth && !authReady(user, password))} onClick={submit}>预览改动</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}
