import { useState } from "react";
import { api, usePoll } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { Field } from "@/components/fields";
import { Panel, Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { OidcView } from "@/types.gen";

export function Oidc() {
  const { data, error, refresh } = usePoll<OidcView>("/api/oidc", 30000);
  const [email, setEmail] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const value = email ?? data?.email ?? "";
  const save = async () => {
    setBusy(true); setFailure(null);
    try { await api.put("/api/oidc/settings", { email: value.trim() || null }); setEmail(null); refresh(); }
    catch (e) { setFailure(e); } finally { setBusy(false); }
  };
  return <>
    <div id="oidc"><SectionTitle count={data?.clients.length}>统一登录（OIDC）</SectionTitle></div>
    <ErrorNote error={error || failure} />
    {data && <Panel className="grid gap-3 p-4 text-sm">
      <div className="grid gap-1">
        <span className="text-muted-foreground">Issuer</span>
        <code className="break-all text-xs">{data.issuer ?? "不可用：控制面没有对外 https 地址"}</code>
      </div>
      {data.discovery && <div className="grid gap-1">
        <span className="text-muted-foreground">发现地址</span>
        <code className="break-all text-xs">{data.discovery}</code>
      </div>}
      <div className="text-muted-foreground">用户 {data.username}</div>
      <Field label="邮箱" htmlFor="oidc-email">
        <div className="flex gap-2">
          <Input id="oidc-email" type="email" value={value} placeholder="没设" onChange={(e) => setEmail(e.target.value)} />
          <Button variant="outline" disabled={busy || value === (data.email ?? "")} onClick={save}>{busy ? "保存中…" : "保存"}</Button>
        </div>
      </Field>
    </Panel>}
    {data && data.clients.length > 0 && <Rows>{data.clients.map((c) => <Row key={c.client_id}>
      <div className="min-w-0 flex-1 break-all">
        <div>{c.client_id}{c.public && <span className="ml-2 text-xs text-muted-foreground">公开站点</span>}</div>
        <code className="text-xs text-muted-foreground">{c.secret_ref}</code>
      </div>
    </Row>)}</Rows>}
  </>;
}
