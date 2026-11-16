import { useState } from "react";
import { api, usePoll } from "@/api";
import { ErrorNote } from "@/components/common";
import { Button } from "@/components/ui/button";
import type { OidcSecretView, OidcView } from "@/types.gen";

export function OidcClient({ hostname }: { hostname: string }) {
  const { data } = usePoll<OidcView>("/api/oidc", 30000);
  const [copied, setCopied] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const client = data?.clients.find((c) => c.client_id === hostname);
  const copy = async () => {
    setFailure(null);
    try {
      const s = await api.get<OidcSecretView>(`/api/oidc/clients/${encodeURIComponent(hostname)}/secret`);
      await navigator.clipboard.writeText(s.client_secret);
      setCopied(true);
    } catch (e) { setFailure(e); }
  };
  if (!data || !client) return null;
  const rows: [string, string][] = [
    ["Issuer", data.issuer ?? "不可用"],
    ["Client ID", client.client_id],
    ["密钥引用", client.secret_ref],
    ...client.redirect_uris.map((u) => ["回调", u] as [string, string]),
  ];
  return <div className="grid gap-1">
    <div className="flex flex-wrap items-center gap-2"><span className="flex-1">用 Wharf 账号登录（OIDC）{client.public ? " · 公开站点" : ""}</span><Button size="sm" variant="outline" onClick={copy}>{copied ? "已复制密钥" : "复制密钥"}</Button></div>
    {rows.map(([k, v], i) => <div key={i} className="flex min-w-0 gap-2 text-xs"><span className="w-20 shrink-0 text-muted-foreground">{k}</span><code className="min-w-0 break-all">{v}</code></div>)}
    {!data.email && <span className="text-xs text-muted-foreground">邮箱没设</span>}
    <ErrorNote error={failure} />
  </div>;
}
