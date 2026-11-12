import { useState } from "react";
import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Notice } from "@/components/common";
import { Field, Picker, Segmented, serverOptions, toName } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { SheetFooter } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { AccountView, GatewaySpec, GatewayTls } from "@/types";

type GatewayKind = GatewaySpec["kind"];
const TLS_TEXT: Record<GatewayTls, string> = { auto: "自动签证书", internal: "自签证书", off: "只走 HTTP" };

export function NewGateway({ onDone }: { onDone: () => void }) {
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
      title: `新建入口 ${gwName}`,
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
          设为默认入口
        </label>
      </div>
      <SheetFooter className="flex-row justify-end border-t">
        <Button variant="ghost" onClick={onDone}>
          取消
        </Button>
        <Button disabled={!chosen || !gwName || (tunnel && !chosenAccount)} onClick={submit}>
          预览改动
        </Button>
      </SheetFooter>
    </>
  );
}
