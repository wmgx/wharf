import { useState } from "react";
import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { useStatus } from "@/status";
import type { AccountView, Change } from "@/types";
import { Notice } from "./common";
import { Field, Picker } from "./fields";

/** 选项值：在服务所在的服务器上新建 Cloudflare 隧道网关。 */
const NEW_TUNNEL = "__new_tunnel__";

/**
 * 域名的公网入口：已有的网关，或者在服务所在服务器上新建一条 Cloudflare 隧道。
 * 新建隧道时，网关和路由放在同一个计划里。
 */
export function useEntry(server: string) {
  const { status } = useStatus();
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 60000);
  const [choice, setChoice] = useState("");
  const gateways = status?.gateways ?? [];
  const tunnelHere = gateways.some((g) => g.spec.kind === "cloudflare_tunnel" && g.spec.server === server);
  const account = accounts?.[0]?.name;

  const options = gateways.map((g) => ({
    value: g.name,
    label: g.name,
    hint: `${g.spec.kind === "cloudflare_tunnel" ? "Cloudflare 隧道" : "Caddy"} · ${g.spec.server}${g.spec.default ? " · 默认" : ""}`,
  }));
  if (server && !tunnelHere) {
    options.push({ value: NEW_TUNNEL, label: "Cloudflare 隧道（新建）", hint: `直接从 ${server} 出去，不需要公网 IP` });
  }
  const fallback = gateways.find((g) => g.spec.default)?.name ?? gateways[0]?.name ?? (server ? NEW_TUNNEL : "");
  const chosen = options.some((o) => o.value === choice) ? choice : fallback;
  const newTunnel = chosen === NEW_TUNNEL;
  const tunnel = newTunnel || gateways.find((g) => g.name === chosen)?.spec.kind === "cloudflare_tunnel";
  const tunnelName = gateways.some((g) => g.name === `${server}-tunnel`) ? `${server}-cf` : `${server}-tunnel`;

  return {
    options,
    chosen,
    setChoice,
    /** 隧道入口不支持登录保护。 */
    tunnel,
    needsAccount: newTunnel && accounts !== undefined && !account,
    ready: !!chosen && (!newTunnel || !!account),
    /** 路由用的网关名，以及需要一起提交的网关修改。 */
    resolve(): { gateway: string; changes: Change[] } {
      if (!newTunnel) return { gateway: chosen, changes: [] };
      return {
        gateway: tunnelName,
        changes: [{ op: "upsert_gateway", name: tunnelName, spec: { kind: "cloudflare_tunnel", server, account } }],
      };
    },
  };
}

export function EntryField({ entry }: { entry: ReturnType<typeof useEntry> }) {
  return (
    <>
      <Field
        label="公网入口"
        htmlFor="entry"
      >
        <Picker id="entry" value={entry.chosen} options={entry.options} onChange={entry.setChoice} placeholder="还没有网关" />
      </Field>
      {entry.needsAccount && (
        <Notice kind="warn">
          新建隧道需要 Cloudflare 账号。{" "}
          <Link to="/accounts" className="font-medium underline underline-offset-2">
            去添加厂商账号
          </Link>
        </Notice>
      )}
    </>
  );
}
