import { ArrowUpRightIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { useActions } from "@/components/actions";
import { Empty } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import type { RouteView } from "@/types";

export const isShare = (r: RouteView) => r.spec.expires_at != null;
export const shareExpired = (r: RouteView) => (r.spec.expires_at ?? Infinity) <= Date.now();

const RENEW: [number, string][] = [[3600000, "1 小时"], [7200000, "2 小时"], [86400000, "1 天"], [604800000, "7 天"]];

const at = (ms: number) => new Date(ms).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });

/** 临时分享列表：有效的在前，已失效的标出来并给删除按钮。 */
export function ShareList({ routes, showService = false, empty, onProtect }: { routes: RouteView[]; showService?: boolean; empty: React.ReactNode; onProtect?: (r: RouteView) => void }) {
  const actions = useActions();
  if (!routes.length) return <Empty>{empty}</Empty>;
  const sorted = [...routes].sort((a, b) => Number(shareExpired(a)) - Number(shareExpired(b)) || (b.spec.expires_at ?? 0) - (a.spec.expires_at ?? 0));
  return <Rows limit={20}>{sorted.map((r) => {
    const expired = shareExpired(r);
    return <Row className="flex-wrap" key={r.id}>
      <a className={`inline-flex min-w-0 flex-1 items-center gap-1 font-mono text-sm hover:underline ${expired ? "text-muted-foreground line-through" : "text-primary"}`} href={r.url} target="_blank" rel="noreferrer">
        <span className="truncate">{r.url}</span><ArrowUpRightIcon className="size-3.5 shrink-0" />
      </a>
      {showService && <Link className="text-xs hover:underline" to={`/services/${encodeURIComponent(r.spec.service ?? "")}?tab=domains`}>{r.spec.service}</Link>}
      <span className="text-xs text-muted-foreground">{r.spec.auth ? "账号密码" : r.spec.sso ? "Wharf 登录" : "不保护"}</span>
      <span className={`text-xs ${expired ? "text-warning" : "text-muted-foreground"}`}>{expired ? "已失效" : `${at(r.spec.expires_at!)} 到期`}</span>
      {onProtect && !expired && <Button variant="outline" size="xs" onClick={() => onProtect(r)}>访问保护</Button>}
      <DropdownMenu>
        <DropdownMenuTrigger asChild><Button variant="outline" size="xs">续期</Button></DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {RENEW.map(([ms, label]) => <DropdownMenuItem key={ms} onSelect={() => actions.plan({ title: `续期 ${r.spec.hostname}`, changes: [{ op: "upsert_route", spec: { ...r.spec, expires_at: Date.now() + ms } }] })}>从现在起 {label}</DropdownMenuItem>)}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button variant="outline" size="xs" onClick={() => actions.removeRoute(r.spec.hostname)}>{expired ? "删除" : "停止分享"}</Button>
    </Row>;
  })}</Rows>;
}
