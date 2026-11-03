import { ArrowRightIcon, ArrowUpRightIcon, CheckIcon, CloudIcon, PlusIcon } from "lucide-react";
import type { CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { CardsSkeleton, CopyButton, Mark, PageHeader, SectionTitle, ServerTag, StatusBadge, type Tone } from "@/components/common";
import { serviceTruth } from "@/components/health";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import type { AccountView, Status, TokenView } from "@/types";
import { edgeTone } from "./edge";

const card =
  "group flex flex-col gap-3 rounded-xl border bg-card p-4 shadow-xs transition-all hover:-translate-y-px hover:border-foreground/15 hover:shadow-md animate-in fade-in slide-in-from-bottom-1 fill-mode-both";

/** 首页的一张卡片：一个服务（服务器上的或 Cloudflare 上的）。 */
interface Item {
  name: string;
  url?: string;
  address?: string;
  detail: string;
  where: string;
  cloud: boolean;
  tone: Tone;
  text: string;
}

function itemsOf(status: Status): Item[] {
  const services: Item[] = status.services.map((s) => {
    const route = status.routes.find((r) => r.spec.service === s.name);
    const { tone, text } = serviceTruth(s, status);
    return { name: s.name, url: route?.url, address: Object.values(s.addresses)[0], detail: `/services/${s.name}`, where: s.spec.server, cloud: false, tone, text };
  });
  const edge: Item[] = (status.edge_apps ?? []).map((a) => {
    const { tone, text } = edgeTone(a.live, a.drift);
    const url = a.spec.domains?.[0] ? `https://${a.spec.domains[0]}` : a.live?.url;
    return { name: a.name, url, detail: `/edge/${a.name}`, where: "Cloudflare", cloud: true, tone, text };
  });
  return [...services, ...edge].sort((x, y) => x.name.localeCompare(y.name));
}

/** 首页：每个服务一张卡片，点开就用；系统还没配完时顶部是上手清单。 */
export function Home() {
  const { status } = useStatus();
  const items = status ? itemsOf(status) : [];
  const open = items.filter((i) => i.url);
  const internal = items.filter((i) => !i.url);

  return (
    <>
      <PageHeader
        title="首页"
        description={status ? `${status.servers.length} 台服务器 · ${items.length} 个服务 · ${status.routes.length} 个域名` : "载入中…"}
      />
      {status && <Onboarding status={status} />}
      {!status ? (
        <CardsSkeleton />
      ) : (
        <>
          {open.length > 0 && <SectionTitle count={open.length}>能从外网打开</SectionTitle>}
          <Cards items={open} />
          {internal.length > 0 && <SectionTitle count={internal.length}>只在内网</SectionTitle>}
          <Cards items={internal} />
        </>
      )}
    </>
  );
}

function Cards({ items }: { items: Item[] }) {
  const nav = useNavigate();
  if (items.length === 0) return null;
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,260px),1fr))] gap-3">
      {items.map((it, i) => {
        const style = { animationDelay: `${i * 30}ms` } as CSSProperties;
        // 只在内网的服务点卡片直接打开内网地址。
        const href = it.url ?? (it.address ? `http://${it.address}` : undefined);
        const shown = it.url ? it.url.replace(/^https?:\/\//, "") : it.address;
        const body = (
          <>
            <div className="flex items-center gap-3">
              <Mark name={it.name} url={it.url} />
              <div className="min-w-0">
                <div className="font-semibold">{it.name}</div>
                <div className="flex min-w-0 items-center gap-0.5 font-mono text-xs text-muted-foreground">
                  <span className="truncate">{shown ?? "-"}</span>
                  {shown && <CopyButton text={shown} className="size-5 opacity-0 transition-opacity group-hover:opacity-100" />}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <StatusBadge tone={it.tone}>{it.text}</StatusBadge>
              {it.cloud ? (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <CloudIcon className="size-3" />
                  Cloudflare
                </span>
              ) : (
                <ServerTag name={it.where} />
              )}
              <span
                role="link"
                tabIndex={0}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  nav(it.detail);
                }}
                className="ml-auto cursor-pointer text-xs text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 hover:text-foreground"
              >
                详情
              </span>
              {href && <ArrowUpRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-primary" />}
            </div>
          </>
        );
        return href ? (
          <a key={it.detail} className={card} style={style} href={href} target="_blank" rel="noreferrer">
            {body}
          </a>
        ) : (
          <Link key={it.detail} className={card} style={style} to={it.detail}>
            {body}
          </Link>
        );
      })}
    </div>
  );
}

/** 上手清单：按顺序做完就能用；全部做完后不再显示。 */
function Onboarding({ status }: { status: Status }) {
  const nav = useNavigate();
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 60000);
  const { data: tokens } = usePoll<TokenView[]>("/api/tokens", 60000);
  if (!accounts || !tokens) return null;

  const steps: { done: boolean; title: string; hint: string; action: string; go: () => void }[] = [
    {
      done: status.servers.some((s) => s.online),
      title: "加一台服务器",
      hint: "在机器上执行一条命令，agent 连上后就能往上放服务",
      action: "加服务器",
      go: () => nav("/servers"),
    },
    {
      done: accounts.length > 0,
      title: "加 Cloudflare 账号",
      hint: "用来自动配 DNS 和隧道，加域名时不用手动去解析",
      action: "加账号",
      go: () => nav("/settings?add=account"),
    },
    {
      done: status.gateways.length > 0,
      title: "建一个入口",
      hint: "域名从哪进来：有公网 IP 的机器直连，或 Cloudflare 隧道",
      action: "新建入口",
      go: () => nav("/domains?tab=entries&new=1"),
    },
    {
      done: status.services.length + (status.edge_apps?.length ?? 0) > 0,
      title: "部署第一个服务",
      hint: "镜像、git 仓库或 compose 都行",
      action: "部署服务",
      go: () => nav("/services?new=1"),
    },
    {
      done: status.routes.length > 0,
      title: "给它一个域名",
      hint: "证书和 DNS 自动配好",
      action: "加域名",
      go: () => nav("/domains"),
    },
    {
      done: tokens.some((t) => !!t.last_used_at),
      title: "接入 CLI 或 AI",
      hint: "命令行和 AI 用同一套操作，先预览改动再执行",
      action: "去接入",
      go: () => nav("/settings"),
    },
  ];
  const left = steps.filter((s) => !s.done).length;
  if (left === 0) return null;
  const next = steps.findIndex((s) => !s.done);

  return (
    <section className="mb-8 rounded-xl border bg-card p-4 shadow-xs">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="font-medium">开始使用</h2>
        <span className="text-xs text-muted-foreground">还剩 {left} 步</span>
      </div>
      <ol className="grid gap-1">
        {steps.map((s, i) => (
          <li key={s.title} className={`flex items-center gap-3 rounded-lg px-2 py-2 ${i === next ? "bg-accent/60" : ""}`}>
            <span className={`grid size-5 shrink-0 place-items-center rounded-full border text-xs ${s.done ? "border-success bg-success text-background" : "text-muted-foreground"}`}>
              {s.done ? <CheckIcon className="size-3" /> : i + 1}
            </span>
            <div className="grid min-w-0 flex-1">
              <span className={`text-sm ${s.done ? "text-muted-foreground line-through" : "font-medium"}`}>{s.title}</span>
              {!s.done && <span className="truncate text-xs text-muted-foreground">{s.hint}</span>}
            </div>
            {!s.done && (
              <Button size="xs" variant={i === next ? "default" : "ghost"} onClick={s.go}>
                {i === next ? <PlusIcon /> : null}
                {s.action}
                {i !== next && <ArrowRightIcon />}
              </Button>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
