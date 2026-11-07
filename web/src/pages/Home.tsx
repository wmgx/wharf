import { ArrowRightIcon, ArrowUpCircleIcon, CheckIcon, ChevronRightIcon, CloudIcon, LayoutGridIcon, ListIcon, PlusIcon } from "lucide-react";
import { useState, type CSSProperties } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CardsSkeleton, OpenLink, useClickable, Mark, PageHeader, SectionTitle, ServerTag, StatusBadge, type Tone } from "@/components/common";
import { serviceTruth } from "@/components/health";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import type { AccountView, Status, TokenView } from "@/types";
import { UnmanagedList } from "./containers";
import { EdgeList, edgeTone } from "./edge";
import { NewService } from "./NewService";
import { ServiceTable } from "./Services";
import { cn } from "@/lib/utils";

type View = "cards" | "list";
const VIEW_KEY = "wharf.home.view";
const savedView = (): View => {
  try {
    return localStorage.getItem(VIEW_KEY) === "list" ? "list" : "cards";
  } catch {
    return "cards";
  }
};

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
  newer?: boolean;
}

function itemsOf(status: Status): Item[] {
  const services: Item[] = status.services.map((s) => {
    const route = status.routes.find((r) => r.spec.service === s.name);
    const { tone, text } = serviceTruth(s, status);
    return { name: s.name, url: route?.url, address: Object.values(s.addresses)[0], detail: `/services/${s.name}`, where: s.spec.server, cloud: false, tone, text, newer: status.updates?.services[s.name]?.newer };
  });
  const edge: Item[] = (status.edge_apps ?? []).map((a) => {
    const { tone, text } = edgeTone(a.live, a.drift);
    const url = a.spec.domains?.[0] ? `https://${a.spec.domains[0]}` : a.live?.url;
    return { name: a.name, url, detail: `/edge/${a.name}`, where: "Cloudflare", cloud: true, tone, text };
  });
  return [...services, ...edge].sort((x, y) => x.name.localeCompare(y.name));
}

/** 首页：全部服务。默认卡片，可以切成列表、按服务器筛选；系统还没配完时顶部是上手清单。 */
export function Home() {
  const { status, refresh } = useStatus();
  const [params, setParams] = useSearchParams();
  const [view, setViewState] = useState<View>(savedView);
  const [server, setServer] = useState<string | undefined>(undefined);
  const setView = (v: View) => {
    setViewState(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      // 存不了就只在这次有效
    }
  };
  const items = (status ? itemsOf(status) : []).filter((i) => !server || (i.cloud ? server === "cloudflare" : i.where === server));
  const open = items.filter((i) => i.url);
  const internal = items.filter((i) => !i.url);
  const where = status ? [...status.servers.map((s) => s.name), ...(status.edge_apps?.length ? ["cloudflare"] : [])] : [];

  return (
    <>
      <PageHeader
        title="首页"
        description={status ? `${status.servers.length} 台服务器 · ${status.services.length + (status.edge_apps?.length ?? 0)} 个服务 · ${status.routes.length} 个域名` : "载入中…"}
        actions={
          <Button onClick={() => setParams({ new: "1" })}>
            <PlusIcon />
            新建服务
          </Button>
        }
      />
      {status && <Onboarding status={status} />}
      {status && <UpdatesBanner status={status} />}
      {status && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap items-center gap-1">
            {[undefined, ...where].map((w) => (
              <button
                key={w ?? "all"}
                type="button"
                onClick={() => setServer(w)}
                className={cn("rounded-md px-2.5 py-1 text-sm text-muted-foreground transition-colors hover:text-foreground", server === w && "bg-accent font-medium text-foreground")}
              >
                {w === undefined ? "全部" : w === "cloudflare" ? "Cloudflare" : w}
              </button>
            ))}
          </div>
          <div className="ml-auto flex rounded-md border bg-card p-0.5">
            <ViewButton on={view === "cards"} label="卡片" onClick={() => setView("cards")}>
              <LayoutGridIcon />
            </ViewButton>
            <ViewButton on={view === "list"} label="列表" onClick={() => setView("list")}>
              <ListIcon />
            </ViewButton>
          </div>
        </div>
      )}
      {!status ? (
        <CardsSkeleton />
      ) : view === "list" ? (
        <ServiceTable status={status} server={server} />
      ) : (
        <>
          {open.length > 0 && <SectionTitle count={open.length}>能从外网打开</SectionTitle>}
          <Cards items={open} />
          {internal.length > 0 && <SectionTitle count={internal.length}>只在内网</SectionTitle>}
          <Cards items={internal} />
        </>
      )}
      <UnmanagedList />
      <EdgeList />
      <NewService
        open={params.get("new") === "1"}
        onClose={() => {
          setParams({});
          refresh();
        }}
      />
    </>
  );
}

function ViewButton({ on, label, onClick, children }: { on: boolean; label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      aria-pressed={on}
      title={label}
      onClick={onClick}
      className={cn("grid size-7 place-items-center rounded text-muted-foreground [&_svg]:size-4 hover:text-foreground", on && "bg-accent text-foreground")}
    >
      {children}
    </button>
  );
}

/** 有服务出了新版本时，首页顶部一条横幅，一次预览全部更新。 */
function UpdatesBanner({ status }: { status: Status }) {
  const actions = useActions();
  const names = Object.entries(status.updates?.services ?? {})
    .filter(([n, c]) => c.newer && status.services.some((s) => s.name === n))
    .map(([n]) => n)
    .sort();
  if (!names.length) return null;
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-primary/30 bg-primary/5 px-4 py-3 text-sm">
      <ArrowUpCircleIcon className="size-4 text-primary" />
      <span className="flex-1">
        {names.length} 个服务有新版本：{names.join("、")}
      </span>
      <Button
        size="sm"
        onClick={() =>
          actions.plan({
            title: names.length === 1 ? `更新 ${names[0]}` : `更新 ${names.length} 个服务`,
            changes: names.map((name) => ({ op: "refresh_images", name })),
          })
        }
      >
        预览更新
      </Button>
    </div>
  );
}

function Cards({ items }: { items: Item[] }) {
  const clickable = useClickable();
  if (items.length === 0) return null;
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,260px),1fr))] gap-3">
      {items.map((it, i) => {
        const style = { animationDelay: `${i * 30}ms` } as CSSProperties;
        // 点卡片进详情；点地址才去打开服务本身。
        const shown = it.url ?? it.address;
        const body = (
          <>
            <div className="flex items-center gap-3">
              <Mark name={it.name} url={it.url} />
              <div className="min-w-0">
                <div className="font-semibold">{it.name}</div>
                <div className="flex min-w-0 font-mono text-xs text-muted-foreground">
                  {shown ? <OpenLink value={shown} label={shown.replace(/^https?:\/\//, "")} /> : "-"}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <StatusBadge tone={it.tone}>{it.text}</StatusBadge>
              {it.newer && (
                <span className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-1.5 py-0.5 text-xs font-medium text-primary">
                  <ArrowUpCircleIcon className="size-3" />
                  新版本
                </span>
              )}
              {it.cloud ? (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <CloudIcon className="size-3" />
                  Cloudflare
                </span>
              ) : (
                <ServerTag name={it.where} />
              )}
              <ChevronRightIcon className="ml-auto size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
            </div>
          </>
        );
        return (
          <div key={it.detail} className={`${card} cursor-pointer`} style={style} {...clickable({ to: it.detail })}>
            {body}
          </div>
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
      go: () => nav("/entries?new=1"),
    },
    {
      done: status.services.length + (status.edge_apps?.length ?? 0) > 0,
      title: "部署第一个服务",
      hint: "镜像、git 仓库或 compose 都行",
      action: "部署服务",
      go: () => nav("/?new=1"),
    },
    {
      done: status.routes.length > 0,
      title: "给它一个域名",
      hint: "证书和 DNS 自动配好",
      action: "加域名",
      go: () => nav("/entries"),
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
