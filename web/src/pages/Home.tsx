import { SearchIcon, Settings2Icon, TriangleAlertIcon, ArrowRightIcon, CheckIcon, PlusIcon } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { usePoll } from "@/api";
import { AddRoute } from "@/components/add-route";
import { CardsSkeleton, Dot, Empty, Mark, SectionTitle, useClickable, type Tone } from "@/components/common";
import { diagnosisOf, routeTone, serviceTruth } from "@/components/health";
import { issueCount, useIssues } from "@/components/issues";
import { Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { AccountView, BookmarkView, Status, TokenView } from "@/types";
import { edgeTone } from "./edge";
import { HomeBookmarks, bookmarkGroups } from "./home-bookmarks";

interface Item {
  name: string;
  url?: string;
  address?: string;
  detail: string;
  tone: Tone;
  text: string;
  search: string;
}

export function Home() {
  const { status } = useStatus();
  const issues = useIssues().filter((i) => i.level !== "info");
  const nav = useNavigate();
  const [query, setQuery] = useState("");
  const [adding, setAdding] = useState(false);
  const [bookmarksOpen, setBookmarksOpen] = useState(false);
  const bookmarks = status?.bookmarks ?? [];
  const filteredBookmarks = bookmarks.filter(({ spec }) => [spec.title, spec.url, spec.group ?? ""].some((v) => v.toLowerCase().includes(query.toLowerCase())));
  const items: Item[] = status ? [
    ...status.services.map((svc) => {
      const routes = status.routes.filter((r) => r.spec.service === svc.name);
      const addresses = Object.values(svc.addresses);
      const { tone, text, detail } = serviceTruth(svc, status);
      return { name: svc.name, url: routes[0]?.url, address: addresses[0], detail: `/services/${svc.name}`, tone, text: detail ? `${text} · ${detail}` : text, search: [svc.name, ...routes.map((r) => r.spec.hostname), ...addresses].join(" ").toLowerCase() };
    }),
    ...(status.edge_apps ?? []).map((app) => {
      const { tone, text } = edgeTone(app.live, app.drift);
      const url = app.spec.domains?.[0] ? `https://${app.spec.domains[0]}` : app.live?.url;
      return { name: app.name, url, detail: `/edge/${app.name}`, tone, text, search: [app.name, ...(app.spec.domains ?? []), app.live?.url ?? ""].join(" ").toLowerCase() };
    }),
  ].sort((a, b) => a.name.localeCompare(b.name)) : [];
  const filtered = items.filter((item) => item.search.includes(query.toLowerCase()));
  const go = (item: Item) => {
    const href = item.url ?? (item.address ? `http://${item.address}` : undefined);
    if (href) window.open(href, "_blank", "noreferrer");
    else nav(item.detail);
  };
  const count = issueCount(issues);
  const fault = issues.some((i) => i.level === "fault");
  return (
    <>
      <div className="flex items-center gap-2">
      <div className="relative min-w-0 max-w-md flex-1">
        <SearchIcon className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input autoFocus placeholder="找服务或网址" value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && filtered.length === 1) go(filtered[0]); }} className="pl-9" />
      </div>
      <Button variant="outline" onClick={() => setBookmarksOpen(true)}>管理书签</Button>
      </div>
      <HomeBookmarks open={bookmarksOpen} onClose={() => setBookmarksOpen(false)} />
      {count > 0 && <div className={`mt-4 flex items-center gap-3 rounded-xl border px-4 py-3 text-sm ${fault ? "border-destructive/30 bg-destructive/5" : "border-warning/30 bg-warning/5"}`}>
        <TriangleAlertIcon className={`size-4 shrink-0 ${fault ? "text-destructive" : "text-warning"}`} />
        <span className="min-w-0 flex-1 break-words">{count} 项待处理：{issues[0].title}{count > 1 ? " 等" : ""}</span>
        <Button variant="outline" size="sm" onClick={() => nav("/inbox")}>查看</Button>
      </div>}
      {status && <Onboarding status={status} onAdd={() => setAdding(true)} />}
      <AddRoute open={adding} onClose={() => setAdding(false)} />
      {!status ? <CardsSkeleton /> : items.length + bookmarks.length === 0 ? <Empty action={<Button onClick={() => nav("/services?new=1")}>部署服务</Button>}>还没有服务</Empty> : filtered.length + filteredBookmarks.length === 0 ? <Empty>没有叫这个名字的服务</Empty> : <>
        <CardGroup title="能从外网打开" items={filtered.filter((i) => i.url)} />
        <CardGroup title="只在内网" items={filtered.filter((i) => !i.url)} />
        <BookmarkCards bookmarks={filteredBookmarks} status={status} />
      </>}
    </>
  );
}

function BookmarkCards({ bookmarks, status }: { bookmarks: BookmarkView[]; status: Status }) {
  const clickable = useClickable();
  return bookmarkGroups(bookmarks).map(([group, items]) => <section key={group}>
    <SectionTitle count={items.length}>{group}</SectionTitle>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,220px),1fr))] gap-3">
      {items.map((b) => {
        let host = b.spec.url;
        let href: string | undefined;
        try { host = new URL(b.spec.url).hostname; href = b.spec.url; } catch { href = undefined; }
        const d = diagnosisOf(status, host);
        const truth = d && routeTone(d);
        return <div key={b.id} {...clickable({ href })} aria-disabled={!href} className="group flex cursor-pointer items-center gap-3 rounded-xl border bg-card p-3 shadow-xs hover:bg-accent/50">
          <Mark name={b.spec.title} url={href} />
          <div className="min-w-0 flex-1"><div className="truncate font-medium">{b.spec.title}</div><div className="truncate font-mono text-xs text-muted-foreground">{host}</div></div>
          {truth && <Tip text={truth.detail ?? truth.text}><span><Dot tone={truth.tone} /></span></Tip>}
        </div>;
      })}
    </div>
  </section>);
}

function CardGroup({ title, items }: { title: string; items: Item[] }) {
  const clickable = useClickable();
  const nav = useNavigate();
  if (!items.length) return null;
  return <>
    <SectionTitle count={items.length}>{title}</SectionTitle>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,220px),1fr))] gap-3">
      {items.map((item) => {
        const href = item.url ?? (item.address ? `http://${item.address}` : undefined);
        const link = clickable(href ? { href } : { to: item.detail });
        return <div key={item.detail} {...link} onKeyDown={(e) => { if (e.key.toLowerCase() === "m" && e.target === e.currentTarget) nav(item.detail); else link.onKeyDown(e); }} className="group flex cursor-pointer items-center gap-3 rounded-xl border bg-card p-3 shadow-xs hover:bg-accent/50">
          <Mark name={item.name} url={item.url} />
          <div className="min-w-0 flex-1"><div className="truncate font-medium">{item.name}</div><div className="truncate font-mono text-xs text-muted-foreground">{(item.url ?? item.address ?? "-").replace(/^https?:\/\//, "")}</div></div>
          <div className="flex flex-col items-end gap-1"><Tip text="管理"><Button variant="ghost" size="icon-xs" aria-label={`管理 ${item.name}`} className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100" onClick={(e) => { e.stopPropagation(); nav(item.detail); }}><Settings2Icon /></Button></Tip><Tip text={item.text}><span><Dot tone={item.tone} /></span></Tip></div>
        </div>;
      })}
    </div>
  </>;
}

/** 上手清单：按顺序做完就能用；全部做完后不再显示。 */
function Onboarding({ status, onAdd }: { status: Status; onAdd: () => void }) {
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
      go: onAdd,
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
    <Panel className="mt-4 mb-8 p-4">
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
    </Panel>
  );
}
