import { ChevronRightIcon, RadarIcon } from "lucide-react";
import { Fragment, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/api";
import { Dot, MODES, SectionTitle, StatusBadge, ago, useClickable } from "@/components/common";
import { Panel, Tip } from "@/components/kit";
import { TailscaleDialog } from "@/components/tailscale-setup";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { NetworkView } from "@/types";
import { pairs, type Pair } from "./model";

const order = { bad: 0, warn: 1, idle: 2, ok: 3 };

export function PairTable({ items, server }: { items: Pair[]; server?: string }) {
  const [params] = useSearchParams();
  const clickable = useClickable();
  return <Panel>
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>
            {server ? "服务器" : "链路"}
          </TableHead>
          <TableHead>去</TableHead>
          <TableHead>回</TableHead>
          <TableHead>状态</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {[...items].sort((x, y) => order[x.tone] - order[y.tone]).map((p) => {
          const reverse = server === p.b;
          const from = reverse ? p.b : p.a;
          const to = reverse ? p.a : p.b;
          const forward = reverse ? p.ba : p.ab;
          const back = reverse ? p.ab : p.ba;
          const worst = order[p.ab.tone] <= order[p.ba.tone] ? p.ab : p.ba;
          const next = new URLSearchParams(params); next.set("link", `${p.a}~${p.b}`);
          return <Fragment key={`${p.a}-${p.b}`}>
            <TableRow className="cursor-pointer" {...clickable({ to: `?${next}` })}>
              <TableCell>
                {server ? to : `${p.a} ⇄ ${p.b}`}
              </TableCell>
              <TableCell>
                <Tip text={`${from} 连 ${to}`}>
                  <span className={forward.tone === "bad" ? "text-destructive" : forward.tone === "warn" ? "text-warning" : ""}>
                    {forward.text}
                  </span>
                </Tip>
              </TableCell>
              <TableCell>
                <Tip text={`${to} 连 ${from}`}>
                  <span className={back.tone === "bad" ? "text-destructive" : back.tone === "warn" ? "text-warning" : ""}>
                    {back.text}
                  </span>
                </Tip>
              </TableCell>
              <TableCell>
                <StatusBadge tone={p.tone}>
                  {p.tone === "ok" ? "正常" : worst.text}
                </StatusBadge>
              </TableCell>
              <TableCell>
                <ChevronRightIcon className="size-4" />
              </TableCell>
            </TableRow>
            {p.relay && <TableRow>
              <TableCell colSpan={5} className="text-xs text-muted-foreground">
                {p.relay}
              </TableCell>
            </TableRow>}
          </Fragment>;
        })}
      </TableBody>
    </Table>
  </Panel>;
}

export function Machines({ net, refresh }: { net: NetworkView; refresh: () => void }) {
  const [checking, setChecking] = useState(false);
  const [setup, setSetup] = useState(false);
  const clickable = useClickable();
  const all = pairs(net);
  const bad = all.filter((p) => p.tone === "bad");
  const warning = all.filter((p) => p.tone === "warn");
  const idle = all.filter((p) => p.tone === "idle");
  const descriptions = bad.flatMap((p) => [[p.a, p.b, p.ab], [p.b, p.a, p.ba]] as const).filter(([, , state]) => state.tone === "bad").slice(0, 2).map(([a, b, state]) => `${a} → ${b} ${state.text}`);
  const tone = bad.length ? "bad" : warning.length ? "warn" : idle.length || net.servers.length <= 1 ? "idle" : "ok";
  const text = net.servers.length <= 1 ? "只有一台机器" : bad.length ? `${bad.length} 条链路有问题：${descriptions.join("、")}` : warning.length ? `${warning.length} 条链路有丢包` : idle.length ? `还有 ${idle.length} 条链路没检查过` : `${net.servers.length} 台机器之间都能连通`;
  const latest = net.reach.map((r) => r.checked_at).sort().at(-1);
  const check = async () => { setChecking(true); try { await api.post("/api/network/probe", {}); refresh(); } catch { toast.error("检查失败"); } finally { setChecking(false); } };
  return <>
    <Panel className="flex flex-wrap items-center gap-3 p-4">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 text-base font-medium">
          <Dot tone={tone} />
          {text}
        </div>
        <div className="mt-1 text-sm text-muted-foreground">
          {latest ? `上次检查 ${ago(latest)}` : "还没检查过"}
        </div>
      </div>
      <Button variant="outline" size="sm" onClick={() => setSetup(true)}>组网设置</Button>
      <Button variant="outline" size="sm" disabled={checking} onClick={check}>
        <RadarIcon />
        {checking ? "检查中…" : "重新检查"}
      </Button>
    </Panel>
    <SectionTitle count={net.servers.length}>机器</SectionTitle>
    <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>服务器</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>接入方式</TableHead>
            <TableHead>内网地址</TableHead>
            <TableHead>公网 IP</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {net.servers.map((s) => <TableRow key={s.name} className="cursor-pointer" {...clickable({ to: `/servers/${encodeURIComponent(s.name)}?tab=network` })}>
            <TableCell className="font-medium">
              {s.name}
            </TableCell>
            <TableCell>
              <span className="inline-flex items-center gap-2">
                <Dot tone={s.online ? "ok" : "idle"} />
                {s.online ? "在线" : "离线"}
              </span>
            </TableCell>
            <TableCell>
              {MODES[s.mode]} {!s.configured && <span className="text-xs text-muted-foreground">自动</span>}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {s.private_ip ?? "-"}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {s.public_ip ?? "-"}
            </TableCell>
          </TableRow>)}
        </TableBody>
      </Table>
    </Panel>
    {all.length > 0 && <>
      <SectionTitle count={all.length}>链路</SectionTitle>
      <PairTable items={all} />
    </>}
    <TailscaleDialog open={setup} onClose={() => setSetup(false)} />
  </>;
}
