import { Panel, Tip } from "@/components/kit";
import { CheckIcon, ChevronDownIcon, MinusIcon, RadarIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ago, CardsSkeleton, ErrorNote, MODES, SectionTitle } from "@/components/common";
import { TailscaleSetup } from "@/components/tailscale-setup";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { NetworkMode, NetworkView } from "@/types";

/** 接入方式：选"自动"时按检测到的地址推断。 */
export function ModeMenu({ server }: { server: NetworkView["servers"][number] }) {
  const actions = useActions();
  const choose = async (value: string) => {
    const mode = value === "auto" ? undefined : (value as NetworkMode);
    if (mode === (server.configured ? server.mode : undefined)) return;
    try {
      const v = await api.get<{ settings: Record<string, unknown> }>(`/api/servers/${encodeURIComponent(server.name)}`);
      const settings = { ...v.settings, network_mode: mode };
      actions.plan({
        title: `${server.name} 的接入方式改为${mode ? MODES[mode] : "自动"}`,
        changes: [{ op: "update_server", name: server.name, settings }],
      });
    } catch (e) {
      toast.error("读取服务器设置失败", { description: (e as Error).message });
    }
  };
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="xs" className="-ml-2">
          <Badge variant={server.mode === "public" ? "outline" : "secondary"}>{MODES[server.mode]}</Badge>
          {!server.configured && <span className="text-xs text-muted-foreground">自动</span>}
          <ChevronDownIcon className="size-3 text-muted-foreground" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-36">
        <DropdownMenuRadioGroup value={server.configured ? server.mode : "auto"} onValueChange={choose}>
          <DropdownMenuRadioItem value="auto">自动</DropdownMenuRadioItem>
          {(Object.keys(MODES) as NetworkMode[]).map((m) => (
            <DropdownMenuRadioItem key={m} value={m}>
              {MODES[m]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** 服务器页的"组网"标签：各机器怎么接入、谁能连谁的内网地址（design 2.10）。 */
export function NetworkPanel() {
  const { data, error, refresh } = usePoll<NetworkView>("/api/network", 30000);
  const [probing, setProbing] = useState(false);

  const probe = async () => {
    setProbing(true);
    try {
      await api.post<NetworkView>("/api/network/probe", {});
      refresh();
    } catch (e) {
      toast.error("探测失败", { description: (e as Error).message });
    } finally {
      setProbing(false);
    }
  };

  const reach = new Map(data?.reach.map((r) => [`${r.from}\u0000${r.to}`, r]));
  const names = data?.servers.map((s) => s.name) ?? [];
  const links = new Map(data?.links?.map((l) => [`${l.from}\u0000${l.to}`, l]));

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-end gap-3">
        <div className="flex items-center gap-2">
          <TailscaleSetup />
          <Button variant="outline" size="sm" onClick={probe} disabled={probing}>
            <RadarIcon />
            {probing ? "探测中" : "探测"}
          </Button>
        </div>
      </div>
      <ErrorNote error={error} />
      {!data ? (
        <CardsSkeleton count={1} />
      ) : (
        <div className="flex flex-col gap-6">
          <Panel>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>服务器</TableHead>
                  <TableHead>接入方式</TableHead>
                  <TableHead>内网地址</TableHead>
                  <TableHead>公网 IP</TableHead>
                  <TableHead>状态</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.servers.map((s) => (
                  <TableRow key={s.name}>
                    <TableCell className="font-medium">
                      <Link to={`/servers/${encodeURIComponent(s.name)}?tab=network`} className="hover:underline">
                        {s.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.mode === "public" ? "outline" : "secondary"}>{MODES[s.mode]}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{s.private_ip ?? "-"}</TableCell>
                    <TableCell className="font-mono text-xs">{s.public_ip ?? "-"}</TableCell>
                    <TableCell className={s.online ? "text-success" : "text-muted-foreground"}>{s.online ? "在线" : "离线"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>

          <div className="flex flex-col gap-2">
            <SectionTitle>连通和链路质量（行 → 列，每 5 分钟测一次）</SectionTitle>
            <Panel className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead />
                    {names.map((n) => (
                      <TableHead key={n} className="text-center">
                        {n}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {names.map((from) => (
                    <TableRow key={from}>
                      <TableCell className="font-medium">{from}</TableCell>
                      {names.map((to) => (
                        <TableCell key={to} className="text-center">
                          <Cell self={from === to} r={reach.get(`${from}\u0000${to}`)} from={from} to={to} />
                          <Quality l={links.get(`${from}\u0000${to}`)} />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Panel>
            {data.relays?.map((h) => (
              <p key={`${h.from}-${h.to}`} className="text-sm text-warning">
                {h.from} → {h.to} 直连丢包 {h.direct_loss.toFixed(0)}%，经 {h.via} 中转约 {h.via_loss.toFixed(0)}%
              </p>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function Cell({ self, r, from, to }: { self: boolean; r?: NetworkView["reach"][number]; from: string; to: string }) {
  if (self) return <span className="text-muted-foreground">·</span>;
  if (!r)
    return (
      <Tip text="未探测"><span className="inline-flex text-muted-foreground">
        <MinusIcon className="size-4" />
      </span></Tip>
    );
  if (r.stale)
    return (
      <Tip text={`${r.ok ? "通" : "不通"} · ${ago(r.checked_at)}，已过期`}><span className="inline-flex text-muted-foreground">
        {r.ok ? <CheckIcon className="size-4" /> : <XIcon className="size-4" />}
      </span></Tip>
    );
  return r.ok ? (
    <Tip text={`通 · ${ago(r.checked_at)}`}><span className="inline-flex text-success">
      <CheckIcon className="size-4" />
    </span></Tip>
  ) : (
    <Tip text={`不通：${from} 不能迁移到 ${to}，也不能备份到 ${to} · ${ago(r.checked_at)}`}><span className="inline-flex text-destructive">
      <XIcon className="size-4" />
    </span></Tip>
  );
}

export function Quality({ l }: { l?: NonNullable<NetworkView["links"]>[number] }) {
  if (!l) return null;
  const tone = l.loss >= 20 ? "text-destructive" : l.loss > 0 ? "text-warning" : "text-muted-foreground";
  return (
    <Tip text={`${ago(l.at)}测量`}><div className={`text-xs tabular-nums ${tone}`}>
      {l.ms === undefined ? "-" : `${l.ms.toFixed(0)}ms`}
      {l.loss > 0 && ` · ${l.loss.toFixed(0)}%`}
    </div></Tip>
  );
}
