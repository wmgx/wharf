import { CheckIcon, MinusIcon, RadarIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { ago, CardsSkeleton, ErrorNote, PageHeader } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { NetworkMode, NetworkView } from "@/types";

const MODES: Record<NetworkMode, string> = { tailscale: "Tailscale", lan: "局域网", public: "公网" };

/** 组网：各机器怎么接入、谁能连谁的内网地址（design 2.10）。 */
export function Network() {
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

  return (
    <>
      <PageHeader
        title="组网"
        actions={
          <Button variant="outline" onClick={probe} disabled={probing}>
            <RadarIcon />
            {probing ? "探测中" : "探测"}
          </Button>
        }
      />
      <ErrorNote error={error} />
      {!data ? (
        <CardsSkeleton count={1} />
      ) : (
        <div className="flex flex-col gap-6">
          <div className="rounded-xl border bg-card shadow-xs">
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
                    <TableCell className="font-medium">{s.name}</TableCell>
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
          </div>

          <div className="flex flex-col gap-2">
            <h2 className="text-sm font-medium text-muted-foreground">谁能连谁（行 → 列）</h2>
            <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
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
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
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
      <span title="未探测" className="inline-flex text-muted-foreground">
        <MinusIcon className="size-4" />
      </span>
    );
  return r.ok ? (
    <span title={`通 · ${ago(r.checked_at)}`} className="inline-flex text-success">
      <CheckIcon className="size-4" />
    </span>
  ) : (
    <span title={`不通：${from} 不能迁移到 ${to}，也不能备份到 ${to} · ${ago(r.checked_at)}`} className="inline-flex text-destructive">
      <XIcon className="size-4" />
    </span>
  );
}
