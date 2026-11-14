import { HistoryIcon } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Empty, ServerTag, ago } from "@/components/common";
import { Segmented } from "@/components/fields";
import { Panel, Tip } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { DeploymentView } from "@/types";
import { ServiceTimeline } from "./timeline";

export function HistoryTab({ name }: { name: string }) {
  const [params, setParams] = useSearchParams();
  const show = params.get("show") === "versions" ? "versions" : "all";
  return <div className="grid gap-3"><Segmented value={show} options={[["all", "全部"], ["versions", "版本"]]} onChange={(v) => { const next = new URLSearchParams(params); if (v === "versions") next.set("show", v); else next.delete("show"); setParams(next, { replace: true }); }} />{show === "versions" ? <History name={name} /> : <ServiceTimeline name={name} />}</div>;
}

function History({ name }: { name: string }) {
  const { data } = usePoll<DeploymentView[]>(
    `/api/services/${encodeURIComponent(name)}/deployments`,
    15000,
  );
  const actions = useActions();
  if (!data) return <Skeleton className="h-40 rounded-xl" />;
  if (data.length === 0) return <Empty>没有版本</Empty>;
  return (
    <Panel>
      <Table>
        <TableHeader className="bg-muted/50">
          <TableRow>
            <TableHead className="pl-4">#</TableHead>
            <TableHead>时间</TableHead>
            <TableHead>服务器</TableHead>
            <TableHead>版本</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((d, i) => (
            <TableRow key={d.id}>
              <TableCell className="pl-4 font-mono text-xs">#{d.id}</TableCell>
              <TableCell>
                <Tip text={new Date(d.created_at).toLocaleString("zh-CN")}><span>
                  {ago(d.created_at)}
                </span></Tip>
              </TableCell>
              <TableCell>
                <ServerTag name={d.server} />
              </TableCell>
              <TableCell
                className="max-w-md truncate font-mono text-xs text-muted-foreground"
                title={[
                  d.commit,
                  ...d.images.map((im) => im.digest ?? im.image),
                ]
                  .filter(Boolean)
                  .join(" ")}
              >
                {d.commit && (
                  <span className="mr-2 text-foreground">
                    {d.commit.slice(0, 12)}
                  </span>
                )}
                {d.images.map((im) => im.digest ?? im.image).join(" ")}
              </TableCell>
              <TableCell className="pr-4 text-right">
                {i === 0 ? (
                  <Badge variant="secondary">当前版本</Badge>
                ) : d.hash === data[0].hash ? (
                  <span className="text-xs text-muted-foreground">
                    和当前相同
                  </span>
                ) : (
                  <Button
                    variant="outline"
                    size="xs"
                    disabled={!d.spec}
                    title={d.spec ? "" : "这条记录太早，没有保存当时的配置"}
                    onClick={() => actions.rollback(name, d.id)}
                  >
                    <HistoryIcon />
                    回到这个版本
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Panel>
  );
}
