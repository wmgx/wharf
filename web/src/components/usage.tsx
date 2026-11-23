import { Panel } from "@/components/kit";
import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { ErrorNote, SectionTitle } from "@/components/common";
import { bytes } from "@/components/metrics";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

type Usage = {
  name: string;
  kind: "service" | "gateway" | "agent";
  cpu: number | null;
  mem: number | null;
  net_rx: number | null;
  net_tx: number | null;
};

/** 这台服务器上各服务最近 10 分钟的平均资源用量，按内存排。 */
export function ServiceUsage({ server }: { server: string }) {
  const { data, error } = usePoll<Usage[]>(
    `/api/metrics/usage?server=${encodeURIComponent(server)}`,
    60000,
  );
  if (error) return <ErrorNote error={error} />;
  if (!data?.length) return null;
  const maxMem = Math.max(...data.map((u) => u.mem ?? 0), 1);
  return (
    <div className="mt-6">
      <SectionTitle>各服务用量（最近 10 分钟平均）</SectionTitle>
      <Panel className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>服务</TableHead>
              <TableHead className="w-48">内存</TableHead>
              <TableHead className="text-right">CPU</TableHead>
              <TableHead className="text-right">网络 收 / 发</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((u) => (
              <TableRow key={`${u.kind}/${u.name}`}>
                <TableCell>
                  {u.kind === "service" ? (
                    <Link
                      className="text-primary hover:underline"
                      to={`/services/${encodeURIComponent(u.name)}`}
                    >
                      {u.name}
                    </Link>
                  ) : (
                    <span>
                      {u.name}{" "}
                      <span className="text-xs text-muted-foreground">
                        {u.kind === "gateway" ? "入口" : "agent"}
                      </span>
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${((u.mem ?? 0) / maxMem) * 100}%` }}
                      />
                    </div>
                    <span className="w-14 text-right font-mono text-xs tabular-nums">
                      {u.mem == null ? "-" : bytes(u.mem)}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="text-right font-mono text-xs tabular-nums">
                  {u.cpu == null ? "-" : `${u.cpu.toFixed(1)}%`}
                </TableCell>
                <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                  {u.net_rx == null || u.net_tx == null ? "-" : `${bytes(u.net_rx)}/s / ${bytes(u.net_tx)}/s`}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </div>
  );
}
