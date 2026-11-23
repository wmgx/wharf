import { usePoll } from "@/api";
import { ErrorNote, SectionTitle, StatusBadge, ago } from "@/components/common";
import { Panel } from "@/components/kit";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ExternalStatus } from "@/types";

export function ExternalServices() {
  const { data, error } = usePoll<ExternalStatus[]>("/api/external", 60000);
  return <>
    <SectionTitle>外部服务</SectionTitle>
    <ErrorNote error={error} />
    {data && <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>名称</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>事件</TableHead>
            <TableHead>最后检查</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((service) => {
            const indicator = service.indicator;
            const tone = indicator === "major" || indicator === "critical" ? "bad"
              : indicator === "minor" || indicator === "maintenance" ? "warn"
              : indicator === "none" ? "ok" : "idle";
            return <TableRow key={service.name}>
              <TableCell className="font-medium">{service.name}</TableCell>
              <TableCell><StatusBadge tone={tone}>{service.description}</StatusBadge></TableCell>
              <TableCell>{service.incidents.length ? service.incidents.map((i) => <div key={i.url}>
                <a className="underline" href={i.url} target="_blank" rel="noreferrer">{i.name}</a>
              </div>) : "-"}</TableCell>
              <TableCell>{service.checked_at ? <span title={service.checked_at}>{ago(service.checked_at)}</span> : "-"}</TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>}
  </>;
}
