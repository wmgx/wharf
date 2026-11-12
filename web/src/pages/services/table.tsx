import { ArrowUpCircleIcon, CloudIcon, LockIcon } from "lucide-react";
import { usePoll } from "@/api";
import { Dot, OpenLink, ServerTag, StatusBadge, ago, useClickable, type Tone } from "@/components/common";
import { serviceTruth } from "@/components/health";
import { Panel, Tip } from "@/components/kit";
import { OpMenu, serviceOps } from "@/components/ops";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { splitNote } from "@/lib/vault";
import type { DataView, ServiceData, ServiceView, Status } from "@/types";
import { edgeTone } from "../edge";

interface Row {
  name: string;
  to: string;
  where: string;
  domains: string[];
  address?: string;
  tone: Tone;
  text: string;
  svc?: ServiceView;
}

export function rowsOf(status: Status): Row[] {
  const routes = (name: string) => status.routes.filter((r) => r.spec.service === name).map((r) => r.spec.hostname);
  const services: Row[] = status.services.map((s) => {
    const { tone, text } = serviceTruth(s, status);
    return { name: s.name, to: `/services/${s.name}`, where: s.spec.server, domains: routes(s.name), address: Object.values(s.addresses)[0], tone, text, svc: s };
  });
  const edge: Row[] = (status.edge_apps ?? []).map((a) => {
    const { tone, text } = edgeTone(a.live, a.drift);
    const domains = a.spec.domains?.length ? a.spec.domains : a.live?.url ? [a.live.url.replace(/^https:\/\//, "")] : [];
    return { name: a.name, to: `/edge/${a.name}`, where: a.spec.kind === "worker" ? "Workers" : "Pages", domains, tone, text };
  });
  return [...services, ...edge].sort((x, y) => x.name.localeCompare(y.name));
}

export function ServiceTable({ status, rows }: { status: Status; rows: Row[] }) {
  const clickable = useClickable();
  const { data } = usePoll<DataView>("/api/data", 60000);
  const backup = (r: Row) => r.svc && data?.services.find((s) => s.name === r.name && s.server === r.where);
  return (
    <>
      <Panel className="hidden md:block">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="pl-4">服务</TableHead><TableHead>状态</TableHead><TableHead>所在</TableHead><TableHead>域名</TableHead><TableHead>备份</TableHead><TableHead className="w-12" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.to} className="cursor-pointer" {...clickable({ to: r.to })}>
                <TableCell className="pl-4 font-medium">
                  <span className="inline-flex items-center gap-1.5">{!r.svc && <CloudIcon className="size-3.5 text-muted-foreground" />}{r.name}</span>
                  {r.svc?.note && <NotePreview note={r.svc.note} />}
                </TableCell>
                <TableCell><StatusBadge tone={r.tone}>{r.text}</StatusBadge>{r.svc && status.updates?.services[r.name]?.newer && <span className="ml-1.5 inline-flex items-center gap-1 rounded-md bg-primary/10 px-1.5 py-0.5 text-xs font-medium text-primary"><ArrowUpCircleIcon className="size-3" />新版本</span>}</TableCell>
                <TableCell>{r.svc ? <ServerTag name={r.where} /> : r.where}</TableCell>
                <TableCell className="font-mono text-xs">
                  {r.domains.map((d) => <div key={d}><OpenLink value={d} /></div>)}
                  {r.domains.length === 0 && (r.address ? <OpenLink value={r.address} className="text-muted-foreground" /> : <span className="text-muted-foreground">-</span>)}
                </TableCell>
                <TableCell><BackupDot data={backup(r)} /></TableCell>
                <TableCell onClick={(e) => e.stopPropagation()}>{r.svc && <OpMenu ops={serviceOps} target={r.svc} label={`${r.svc.name} 的操作`} size="icon-sm" />}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      <div className="grid gap-2 md:hidden">
        {rows.map((r) => (
          <div key={r.to} className="cursor-pointer" {...clickable({ to: r.to })}>
            <Panel className="flex items-start gap-2 p-3">
              <div className="grid min-w-0 flex-1 gap-1.5">
                <div className="flex items-center gap-1.5 font-medium">{!r.svc && <CloudIcon className="size-3.5 text-muted-foreground" />}{r.name}</div>
                {r.svc?.note && <NotePreview note={r.svc.note} />}
                <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                  <StatusBadge tone={r.tone}>{r.text}</StatusBadge>
                  {r.svc && status.updates?.services[r.name]?.newer && <span className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-1.5 py-0.5 text-xs font-medium text-primary"><ArrowUpCircleIcon className="size-3" />新版本</span>}
                  {r.svc ? <ServerTag name={r.where} /> : <span>{r.where}</span>}
                  <BackupDot data={backup(r)} />
                </div>
                {(r.domains.length > 0 || r.address) && <div className="flex min-w-0 flex-wrap gap-x-2 font-mono text-xs text-muted-foreground">{(r.domains.length ? r.domains : [r.address!]).map((d) => <OpenLink key={d} value={d} />)}</div>}
              </div>
              <div onClick={(e) => e.stopPropagation()}>{r.svc && <OpMenu ops={serviceOps} target={r.svc} label={`${r.svc.name} 的操作`} size="icon-sm" />}</div>
            </Panel>
          </div>
        ))}
      </div>
    </>
  );
}

function BackupDot({ data }: { data?: ServiceData }) {
  if (!data || data.status === "none") return null;
  const tone = data.status === "ok" ? "ok" : data.status === "stale" ? "bad" : "warn";
  const text = data.status === "ok" ? `备份正常 · ${ago(data.last_ok)}` : data.status === "stale" ? "备份过期" : data.status === "off" ? "有数据但没开备份" : "有数据不在备份范围";
  return <Tip text={text}><span><Dot tone={tone} /></span></Tip>;
}

function NotePreview({ note }: { note: string }) {
  const { plain, sealed } = splitNote(note);
  return (
    <div className="flex max-w-56 items-center gap-1 text-xs font-normal text-muted-foreground" title={plain}>
      {sealed && <LockIcon className="size-3 shrink-0" />}
      <span className="truncate">{plain.split("\n")[0] || "私密备注"}</span>
    </div>
  );
}
