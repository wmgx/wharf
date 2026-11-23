import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Empty, ErrorNote, SectionTitle } from "@/components/common";
import { Picker } from "@/components/fields";
import { Panel } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ServerView } from "@/types";
import type { ImagesView, UsageRow } from "@/types.gen";
import { size } from "./format";

type Sort = "cpu" | "mem" | "net";
const names = { service: "服务", gateway: "网关", agent: "agent" };
const numberCell = "text-right font-mono text-xs";
const amount = (value?: number | null, suffix = "") => value == null ? "-" : `${size(value)}${suffix}`;
const percent = (value?: number | null) => value == null ? "-" : `${value.toFixed(1)}%`;

export function ResourceTop({ servers }: { servers: ServerView[] }) {
  const [server, setServer] = useState("");
  const [sort, setSort] = useState<Sort>("cpu");
  const query = server ? `server=${encodeURIComponent(server)}` : "";
  const { data, error } = usePoll<UsageRow[]>(`/api/metrics/top?${query}`, 30000);
  const by = (row: UsageRow) => sort === "net"
    ? row.net_rx == null || row.net_tx == null ? -1 : row.net_rx + row.net_tx
    : row[sort] ?? -1;
  const rows = (data ?? []).slice().sort((a, b) => by(b) - by(a));
  const header = (label: string, key: Sort, announce = true) => (
    <TableHead className="text-right" aria-sort={announce && sort === key ? "descending" : undefined}>
      <Button size="sm" variant={sort === key ? "secondary" : "ghost"} onClick={() => setSort(key)}>{label}</Button>
    </TableHead>
  );
  return <>
    <SectionTitle action={<Picker value={server} placeholder="全部机器"
      options={[{ value: "", label: "全部机器" }, ...servers.map((s) => ({ value: s.name, label: s.name }))]}
      onChange={setServer} />}>服务</SectionTitle>
    {error ? <ErrorNote error={error} /> : !rows.length ? <Empty>{data ? "没有资源数据" : "读取中…"}</Empty> : (
      <Panel className="overflow-x-auto">
        <Table>
          <TableHeader><TableRow>
            <TableHead>名称</TableHead>
            <TableHead>种类</TableHead>
            <TableHead>机器</TableHead>
            {header("CPU", "cpu")}
            {header("内存", "mem")}
            <TableHead className="text-right">内存上限</TableHead>
            <TableHead className="text-right">占上限</TableHead>
            {header("网络收", "net")}
            {header("网络发", "net", false)}
          </TableRow></TableHeader>
          <TableBody>
            {rows.map((r) => <TableRow key={`${r.server}/${r.kind}/${r.name}`}>
              <TableCell className="font-medium">{r.name}</TableCell>
              <TableCell><Badge variant="secondary">{names[r.kind]}</Badge></TableCell>
              <TableCell>{r.server}</TableCell>
              <TableCell className={numberCell}>{percent(r.cpu)}</TableCell>
              <TableCell className={numberCell}>{amount(r.mem)}</TableCell>
              <TableCell className={numberCell}>{amount(r.memory_limit)}</TableCell>
              <TableCell className={numberCell}>{percent(r.memory_pct)}</TableCell>
              <TableCell className={numberCell}>{amount(r.net_rx, "/s")}</TableCell>
              <TableCell className={numberCell}>{amount(r.net_tx, "/s")}</TableCell>
            </TableRow>)}
          </TableBody>
        </Table>
      </Panel>
    )}
    <ImageTop />
  </>;
}

function ImageTop() {
  const { data, error, refresh } = usePoll<ImagesView>("/api/metrics/images", 60000);
  const { prune } = useActions();
  return <>
    <SectionTitle action={<Button variant="ghost" size="sm" onClick={refresh}>刷新</Button>}>镜像</SectionTitle>
    {error && <ErrorNote error={error} />}
    {Object.entries(data?.errors ?? {}).map(([server, reason]) => (
      <p className="mb-3 text-sm text-muted-foreground" key={server}>没查到：{server}（{reason}）</p>
    ))}
    {Object.entries(data?.unused ?? {}).map(([server, bytes]) => (
      <div className="mb-3 flex flex-wrap items-center gap-2" key={server}>
        <span className="text-xs text-muted-foreground">{server} · 没在用的镜像 {size(bytes)}</span>
        <Button variant="outline" size="sm" onClick={() => prune(server)}>清理</Button>
      </div>
    ))}
    {!data?.rows.length ? <Empty>{data ? "没有镜像数据" : "查询中…"}</Empty> : (
      <Panel className="overflow-x-auto">
        <Table>
          <TableHeader><TableRow>
            <TableHead>镜像</TableHead>
            <TableHead>机器</TableHead>
            <TableHead className="text-right">体积</TableHead>
            <TableHead>在用容器</TableHead>
          </TableRow></TableHeader>
          <TableBody>{data.rows.map((r) => <TableRow key={`${r.server}/${r.id}/${r.image}`}>
            <TableCell className="font-medium">{r.image}</TableCell>
            <TableCell>{r.server}</TableCell>
            <TableCell className={numberCell}>{size(r.size)}</TableCell>
            <TableCell>{r.used_by.length ? r.used_by.join("、") : "未用"}</TableCell>
          </TableRow>)}</TableBody>
        </Table>
      </Panel>
    )}
  </>;
}
