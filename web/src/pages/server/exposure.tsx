import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useStatus } from "@/status";
import { api } from "@/api";
import { Empty, ErrorNote, SectionTitle, StatusBadge, ago } from "@/components/common";
import { riskText } from "@/components/container-risk";
import { Row, Rows } from "@/components/kit";
import { Button } from "@/components/ui/button";
import type { ExposureView } from "@/types.gen";

const owners: Record<string, string> = { gateway: "入口", wharf: "Wharf", service: "服务", container: "容器", host: "宿主机程序", unknown: "未知" };
export function ServerExposure({ server }: { server: string }) {
  const base = `/api/servers/${encodeURIComponent(server)}/exposure`;
  const [data, setData] = useState<ExposureView | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const { refresh: refreshStatus } = useStatus();
  const load = useCallback(async (action?: string, body?: unknown) => {
    setBusy(true); setError(null);
    try {
      setData(action ? await api.post<ExposureView>(`${base}/${action}`, body ?? {}) : await api.get<ExposureView>(base));
      if (action) refreshStatus();
    } catch (e) { setError(e); } finally { setBusy(false); }
  }, [base, refreshStatus]);
  useEffect(() => { setData(null); load(); }, [load]);
  return <>
    <ErrorNote error={error} />
    {data?.outdated ? <Empty>agent 版本太旧，没有数据</Empty> : <>
      <div className="mb-3 flex flex-wrap items-center justify-end gap-2">
        {data?.checked_at && <span className="text-xs text-muted-foreground">检查于 {ago(new Date(data.checked_at).toISOString())}</span>}
        <Button variant="outline" size="sm" disabled={busy} onClick={() => load("refresh")}>{busy ? "检查中" : "重新检查"}</Button>
      </div>
      {!data?.checked_at ? <Empty>{busy ? "读取中" : "还没有检查过"}</Empty> : <>
        <SectionTitle>对公网开放的端口</SectionTitle>
        <p className="mb-3 text-xs text-muted-foreground">本机在监听的端口，云厂商的安全组可能挡掉其中一部分</p>
        {!data.ports.length ? <Empty>没有对公网开放的端口</Empty> : <Rows limit={10}>{data.ports.map((p) => <Row key={`${p.proto}/${p.port}/${p.addr}`} className={!p.expected && !p.acked ? "bg-warning/10" : undefined}>
          <span className="font-mono">{p.proto}/{p.port}</span>
          <span className="min-w-0 flex-1 break-all">{owners[p.owner]} · {p.name}</span>
          {p.expected ? <StatusBadge tone="idle">预期</StatusBadge> : <span className="flex items-center gap-2">
            {p.acked && <StatusBadge tone="idle">已确认</StatusBadge>}
            <Button size="xs" variant="outline" disabled={busy} onClick={() => load("ack", { port: `${p.proto}/${p.port}`, acked: !p.acked })}>{p.acked ? "取消确认" : "我知道"}</Button>
          </span>}
        </Row>)}</Rows>}
        <div className="mt-6"><SectionTitle>权限较大的容器</SectionTitle></div>
        {!data.risks.length ? <Empty>没有权限较大的容器</Empty> : <Rows limit={10}>{data.risks.map((r) => <Row key={r.container} className={r.own ? "text-muted-foreground" : undefined}>
          <span className="min-w-0 flex-1 break-all font-mono">{r.container}</span>
          {r.own ? <span>Wharf 自身</span> : r.service ? <Link className="text-primary hover:underline" to={`/services/${encodeURIComponent(r.service)}`}>{r.service}</Link> : <span>未纳管</span>}
          <span className="w-full break-words text-xs">{riskText(r.risks)}</span>
        </Row>)}</Rows>}
      </>}
    </>}
  </>;
}
