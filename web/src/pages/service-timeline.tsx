import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api";
import { Empty, ErrorNote } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Timeline } from "@/types";

const KINDS: Record<string, string> = {
  deploy: "部署", backup: "备份", task: "任务", heal: "自动重启", alert: "告警", op: "操作",
};

export function ServiceTimeline({ name }: { name: string }) {
  const [view, setView] = useState<Timeline>({ items: [], next_before: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const version = useRef(0);
  const path = `/api/services/${encodeURIComponent(name)}/timeline?limit=50`;

  useEffect(() => {
    const current = ++version.current;
    setView({ items: [], next_before: null });
    setLoading(true);
    setError(null);
    api.get<Timeline>(path).then((data) => {
      if (version.current === current) setView(data);
    }).catch((e) => {
      if (version.current === current) setError(e);
    }).finally(() => {
      if (version.current === current) setLoading(false);
    });
    return () => { version.current += 1; };
  }, [path]);

  const earlier = async () => {
    const current = version.current;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<Timeline>(`${path}&before=${view.next_before}`);
      if (version.current === current) {
        setView((previous) => ({ items: [...previous.items, ...data.items], next_before: data.next_before }));
      }
    } catch (e) {
      if (version.current === current) setError(e);
    } finally {
      if (version.current === current) setLoading(false);
    }
  };

  return (
    <div className="grid gap-3">
      <ErrorNote error={error} />
      {view.items.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead><TableHead>类型</TableHead><TableHead>标题</TableHead><TableHead>结果</TableHead><TableHead>发起人</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {view.items.map((item, index) => (
              <TableRow key={`${item.at}-${item.kind}-${index}`}>
                <TableCell className="whitespace-nowrap">{new Date(item.at).toLocaleString()}</TableCell>
                <TableCell>{KINDS[item.kind]}</TableCell>
                <TableCell>
                  {item.kind === "deploy" || item.kind === "backup" ? (
                    <Link className="hover:underline" to={`?tab=${item.kind === "deploy" ? "history" : "data"}`}>{item.title}</Link>
                  ) : item.title}
                </TableCell>
                <TableCell className={item.ok === true ? "text-success" : item.ok === false ? "text-destructive" : ""}>
                  {item.ok === true ? "成功" : item.ok === false ? "失败" : ""}
                </TableCell>
                <TableCell>{item.actor}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : !loading && !error ? <Empty>没有</Empty> : null}
      {view.next_before !== null && <Button variant="outline" className="w-fit" disabled={loading} onClick={earlier}>更早</Button>}
    </div>
  );
}
