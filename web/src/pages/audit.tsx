import { useEffect, useState } from "react";
import { api } from "@/api";
import { Empty, ErrorNote } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AuditEntry } from "@/types";

const LOGIN_ACTIONS: Record<string, string> = {
  login: "登录",
  login_failed: "登录失败",
  logout: "退出",
  setup: "初始化",
};

export function AuditLog() {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let active = true;
    api.get<AuditEntry[]>("/api/audit?limit=100").then((data) => {
      if (active) {
        setRows(data);
        setMore(data.length === 100);
      }
    }).catch((e) => active && setError(e)).finally(() => active && setLoading(false));
    return () => { active = false; };
  }, []);

  const earlier = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<AuditEntry[]>(`/api/audit?limit=100&before=${rows[rows.length - 1].id}`);
      setRows((current) => [...current, ...data]);
      setMore(data.length === 100);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid gap-3">
      <ErrorNote error={error} />
      {rows.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>发起人</TableHead>
              <TableHead>操作</TableHead>
              <TableHead>详情</TableHead>
              <TableHead>结果</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.id}>
                <TableCell className="whitespace-nowrap">{new Date(row.at).toLocaleString()}</TableCell>
                <TableCell>{row.actor}</TableCell>
                <TableCell>{row.kind === "api" ? `${row.method} ${row.path}` : LOGIN_ACTIONS[row.method]}</TableCell>
                <TableCell className="max-w-md whitespace-normal break-all">{row.kind === "login" ? row.source : row.detail}</TableCell>
                <TableCell>{row.kind === "api" ? row.status : ""}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : !loading && !error ? <Empty>还没有操作记录</Empty> : null}
      {more && <Button variant="outline" className="w-fit" disabled={loading} onClick={earlier}>更早</Button>}
    </div>
  );
}
