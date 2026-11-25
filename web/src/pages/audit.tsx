import { useEffect, useState } from "react";
import { api } from "@/api";
import { Empty, ErrorNote } from "@/components/common";
import { Panel } from "@/components/kit";
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
      setRows(data);
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
        <>
          <div className="hidden max-h-[65svh] overflow-y-auto md:block"><Table>
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
          </Table></div>
          <div className="grid max-h-[65svh] gap-2 overflow-y-auto md:hidden">
            {rows.map((row) => (
              <Panel key={row.id} className="grid gap-1 p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{row.actor}</span>
                  <span className="shrink-0 text-muted-foreground">{new Date(row.at).toLocaleString()}</span>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="min-w-0 break-all font-mono">{row.kind === "api" ? `${row.method} ${row.path}` : LOGIN_ACTIONS[row.method]}</span>
                  {row.kind === "api" && row.status != null && <span className="shrink-0 font-mono text-muted-foreground">{row.status}</span>}
                </div>
                {(row.kind === "login" ? row.source : row.detail) && (
                  <div className="break-all text-muted-foreground">{row.kind === "login" ? row.source : row.detail}</div>
                )}
              </Panel>
            ))}
          </div>
        </>
      ) : !loading && !error ? <Empty>还没有操作记录</Empty> : null}
      <div className="flex gap-2"><Button variant="outline" disabled={loading} onClick={() => { setLoading(true); setError(null); api.get<AuditEntry[]>("/api/audit?limit=100").then((data) => { setRows(data); setMore(data.length === 100); }).catch(setError).finally(() => setLoading(false)); }}>最新</Button>{more && <Button variant="outline" className="w-fit" disabled={loading} onClick={earlier}>更早</Button>}</div>
    </div>
  );
}
