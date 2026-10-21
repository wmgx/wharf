import { CloudIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/api";
import { SectionTitle, StatusBadge, type Tone } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { EdgeAppView, EdgeKind, EdgeLive, EdgeSource } from "@/types";

export const KIND_NAME: Record<EdgeKind, string> = { worker: "Worker", pages: "Pages" };

export function edgeTone(live?: EdgeLive): { tone: Tone; text: string } {
  if (!live) return { tone: "idle", text: "未读取" };
  if (live.error) return { tone: "bad", text: "读取失败" };
  if (!live.exists) return { tone: "warn", text: "未发布" };
  return { tone: "ok", text: "在线" };
}

export function edgeSourceLabel(source?: EdgeSource): string {
  if (!source) return "只纳管（在 Cloudflare 面板里改）";
  const where = source.git ? `${source.git.repo.replace(/^https:\/\//, "")} @ ${source.git.ref}` : "本机上传";
  if (source.script) return `${where} · ${source.script}`;
  if (source.build) return `${where} · ${source.build}`;
  return `${where} · wrangler`;
}

export const projectOf = (a: EdgeAppView) => a.spec.project ?? a.name;

/** 发起一次边缘应用的单步任务（重新发布、回滚），返回 run_id。 */
export async function edgeTask(path: string, body: object, what: string): Promise<string | null> {
  try {
    const { run_id } = await api.post<{ run_id: string }>(path, body);
    return run_id;
  } catch (e) {
    toast.error(`不能${what}`, { description: (e as Error).message });
    return null;
  }
}

/** 服务页下方的边缘应用列表。 */
export function EdgeList() {
  const { status } = useStatus();
  const nav = useNavigate();
  const apps = status?.edge_apps ?? [];
  if (apps.length === 0) return null;
  const routesOf = (name: string) => status?.routes.filter((r) => r.spec.service === name) ?? [];
  return (
    <section>
      <SectionTitle count={apps.length}>边缘应用</SectionTitle>
      <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="pl-4">名字</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>来源</TableHead>
              <TableHead>域名</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {apps.map((a) => {
              const { tone, text } = edgeTone(a.live);
              const routes = routesOf(a.name);
              return (
                <TableRow key={a.name} className="cursor-pointer" onClick={() => nav(`/edge/${a.name}`)}>
                  <TableCell className="pl-4 font-medium">
                    <span className="inline-flex items-center gap-1.5">
                      <CloudIcon className="size-3.5 text-muted-foreground" />
                      {a.name}
                    </span>
                  </TableCell>
                  <TableCell>
                    <StatusBadge tone={tone}>{text}</StatusBadge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">{KIND_NAME[a.spec.kind]}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{edgeSourceLabel(a.spec.source)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {routes.map((r) => (
                      <div key={r.id}>{r.spec.hostname}</div>
                    ))}
                    {routes.length === 0 && <span className="text-muted-foreground">{a.live?.url?.replace(/^https:\/\//, "") ?? "-"}</span>}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
