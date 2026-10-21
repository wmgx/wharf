import { CloudIcon, DownloadIcon } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { SectionTitle, StatusBadge, ago, type Tone } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useStatus } from "@/status";
import type { EdgeAppView, EdgeKind, EdgeLive, EdgeProjectView, EdgeSource } from "@/types";

export const KIND_NAME: Record<EdgeKind, string> = { worker: "Worker", pages: "Pages" };

export function edgeTone(live?: EdgeLive, drift?: string): { tone: Tone; text: string } {
  if (drift) return { tone: "warn", text: "有差异" };
  if (!live) return { tone: "idle", text: "同步中" };
  if (live.error) return { tone: "bad", text: "同步失败" };
  if (!live.exists) return { tone: "warn", text: "未发布" };
  return { tone: "ok", text: "在线" };
}

export function edgeSourceLabel(source?: EdgeSource): string {
  if (!source) return "Cloudflare 面板";
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

/** 服务页下方的边缘应用列表，后面跟着账号里还没纳管的项目。 */
export function EdgeList() {
  const { status } = useStatus();
  const nav = useNavigate();
  const actions = useActions();
  const apps = status?.edge_apps ?? [];
  const unmanaged = status?.edge_unmanaged ?? [];
  if (apps.length === 0 && unmanaged.length === 0) return null;
  const importOne = (p: EdgeProjectView) =>
    actions.plan({ title: `导入 ${p.project}`, changes: [{ op: "upsert_edge_app", name: p.project, spec: { account: p.account, kind: p.kind } }] });
  const routesOf = (name: string) => status?.routes.filter((r) => r.spec.service === name) ?? [];
  return (
    <section>
      <SectionTitle count={apps.length}>边缘应用（Cloudflare Workers / Pages）</SectionTitle>
      <div className="overflow-hidden rounded-xl border bg-card shadow-xs">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="pl-4">名字</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>来源</TableHead>
              <TableHead>域名</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {apps.map((a) => {
              const { tone, text } = edgeTone(a.live, a.drift);
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
                  <TableCell />
                </TableRow>
              );
            })}
            {unmanaged.map((p) => (
              <TableRow key={`${p.account}/${p.kind}/${p.project}`} className="text-muted-foreground">
                <TableCell className="pl-4">
                  <span className="inline-flex items-center gap-1.5">
                    <CloudIcon className="size-3.5" />
                    {p.project}
                  </span>
                </TableCell>
                <TableCell>
                  <StatusBadge tone="idle">未纳管</StatusBadge>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{KIND_NAME[p.kind]}</Badge>
                </TableCell>
                <TableCell className="text-xs">{p.modified_at ? `${ago(p.modified_at)}更新 · ${p.account}` : p.account}</TableCell>
                <TableCell className="font-mono text-xs">{p.url?.replace(/^https:\/\//, "") ?? "-"}</TableCell>
                <TableCell className="pr-4 text-right">
                  <Button variant="ghost" size="xs" onClick={() => importOne(p)}>
                    <DownloadIcon />
                    导入
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
