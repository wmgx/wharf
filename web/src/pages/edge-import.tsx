import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ErrorNote, Notice, ago } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import type { EdgeProjectView } from "@/types";
import { KIND_NAME } from "./edge";

/** 列出账号里的 Workers / Pages，一键导入。导入只纳管，不改 Cloudflare 那边的东西。 */
export function EdgeImport({ account, onClose }: { account: string; onClose: () => void }) {
  const { data, error } = usePoll<EdgeProjectView[]>(`/api/accounts/${encodeURIComponent(account)}/edge`, 60000);
  const actions = useActions();
  const [picked, setPicked] = useState<string[]>([]);
  const fresh = (data ?? []).filter((p) => !p.managed_as);
  const toggle = (p: string) => setPicked((s) => (s.includes(p) ? s.filter((x) => x !== p) : [...s, p]));
  const submit = () => {
    onClose();
    actions.plan({
      title: `导入 ${picked.length} 个边缘应用`,
      then: "/services",
      changes: fresh
        .filter((p) => picked.includes(p.project))
        .map((p) => ({ op: "upsert_edge_app", name: p.project, spec: { account, kind: p.kind } })),
    });
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{account} 的 Workers / Pages</DialogTitle>
          <DialogDescription>导入后在服务页统一查看、加域名、切换版本。导入不会改动 Cloudflare 上的项目。</DialogDescription>
        </DialogHeader>
        <ErrorNote error={error} />
        {!data ? (
          !error && <Skeleton className="h-32 rounded-lg" />
        ) : data.length === 0 ? (
          <Notice>这个账号里还没有 Workers 或 Pages 项目。</Notice>
        ) : (
          <div className="grid max-h-80 gap-1 overflow-auto">
            {data.map((p) => (
              <label key={`${p.kind}/${p.project}`} className={`flex items-center gap-3 rounded-md px-2 py-1.5 text-sm ${p.managed_as ? "text-muted-foreground" : "cursor-pointer hover:bg-muted"}`}>
                <Checkbox disabled={!!p.managed_as} checked={!!p.managed_as || picked.includes(p.project)} onCheckedChange={() => toggle(p.project)} />
                <Badge variant="secondary">{KIND_NAME[p.kind]}</Badge>
                <span className="min-w-0 flex-1 truncate font-mono">{p.project}</span>
                <span className="shrink-0 text-xs text-muted-foreground">{p.managed_as ? `已导入为 ${p.managed_as}` : p.modified_at ? ago(p.modified_at) : ""}</span>
              </label>
            ))}
          </div>
        )}
        <Notice>Worker 导入后，用 <code className="font-mono">wharf edge pull &lt;名字&gt;</code> 把脚本拉到本地，改完再发布。</Notice>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={picked.length === 0} onClick={submit}>
            导入 {picked.length || ""}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
