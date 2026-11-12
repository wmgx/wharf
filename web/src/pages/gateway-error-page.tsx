import { useState } from "react";
import { useActions } from "@/components/actions";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import type { GatewayView } from "@/types";

export function GatewayErrorPage({ g }: { g: GatewayView }) {
  const actions = useActions();
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(g.spec.error_page ?? "");
  const save = (error_page: string | undefined) => {
    setOpen(false);
    actions.plan({
      title: `修改入口 ${g.name} 的错误页`,
      changes: [{ op: "upsert_gateway", name: g.name, spec: { ...g.spec, error_page } }],
    });
  };

  return (
    <>
      <span className="inline-flex items-center gap-2">
        {g.spec.error_page === undefined ? "默认" : "自定义"}
        <Button variant="ghost" size="xs" onClick={() => {
          setPage(g.spec.error_page ?? "");
          setOpen(true);
        }}>编辑</Button>
      </span>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>错误页</DialogTitle>
          </DialogHeader>
          <Textarea aria-label="错误页 HTML" className="min-h-64 font-mono text-xs" value={page} onChange={(e) => setPage(e.target.value)} />
          <DialogFooter>
            <Button variant="outline" onClick={() => save(undefined)}>换回默认</Button>
            <Button onClick={() => save(page)}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
