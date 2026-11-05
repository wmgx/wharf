import { DownloadIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { CodeBlock } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

interface AptStatus {
  state: "none" | "running" | "done" | "failed";
  log: string;
}

const STATE_TEXT: Record<AptStatus["state"], string> = { none: "", running: "正在安装…", done: "装完了", failed: "失败了" };

/** 装系统更新：宿主机上起独立的 systemd 单元跑 apt-get upgrade，这里轮询看进度。 */
export function AptUpgrade({ server, enabled, count, onDone }: { server: string; enabled: boolean; count: number; onDone: () => void }) {
  const [asking, setAsking] = useState(false);
  const [st, setSt] = useState<AptStatus | null>(null);
  const path = `/api/servers/${encodeURIComponent(server)}/apt`;

  useEffect(() => {
    if (!enabled) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const s = await api.get<AptStatus>(path);
        if (stop) return;
        setSt((prev) => {
          if (prev?.state === "running" && s.state !== "running") onDone();
          return s;
        });
        timer = setTimeout(tick, s.state === "running" ? 3000 : 30000);
      } catch {
        // docker 重启时 agent 会断一会儿，稍后再看。
        if (!stop) timer = setTimeout(tick, 5000);
      }
    };
    tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [enabled, path, onDone]);

  const start = async () => {
    setAsking(false);
    try {
      await api.post(path, {});
      setSt({ state: "running", log: "" });
    } catch (e) {
      toast.error("不能开始安装", { description: (e as Error).message });
    }
  };

  const running = st?.state === "running";
  return (
    <div className="mb-3 grid justify-items-start gap-2">
      {enabled ? (
        <Button size="sm" variant="outline" disabled={running || (count === 0 && !running)} onClick={() => setAsking(true)}>
          <DownloadIcon />
          {running ? "正在安装" : "安装更新"}
        </Button>
      ) : null}
      {st && st.state !== "none" && (
        <div className="grid w-full gap-1.5">
          <span className="text-xs text-muted-foreground">最近一次安装：{STATE_TEXT[st.state]}</span>
          {st.log && <CodeBlock className="max-h-64 overflow-auto text-xs">{st.log}</CodeBlock>}
        </div>
      )}
      <Dialog open={asking} onOpenChange={setAsking}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>在 {server} 上安装 {count} 个更新？</DialogTitle>
            <DialogDescription>
              执行 apt-get upgrade，不升级系统大版本、不重启机器。更新里有 docker 时，docker 会重启，这台机器上的服务会断几秒到几十秒。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAsking(false)}>
              取消
            </Button>
            <Button onClick={start}>安装</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
