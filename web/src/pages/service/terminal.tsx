import { Suspense, lazy, useState } from "react";
import { Empty } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { ServiceView } from "@/types";

const Terminal = lazy(() => import("@/components/Terminal"));

export function TerminalTab({ svc }: { svc: ServiceView }) {
  const running = [
    ...new Set(
      (svc.containers ?? [])
        .filter((c) => c.state === "running")
        .map((c) => c.service),
    ),
  ];
  const [service, setService] = useState<string | undefined>(undefined);
  if (running.length === 0) return <Empty>没有在运行的容器</Empty>;
  const current = service && running.includes(service) ? service : running[0];
  return (
    <div className="grid gap-2">
      {running.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {running.map((s) => (
            <Button
              key={s}
              size="xs"
              variant={s === current ? "secondary" : "ghost"}
              onClick={() => setService(s)}
            >
              {s}
            </Button>
          ))}
        </div>
      )}
      <Suspense fallback={<Skeleton className="h-80 rounded-xl" />}>
        <Terminal name={svc.name} service={current} />
      </Suspense>
      <span className="text-xs text-muted-foreground">关掉页面后会话保留，30 分钟内回来接着用；输入 exit 结束会话。</span>
    </div>
  );
}
