import { useSearchParams } from "react-router-dom";
import { Segmented } from "@/components/fields";
import { useStatus } from "@/status";
import { ServerTasks } from "./server-tasks";

/** 定时任务：所有服务器的任务，可以按服务器筛选（`?server=`）。 */
export function TasksPage() {
  const { status } = useStatus();
  const [params, setParams] = useSearchParams();
  const server = params.get("server") ?? "";
  const servers = (status?.servers ?? []).map((s) => s.name);
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">按 cron 时间在服务器上跑命令：进服务容器执行、起临时容器，或在宿主机上执行。</p>
        {servers.length > 1 && (
          <Segmented
            value={server}
            options={[["", "全部"], ...servers.map((s) => [s, s] as [string, string])]}
            onChange={(v) => setParams(v ? { server: v } : {}, { replace: true })}
          />
        )}
      </div>
      <ServerTasks server={server || undefined} />
    </>
  );
}
