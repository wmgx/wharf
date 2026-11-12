import { ArrowRightIcon, InfoIcon, TriangleAlertIcon } from "lucide-react";
import { useActions } from "@/components/actions";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useStatus } from "@/status";
import { routeTone } from "./health";

/** 顶栏的"待处理"：点开看完整列表，提到的服务可以直接跳过去。 */
export function Problems() {
  const { status } = useStatus();
  const actions = useActions();
  const newer = Object.entries(status?.updates?.services ?? {})
    .filter(([, c]) => c.newer)
    .map(([name]) => name);
  const pending = status?.updates?.pending?.items ?? [];
  const notes = [...newer.map((n) => ({ text: `${n} 有新版本`, svc: n, run: () => actions.plan({ title: `更新 ${n}`, changes: [{ op: "refresh_images", name: n }] }) }))];
  if (pending.length) notes.push({ text: `有 ${pending.length} 项改动还没执行：${pending.slice(0, 3).join("、")}${pending.length > 3 ? " 等" : ""}`, svc: "", run: () => actions.plan({ title: "执行未完成的改动", changes: [] }) });
  const broken = (status?.health?.routes ?? []).flatMap((r) => {
    const t = routeTone(r);
    return t.tone === "bad" ? [`${r.hostname} 打不开：${t.detail ?? t.text}`] : [];
  });
  const problems = [...broken, ...(status?.problems ?? [])];
  if (!problems.length && !notes.length) return null;
  const services = status?.services.map((s) => s.name) ?? [];
  // 优先匹配更长的名字，避免 "hello" 抢走 "hello-api"。
  const mentioned = (p: string) => [...services].sort((a, b) => b.length - a.length).find((n) => new RegExp(`\\b${n}\\b`).test(p));

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 gap-1.5 bg-warning/10 text-warning hover:bg-warning/15 hover:text-warning">
          <TriangleAlertIcon />
          <span>{problems.length + notes.length}<span className="hidden sm:inline"> 项待处理</span></span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[min(24rem,calc(100vw-2rem))] p-0">
        <div className="border-b px-4 py-3 text-sm font-medium">待处理</div>
        <ul className="max-h-80 divide-y overflow-auto">
          {problems.map((p) => {
            const svc = mentioned(p);
            return (
              <li key={p} className="flex items-start gap-3 px-4 py-3 text-sm">
                <TriangleAlertIcon className="mt-0.5 size-4 shrink-0 text-warning" />
                <span className="flex-1 break-all">{p}</span>
                {svc && (
                  <Button asChild variant="ghost" size="icon-xs" aria-label={`打开 ${svc}`}>
                    <Link to={`/services/${svc}`}>
                      <ArrowRightIcon />
                    </Link>
                  </Button>
                )}
              </li>
            );
          })}
          {notes.map((n) => (
            <li key={n.text} className="flex items-start gap-3 px-4 py-3 text-sm">
              <InfoIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <span className="flex-1 break-all">{n.text}</span>
              <Button variant="outline" size="xs" onClick={n.run}>
                预览
              </Button>
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  );
}
