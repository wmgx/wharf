import { ArrowRightIcon, TriangleAlertIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useStatus } from "@/status";

/** 顶栏的"需要注意"：点开看完整列表，提到的服务可以直接跳过去。 */
export function Problems() {
  const { status } = useStatus();
  const problems = status?.problems ?? [];
  if (!problems.length) return null;
  const services = status?.services.map((s) => s.name) ?? [];
  // 优先匹配更长的名字，避免 "hello" 抢走 "hello-api"。
  const mentioned = (p: string) => [...services].sort((a, b) => b.length - a.length).find((n) => new RegExp(`\\b${n}\\b`).test(p));

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 gap-1.5 bg-warning/10 text-warning hover:bg-warning/15 hover:text-warning">
          <TriangleAlertIcon />
          {problems.length} 项需要注意
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 p-0">
        <div className="border-b px-4 py-3 text-sm font-medium">需要注意</div>
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
        </ul>
      </PopoverContent>
    </Popover>
  );
}
