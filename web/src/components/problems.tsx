import { TriangleAlertIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { IssueRow, issueCount, useIssues } from "@/components/issues";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

export function Problems() {
  const issues = useIssues();
  if (!issues.length) return null;
  const count = issueCount(issues) || issues.length;
  const fault = issues.some((i) => i.level === "fault");
  const warn = issues.some((i) => i.level === "warn");
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className={`h-8 gap-1.5 ${fault ? "bg-destructive/10 text-destructive" : warn ? "bg-warning/10 text-warning" : "text-muted-foreground"}`}>
          <TriangleAlertIcon />
          <span>{count}<span className="hidden sm:inline"> 项待处理</span></span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[min(24rem,calc(100vw-2rem))] p-0">
        <div className="border-b px-4 py-3 text-sm font-medium">待处理</div>
        <div className="max-h-80 divide-y overflow-auto">{issues.slice(0, 6).map((i, index) => <IssueRow key={`${i.code}-${i.subject?.name ?? ""}-${index}`} issue={i} />)}</div>
        <div className="border-t p-3 text-right"><Button asChild variant="ghost" size="sm"><Link to="/inbox">全部 {issues.length} 项</Link></Button></div>
      </PopoverContent>
    </Popover>
  );
}
