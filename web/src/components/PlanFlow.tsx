import { CheckIcon, CircleIcon, LoaderIcon, MinusIcon, XIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { cn } from "@/lib/utils";
import type { Change, Plan, PlanItem, Run, StepStatus } from "@/types";
import { ErrorNote, Notice } from "./common";

const ACTION: Record<PlanItem["action"], { text: string; cls: string }> = {
  create: { text: "新建", cls: "text-success" },
  update: { text: "修改", cls: "text-warning" },
  delete: { text: "删除", cls: "text-destructive" },
  adopt: { text: "接管", cls: "text-muted-foreground" },
};

const LAYER: Record<string, string> = {
  config: "配置",
  volume: "数据卷",
  container: "容器",
  gateway: "网关",
  dns: "DNS",
  tunnel: "隧道",
};

const RISK: Record<string, { text: string; cls: string }> = {
  disruptive: { text: "会短暂中断", cls: "bg-warning/10 text-warning" },
  destructive: { text: "破坏性", cls: "bg-destructive/10 text-destructive" },
  exposes_public: { text: "公网暴露", cls: "bg-primary/10 text-primary" },
};

type Stage = "planning" | "review" | "running" | "done";

/**
 * 页面上所有修改都走这里：提交修改 → 看计划 → 确认 → 看执行日志。
 * 和 CLI 是同一套 plan / apply。给了 `runId` 就直接接上一次已经开始的执行。
 */
export function PlanFlow({
  changes,
  runId,
  onStarted,
  onFinished,
}: {
  changes?: Change[];
  runId?: string;
  onStarted?: (runId: string) => void;
  onFinished?: (run: Run) => void;
}) {
  const [stage, setStage] = useState<Stage>(runId ? "running" : "planning");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (runId) {
      api.run(runId).then(setRun).catch(setError);
      return;
    }
    api
      .plan(changes ?? [])
      .then((p) => {
        setPlan(p);
        setStage("review");
      })
      .catch(setError);
  }, [changes, runId]);

  // 执行中每 800ms 取一次进度。
  useEffect(() => {
    if (!run) return;
    if (run.status !== "running") {
      setStage("done");
      return;
    }
    const t = setTimeout(async () => {
      try {
        const next = await api.run(run.run_id);
        setRun(next);
        if (next.status !== "running") onFinished?.(next);
      } catch (e) {
        setError(e);
      }
    }, 800);
    return () => clearTimeout(t);
  }, [run, onFinished]);

  const needs = plan?.needs_confirm ?? [];
  const allConfirmed = needs.every((a) => confirmed.has(a));

  const apply = async () => {
    if (!plan) return;
    setError(null);
    try {
      const { run_id } = await api.apply(plan.plan_id, needs);
      onStarted?.(run_id);
      setStage("running");
      setRun(await api.run(run_id));
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="grid gap-5">
      <Steps stage={stage} />
      {stage === "planning" && !error && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <LoaderIcon className="size-4 animate-spin" />
          正在对比配置和现实…
        </p>
      )}
      <ErrorNote error={error} />

      {plan && stage === "review" && <PlanReview plan={plan} confirmed={confirmed} setConfirmed={setConfirmed} />}
      {plan && stage === "review" && plan.items.length > 0 && (
        <div className="flex justify-end">
          <Button disabled={!allConfirmed} onClick={apply}>
            {needs.length ? "确认并执行" : "执行"}
          </Button>
        </div>
      )}

      {run && <RunView run={run} />}
      {run?.status === "running" && (
        <div>
          <Button variant="outline" size="sm" className="text-destructive" onClick={() => api.cancelRun(run.run_id).catch(setError)}>
            取消执行
          </Button>
        </div>
      )}
    </div>
  );
}

function Steps({ stage }: { stage: Stage }) {
  const order: Stage[] = ["planning", "review", "running"];
  const at = stage === "done" ? 3 : order.indexOf(stage);
  return (
    <ol className="flex gap-2 text-sm">
      {["计划", "确认", "执行"].map((label, i) => (
        <li key={label} className={cn("flex flex-1 items-center gap-2", i > at ? "text-muted-foreground" : "text-foreground", i === at && "font-medium")}>
          <span
            className={cn(
              "grid size-5 place-items-center rounded-full border text-[10px]",
              i < at && "border-success bg-success text-white",
              i === at && "border-primary text-primary",
            )}
          >
            {i < at ? <CheckIcon className="size-3" /> : i + 1}
          </span>
          {label}
          {i < 2 && <span className="h-px flex-1 bg-border" />}
        </li>
      ))}
    </ol>
  );
}

function PlanReview({ plan, confirmed, setConfirmed }: { plan: Plan; confirmed: Set<string>; setConfirmed: (s: Set<string>) => void }) {
  const needs = plan.needs_confirm ?? [];
  const toggle = (a: string) => {
    const next = new Set(confirmed);
    if (next.has(a)) next.delete(a);
    else next.add(a);
    setConfirmed(next);
  };
  return (
    <div className="grid gap-3">
      {plan.items.length === 0 ? (
        <Notice kind="ok">没有变化，现实和配置一致。</Notice>
      ) : (
        <div className="divide-y rounded-lg border">
          {plan.items.map((it) => (
            <div className="grid grid-cols-[44px_1fr_auto] items-center gap-3 px-3.5 py-2.5" key={it.id}>
              <span className={cn("text-xs font-medium", ACTION[it.action].cls)}>{ACTION[it.action].text}</span>
              <div className="min-w-0">
                <div className="truncate font-mono text-[13px]">
                  {it.address}
                  <span className="ml-2 font-sans text-xs text-muted-foreground">{LAYER[it.layer] ?? it.layer}</span>
                </div>
                <div className="text-xs text-muted-foreground">{it.reason}</div>
              </div>
              {it.risk !== "safe" && RISK[it.risk] && (
                <Badge variant="outline" className={cn("border-transparent", RISK[it.risk].cls)}>
                  {RISK[it.risk].text}
                </Badge>
              )}
            </div>
          ))}
        </div>
      )}
      {needs.length > 0 && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3.5">
          <div className="mb-2 text-sm font-medium">以下操作需要确认</div>
          <div className="grid gap-2">
            {needs.map((a) => (
              <label className="flex cursor-pointer items-center gap-2.5 text-sm" key={a}>
                <Checkbox checked={confirmed.has(a)} onCheckedChange={() => toggle(a)} />
                <span className="font-mono text-[13px]">{a}</span>
                <span className="text-xs text-muted-foreground">
                  {[...new Set(plan.items.filter((i) => i.address === a && i.risk !== "safe").map((i) => RISK[i.risk]?.text))]
                    .filter(Boolean)
                    .join("、")}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}
      <Warnings plan={plan} />
    </div>
  );
}

/** 和这次计划相关的提醒直接显示，其余的（plan 总是全量对比）折叠起来。 */
function Warnings({ plan }: { plan: Plan }) {
  const warnings = plan.warnings ?? [];
  const names = plan.items.map((i) => i.address.split("/").slice(1).join("/")).filter(Boolean);
  const related = warnings.filter((w) => names.some((n) => w.includes(n)));
  const others = warnings.filter((w) => !related.includes(w));
  return (
    <>
      {related.map((w) => (
        <Notice kind="warn" key={w}>
          {w}
        </Notice>
      ))}
      {others.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer select-none">其他提醒（{others.length}）</summary>
          <div className="mt-2 grid gap-2">
            {others.map((w) => (
              <Notice kind="warn" key={w}>
                {w}
              </Notice>
            ))}
          </div>
        </details>
      )}
    </>
  );
}

function StepIcon({ status }: { status: StepStatus }) {
  switch (status) {
    case "running":
      return <LoaderIcon className="size-4 animate-spin text-primary" />;
    case "done":
      return <CheckIcon className="size-4 text-success" />;
    case "failed":
      return <XIcon className="size-4 text-destructive" />;
    case "skipped":
      return <MinusIcon className="size-4 text-muted-foreground" />;
    default:
      return <CircleIcon className="size-3.5 text-muted-foreground/50" />;
  }
}

function RunView({ run }: { run: Run }) {
  return (
    <div className="grid gap-3">
      <div className="divide-y rounded-lg border">
        {run.steps.map((s, i) => (
          <div className="px-3.5 py-2.5" key={i}>
            <div className={cn("flex items-center gap-2.5 text-sm", (s.status === "pending" || s.status === "skipped") && "text-muted-foreground")}>
              <StepIcon status={s.status} />
              {s.title}
            </div>
            {!!s.log?.length && (
              <pre className="mt-2 ml-6.5 max-h-44 overflow-auto rounded-md border bg-muted/40 px-2.5 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all text-muted-foreground">
                {s.log.slice(-40).join("\n")}
              </pre>
            )}
            {s.error && (
              <div className="mt-2 ml-6.5">
                <ErrorNote error={{ message: s.error.message }} />
              </div>
            )}
          </div>
        ))}
      </div>
      {run.status === "succeeded" && <Notice kind="ok">执行成功。</Notice>}
      {run.status === "failed" && <Notice kind="bad">执行失败，已停止。配置已写入，修好问题后重新计划即可继续。</Notice>}
      {run.status === "cancelled" && <Notice>已取消。</Notice>}
    </div>
  );
}
