import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { Change, Plan, PlanItem, Run } from "../types";
import { ErrorNote, Light, type Tone } from "./ui";

const ACTION: Record<PlanItem["action"], string> = {
  create: "新建",
  update: "修改",
  delete: "删除",
  adopt: "接管",
};

const RISK: Record<string, string> = {
  disruptive: "会短暂中断",
  destructive: "破坏性",
  exposes_public: "公网暴露",
};

type Stage = "planning" | "review" | "running" | "done";

/**
 * 页面上所有修改都走这里：提交修改 → 看计划 → 确认 → 看执行日志。
 * 和 CLI 是同一套 plan / apply。
 */
export function PlanFlow({ changes, onFinished }: { changes: Change[]; onFinished?: (ok: boolean) => void }) {
  const [stage, setStage] = useState<Stage>("planning");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set());
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    api
      .plan(changes)
      .then((p) => {
        setPlan(p);
        setStage("review");
      })
      .catch(setError);
  }, [changes]);

  // 执行中每 800ms 取一次进度。
  useEffect(() => {
    if (!run || run.status !== "running") return;
    const t = setTimeout(async () => {
      try {
        const next = await api.run(run.run_id);
        setRun(next);
        if (next.status !== "running") {
          setStage("done");
          onFinished?.(next.status === "succeeded");
        }
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
      setStage("running");
      setRun(await api.run(run_id));
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div>
      <div className="steps">
        <span className={stage === "planning" ? "on" : "done"}>01 计划</span>
        <span className={stage === "review" ? "on" : stage === "planning" ? "" : "done"}>02 确认</span>
        <span className={stage === "running" ? "on" : stage === "done" ? "done" : ""}>03 执行</span>
      </div>

      {stage === "planning" && !error && <p style={{ color: "var(--ink-3)" }}>正在对比配置和现实…</p>}
      <ErrorNote error={error} />

      {plan && stage === "review" && <PlanReview plan={plan} confirmed={confirmed} setConfirmed={setConfirmed} />}

      {stage === "review" && plan && (
        <div style={{ marginTop: 20, display: "flex", gap: 10, justifyContent: "flex-end" }}>
          {plan.items.length > 0 && (
            <button className="btn primary" disabled={!allConfirmed} onClick={apply}>
              {needs.length ? "确认并执行" : "执行"}
            </button>
          )}
        </div>
      )}

      {run && <RunView run={run} />}
      {run && run.status === "running" && (
        <button className="btn danger small" onClick={() => api.cancelRun(run.run_id).catch(setError)}>
          取消执行
        </button>
      )}
    </div>
  );
}

function PlanReview({
  plan,
  confirmed,
  setConfirmed,
}: {
  plan: Plan;
  confirmed: Set<string>;
  setConfirmed: (s: Set<string>) => void;
}) {
  const needs = plan.needs_confirm ?? [];
  const toggle = (a: string) => {
    const next = new Set(confirmed);
    if (next.has(a)) next.delete(a);
    else next.add(a);
    setConfirmed(next);
  };
  return (
    <div>
      {plan.items.length === 0 ? (
        <div className="note good">没有变化，现实和配置一致。</div>
      ) : (
        plan.items.map((it) => (
          <div className="plan-item" key={it.id}>
            <span className={`act ${it.action}`}>{ACTION[it.action]}</span>
            <div>
              <div className="mono">{it.address}</div>
              <div style={{ fontSize: 12, color: "var(--ink-3)" }}>{it.reason}</div>
            </div>
            {it.risk !== "safe" && <span className={`risk ${it.risk}`}>{RISK[it.risk]}</span>}
          </div>
        ))
      )}
      {plan.warnings?.map((w) => (
        <div className="note" key={w}>
          {w}
        </div>
      ))}
      {needs.length > 0 && (
        <div className="confirm-box">
          <h4>这些操作需要你逐项确认</h4>
          {needs.map((a) => (
            <label className="check" key={a}>
              <input type="checkbox" checked={confirmed.has(a)} onChange={() => toggle(a)} />
              <span>
                <span className="mono">{a}</span>
                <span style={{ color: "var(--ink-3)", fontSize: 12, marginLeft: 8 }}>
                  {plan.items
                    .filter((i) => i.address === a && i.risk !== "safe")
                    .map((i) => RISK[i.risk])
                    .filter(Boolean)
                    .join("、")}
                </span>
              </span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

const STEP_TONE: Record<string, Tone> = {
  pending: "fog",
  running: "signal",
  done: "go",
  failed: "stop",
  skipped: "fog",
};

function RunView({ run }: { run: Run }) {
  return (
    <div style={{ marginTop: 8 }}>
      {run.steps.map((s, i) => (
        <div className="run-step" key={i}>
          <div className="title">
            <Light tone={STEP_TONE[s.status]} />
            <span style={{ color: s.status === "pending" || s.status === "skipped" ? "var(--ink-3)" : undefined }}>
              {s.title}
            </span>
          </div>
          {s.log.length > 0 && <div className="log">{s.log.slice(-40).join("\n")}</div>}
          {s.error && <ErrorNote error={{ message: s.error.message }} />}
        </div>
      ))}
      {run.status === "succeeded" && <div className="note good">执行成功。</div>}
      {run.status === "failed" && <div className="note bad">执行失败，已停止。配置已写入，修好问题后重新计划即可继续。</div>}
      {run.status === "cancelled" && <div className="note">已取消。</div>}
    </div>
  );
}
