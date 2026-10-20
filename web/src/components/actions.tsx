import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/api";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { Change, RollbackTarget, Run, ServiceView } from "@/types";
import { PlanFlow } from "./PlanFlow";

interface FlowRequest {
  title: string;
  changes: Change[];
  /** 执行成功后跳转到这里。 */
  then?: string;
}

interface Actions {
  /** 打开计划面板：计划 → 确认 → 执行。 */
  plan: (req: FlowRequest) => void;
  redeploy: (svc: ServiceView) => void;
  /** 不给 `to` 就回到上一个不同的版本。 */
  rollback: (name: string, to?: number) => void;
  /** 先要求输入名称确认，再生成删除计划（连同它的域名）。 */
  remove: (name: string) => void;
}

const Ctx = createContext<Actions | null>(null);

export function useActions(): Actions {
  const a = useContext(Ctx);
  if (!a) throw new Error("useActions 必须在 ActionsProvider 里使用");
  return a;
}

type Open = { key: number; title: string; changes?: Change[]; runId?: string; then?: string };

export function ActionsProvider({ children }: { children: ReactNode }) {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [open, setOpen] = useState<Open | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const seq = useRef(0);
  // 正在执行的那次：关掉面板后继续在后台盯着，结束时弹提示。
  // 用 state 而不是 ref：apply 的返回可能晚于关面板，拿到 run_id 时也要能开始盯。
  const [running, setRunning] = useState<{ runId: string; title: string } | null>(null);

  const finished = useCallback(
    (run: Run, title: string, then?: string) => {
      setRunning(null);
      refresh();
      const reopen = { label: "查看", onClick: () => setOpen({ key: ++seq.current, title, runId: run.run_id }) };
      if (run.status === "succeeded") {
        toast.success(`${title}：执行成功`);
        if (then) setTimeout(() => nav(then), 600);
      } else if (run.status === "failed") {
        const step = run.steps.find((s) => s.status === "failed");
        toast.error(`${title}：执行失败`, { description: step?.error?.message ?? step?.title, action: reopen, duration: 10000 });
      } else {
        toast(`${title}：已取消`);
      }
    },
    [nav, refresh],
  );

  const close = () => {
    setOpen(null);
    refresh();
  };

  // 面板关了但还在执行：后台每 1.5 秒查一次。
  useEffect(() => {
    if (open || !running) return;
    const { runId, title } = running;
    toast(`${title}：在后台继续执行`, { description: "完成后会在这里提示。" });
    let stop = false;
    const tick = async () => {
      if (stop) return;
      try {
        const run = await api.run(runId);
        if (run.status !== "running") return finished(run, title);
      } catch {
        // 网络抖动，下次再试。
      }
      setTimeout(tick, 1500);
    };
    tick();
    return () => {
      stop = true;
    };
  }, [open, running, finished]);

  const actions: Actions = {
    plan: (req) => setOpen({ key: ++seq.current, ...req }),
    redeploy: (svc) => actions.plan({ title: `重新部署 ${svc.name}`, changes: [{ op: "upsert_service", name: svc.name, spec: svc.spec }] }),
    rollback: async (name, to) => {
      try {
        const q = to != null ? `?to=${to}` : "";
        const t = await api.get<RollbackTarget>(`/api/services/${encodeURIComponent(name)}/rollback${q}`);
        actions.plan({ title: `回滚 ${name} 到 #${t.deployment_id}`, changes: [{ op: "upsert_service", name, spec: t.spec }] });
      } catch (e) {
        toast.error(`不能回滚 ${name}`, { description: (e as Error).message });
      }
    },
    remove: (name) => setRemoving(name),
  };

  const confirmRemove = (name: string) => {
    const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];
    setRemoving(null);
    actions.plan({
      title: `删除 ${name}`,
      then: "/services",
      changes: [...routes.map((r) => ({ op: "remove_route", hostname: r.spec.hostname }) as Change), { op: "remove_service", name }],
    });
  };

  return (
    <Ctx.Provider value={actions}>
      {children}
      <Sheet open={!!open} onOpenChange={(o) => !o && close()}>
        <SheetContent className="w-full gap-0 sm:max-w-xl">
          <SheetHeader className="border-b">
            <SheetTitle>{open?.title}</SheetTitle>
            <SheetDescription>和 CLI 是同一套计划：先看会做什么，确认后再执行。</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-auto p-4">
            {open && (
              <PlanFlow
                key={open.key}
                changes={open.changes}
                runId={open.runId}
                onStarted={(runId) => setRunning({ runId, title: open.title })}
                onFinished={(run) => finished(run, open.title, open.then)}
              />
            )}
          </div>
        </SheetContent>
      </Sheet>
      <RemoveDialog name={removing} onCancel={() => setRemoving(null)} onConfirm={confirmRemove} />
    </Ctx.Provider>
  );
}

/** 删除前输入 `service/名称` 确认，和 CLI 的 `--confirm` 一样。 */
function RemoveDialog({ name, onCancel, onConfirm }: { name: string | null; onCancel: () => void; onConfirm: (name: string) => void }) {
  const [typed, setTyped] = useState("");
  useEffect(() => setTyped(""), [name]);
  const expect = `service/${name}`;
  return (
    <AlertDialog open={!!name} onOpenChange={(o) => !o && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>删除服务 {name}？</AlertDialogTitle>
          <AlertDialogDescription>
            会停止并删除它的容器，连同它的域名一起移除。数据卷保留。输入 <code className="font-mono text-foreground">{expect}</code> 确认。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={expect} className="font-mono" />
        <AlertDialogFooter>
          <AlertDialogCancel>取消</AlertDialogCancel>
          <AlertDialogAction
            disabled={typed.trim() !== expect}
            className="bg-destructive text-white hover:bg-destructive/90"
            onClick={() => name && onConfirm(name)}
          >
            生成删除计划
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
