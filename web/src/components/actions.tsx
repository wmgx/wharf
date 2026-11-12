import { ConfirmDialog } from "@/components/kit";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useStatus } from "@/status";
import type { Change, RollbackTarget, Run, ServiceView } from "@/types";
import { BasicAuthDialog } from "./basic-auth";
import { Picker, serverOptions } from "./fields";
import { PlanFlow } from "./PlanFlow";
import { upgradeWharf } from "./upgrade";

interface FlowRequest {
  title: string;
  changes: Change[];
  /** 执行成功后跳转到这里。 */
  then?: string;
  /** 执行前可以"返回修改"：关掉计划，回到这个地址（表单从草稿恢复）。 */
  back?: string;
}

export interface Actions {
  /** 打开计划面板：计划 → 确认 → 执行。 */
  plan: (req: FlowRequest) => void;
  redeploy: (svc: ServiceView) => void;
  /** 从代码构建的服务：按固定的 commit 重新构建并部署。 */
  rebuild: (name: string) => void;
  /** 升级服务器上的 agent 到控制面的版本。 */
  upgradeAgent: (server: string) => void;
  /** 停止（容器保留）或启动服务，走计划。 */
  setStopped: (svc: ServiceView, stopped: boolean) => void;
  /** 重启容器，不改配置。 */
  restart: (name: string) => void;
  /** 删除服务器上没在用的镜像和构建缓存。 */
  prune: (server: string) => void;
  /** 不给 `to` 就回到上一个不同的版本。 */
  rollback: (name: string, to?: number) => void;
  /** 先要求输入名称确认，再预览改动（连同它的域名）。 */
  remove: (name: string) => void;
  removeRoute: (hostname: string) => void;
  /** 选目标服务器，再预览改动。 */
  move: (svc: ServiceView) => void;
  /** 设置一个域名的登录保护账号；`enable` 时保存后预览开启登录保护的改动。 */
  basicAuth: (hostname: string, enable?: boolean) => void;
  /** 确认后升级控制面和全部 agent。 */
  upgrade: () => void;
  /** 打开一次已经开始的执行（备份、恢复），结束时提示。 */
  watch: (runId: string, title: string) => void;
  /** 只查看一次执行（活动页回看），不在后台盯。 */
  view: (runId: string, title: string) => void;
}

const Ctx = createContext<Actions | null>(null);

export function useActions(): Actions {
  const a = useContext(Ctx);
  if (!a) throw new Error("useActions 必须在 ActionsProvider 里使用");
  return a;
}

type Open = { key: number; title: string; changes?: Change[]; runId?: string; then?: string; back?: string };

export function ActionsProvider({ children }: { children: ReactNode }) {
  const { status, refresh } = useStatus();
  const nav = useNavigate();
  const [open, setOpen] = useState<Open | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [removingRoute, setRemovingRoute] = useState<string | null>(null);
  const [moving, setMoving] = useState<ServiceView | null>(null);
  const [settingAuth, setSettingAuth] = useState<{ hostname: string; enable: boolean } | null>(null);
  const [upgrading, setUpgrading] = useState(false);
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
    rebuild: async (name) => {
      try {
        const { run_id } = await api.post<{ run_id: string }>(`/api/services/${encodeURIComponent(name)}/rebuild`, {});
        actions.watch(run_id, `重新构建 ${name}`);
      } catch (e) {
        toast.error(`不能重新构建 ${name}`, { description: (e as Error).message });
      }
    },
    upgradeAgent: async (server) => {
      try {
        const { run_id } = await api.post<{ run_id: string }>(`/api/servers/${encodeURIComponent(server)}/upgrade`, {});
        actions.watch(run_id, `升级 ${server} 的 agent`);
      } catch (e) {
        toast.error(`不能升级 ${server} 的 agent`, { description: (e as Error).message });
      }
    },
    setStopped: (svc, stopped) =>
      actions.plan({
        title: `${stopped ? "停止" : "启动"} ${svc.name}`,
        changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, stopped: stopped || undefined } }],
      }),
    restart: async (name) => {
      try {
        const { run_id } = await api.post<{ run_id: string }>(`/api/services/${encodeURIComponent(name)}/restart`, {});
        actions.watch(run_id, `重启 ${name}`);
      } catch (e) {
        toast.error(`不能重启 ${name}`, { description: (e as Error).message });
      }
    },
    prune: async (server) => {
      try {
        const { run_id } = await api.post<{ run_id: string }>(`/api/servers/${encodeURIComponent(server)}/prune`, {});
        actions.watch(run_id, `清理 ${server} 上没在用的镜像`);
      } catch (e) {
        toast.error(`不能清理 ${server}`, { description: (e as Error).message });
      }
    },
    rollback: async (name, to) => {
      try {
        const q = to != null ? `?to=${to}` : "";
        const t = await api.get<RollbackTarget>(`/api/services/${encodeURIComponent(name)}/rollback${q}`);
        actions.plan({ title: `${name} 回到版本 #${t.deployment_id}`, changes: [{ op: "upsert_service", name, spec: t.spec }] });
      } catch (e) {
        toast.error(`不能回滚 ${name}`, { description: (e as Error).message });
      }
    },
    remove: (name) => setRemoving(name),
    removeRoute: (hostname) => setRemovingRoute(hostname),
    move: (svc) => setMoving(svc),
    basicAuth: (hostname, enable = false) => setSettingAuth({ hostname, enable }),
    upgrade: () => setUpgrading(true),
    watch: (runId, title) => {
      setOpen({ key: ++seq.current, title, runId });
      setRunning({ runId, title });
    },
    view: (runId, title) => setOpen({ key: ++seq.current, title, runId }),
  };

  const authSaved = () => {
    const s = settingAuth;
    setSettingAuth(null);
    const route = status?.routes.find((r) => r.spec.hostname === s?.hostname);
    if (!s || !route) return;
    if (s.enable && !route.spec.auth) {
      actions.plan({ title: `开启 ${s.hostname} 的登录保护`, changes: [{ op: "upsert_route", spec: { ...route.spec, auth: true } }] });
    } else if (route.spec.auth) {
      actions.plan({ title: `更新 ${s.hostname} 的登录账号`, changes: [] });
    }
  };

  const confirmMove = (svc: ServiceView, to: string) => {
    setMoving(null);
    actions.plan({
      title: `迁移 ${svc.name} 到 ${to}`,
      then: `/services/${svc.name}`,
      changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, server: to } }],
    });
  };

  const confirmRemove = (name: string, purge: boolean) => {
    const routes = status?.routes.filter((r) => r.spec.service === name) ?? [];
    setRemoving(null);
    actions.plan({
      title: purge ? `删除 ${name} 和它的数据` : `删除 ${name}`,
      then: "/services",
      changes: [...routes.map((r) => ({ op: "remove_route", hostname: r.spec.hostname }) as Change), { op: "remove_service", name, purge_data: purge || undefined }],
    });
  };

  return (
    <Ctx.Provider value={actions}>
      {children}
      <Sheet open={!!open} onOpenChange={(o) => !o && close()}>
        <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
          <SheetHeader className="border-b">
            <SheetTitle>{open?.title}</SheetTitle>
          </SheetHeader>
          <div className="flex-1 overflow-auto p-4">
            {open && (
              <PlanFlow
                key={open.key}
                changes={open.changes}
                runId={open.runId}
                onStarted={(runId) => setRunning({ runId, title: open.title })}
                onFinished={(run) => finished(run, open.title, open.then)}
                onBack={
                  open.back
                    ? () => {
                        const back = open.back!;
                        setOpen(null);
                        nav(back);
                      }
                    : undefined
                }
              />
            )}
          </div>
        </SheetContent>
      </Sheet>
      <ConfirmDialog open={!!removingRoute} title={`移除域名 ${removingRoute}？`} onCancel={() => setRemovingRoute(null)} onConfirm={() => { const hostname = removingRoute!; setRemovingRoute(null); actions.plan({ title: `移除 ${hostname}`, changes: [{ op: "remove_route", hostname }] }); }}>服务不受影响，DNS 记录和证书一起移除。</ConfirmDialog>
      <RemoveDialog name={removing} onCancel={() => setRemoving(null)} onConfirm={confirmRemove} />
      <MoveDialog svc={moving} onCancel={() => setMoving(null)} onConfirm={confirmMove} />
      <BasicAuthDialog hostname={settingAuth?.hostname ?? null} enable={!!settingAuth?.enable} onClose={() => setSettingAuth(null)} onSaved={authSaved} />
      <ConfirmDialog open={upgrading} title="升级 Wharf？" confirmText="升级" danger={false} onCancel={() => setUpgrading(false)} onConfirm={() => { setUpgrading(false); upgradeWharf(); }}>控制面会重启，页面断开一会儿。</ConfirmDialog>
    </Ctx.Provider>
  );
}

/** 删除前输入 `service/名称` 确认，和 CLI 的 `--confirm` 一样。 */
function RemoveDialog({ name, onCancel, onConfirm }: { name: string | null; onCancel: () => void; onConfirm: (name: string, purge: boolean) => void }) {
  const [typed, setTyped] = useState("");
  const [purge, setPurge] = useState(false);
  useEffect(() => {
    setTyped("");
    setPurge(false);
  }, [name]);
  const expect = `service/${name}`;
  return (
    <AlertDialog open={!!name} onOpenChange={(o) => !o && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>删除服务 {name}？</AlertDialogTitle>
          <AlertDialogDescription>
            会停止并删除它的容器，连同它的域名一起移除。输入 <code className="font-mono text-foreground">{expect}</code> 确认。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <label className="flex cursor-pointer items-start gap-2.5 text-sm">
          <Checkbox className="mt-0.5" checked={purge} onCheckedChange={(v) => setPurge(v === true)} />
          <span>
            连同数据一起删除
            <span className="block text-xs text-muted-foreground">
              {purge ? (
                <span className="text-destructive">/srv/{name} 目录和 compose 里声明的命名卷会被永久删除，不能恢复；外部目录不动。</span>
              ) : (
                "不勾选时数据保留在服务器上，以后重新部署同名服务还能接着用。"
              )}
            </span>
          </span>
        </label>
        <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={expect} className="font-mono" />
        <AlertDialogFooter>
          <AlertDialogCancel>取消</AlertDialogCancel>
          <AlertDialogAction
            disabled={typed.trim() !== expect}
            className="bg-destructive text-white hover:bg-destructive/90"
            onClick={() => name && onConfirm(name, purge)}
          >
            预览改动
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** 迁移：选目标服务器。数据同步、切网关、删旧容器都在计划里列出来。 */
function MoveDialog({ svc, onCancel, onConfirm }: { svc: ServiceView | null; onCancel: () => void; onConfirm: (svc: ServiceView, to: string) => void }) {
  const { status } = useStatus();
  const [to, setTo] = useState("");
  useEffect(() => setTo(""), [svc]);
  const options = serverOptions((status?.servers ?? []).filter((s) => s.joined && s.name !== svc?.spec.server));
  return (
    <Dialog open={!!svc} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>迁移 {svc?.name}</DialogTitle>
          <DialogDescription>
            从 {svc?.spec.server} 迁出，域名不变；有数据卷时会短暂停服，旧数据保留。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <Label htmlFor="move-to">目标服务器</Label>
          {options.length ? (
            <Picker id="move-to" value={to} options={options} onChange={setTo} placeholder="选择服务器…" />
          ) : (
            <p className="text-sm text-muted-foreground">没有其他已加入的服务器。</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            取消
          </Button>
          <Button disabled={!to} onClick={() => svc && onConfirm(svc, to)}>
            预览改动
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
