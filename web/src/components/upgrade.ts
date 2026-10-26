import { toast } from "sonner";
import { api } from "@/api";
import type { Run } from "@/types";

/** 刷新前记下新构建号，刷新后提示一次。 */
const UPGRADED_KEY = "wharf.upgraded";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitRun(runId: string): Promise<Run | null> {
  for (let i = 0; i < 200; i++) {
    await sleep(3000);
    const run = await api.run(runId).catch(() => null);
    if (run && run.status !== "running") return run;
  }
  return null;
}

/**
 * 一键升级：落后的 agent 先升到和控制面一致（控制面要靠同机的 agent 来换），
 * 再换控制面；新控制面起来后自己接着升级 agent，页面刷新加载新界面。
 */
export async function upgradeWharf() {
  const id = toast.loading("检查 agent 版本");
  try {
    const before = await api.get<{ build: string }>("/api/version");
    const { run_id } = await api.post<{ run_id: string | null }>("/api/servers/upgrade", {});
    if (run_id) {
      toast.loading("先升级落后的 agent", { id });
      const run = await waitRun(run_id);
      if (run?.status !== "succeeded") toast.warning("有 agent 没升级成功，继续升级控制面");
    }
    toast.loading("拉取新版控制面", { id });
    const r = await api.post<{ started: boolean }>("/api/upgrade", { then_agents: true });
    if (!r.started) {
      toast.success("已经是最新版本", { id, description: `构建 ${before.build}` });
      return;
    }
    toast.loading("控制面正在重启", { id });
    for (let i = 0; i < 60; i++) {
      await sleep(3000);
      const now = await api.get<{ build: string }>("/api/version").catch(() => null);
      if (now && now.build !== before.build) {
        try {
          sessionStorage.setItem(UPGRADED_KEY, now.build);
        } catch {
          // 存不了就不提示，不影响升级。
        }
        location.reload();
        return;
      }
    }
    toast.error("控制面没有换成新版本", { id, description: "接班容器会恢复旧的控制面" });
  } catch (e) {
    toast.error("升级失败", { id, description: (e as Error).message });
  }
}

/** 页面加载时调用：刚升级完就提示一次。 */
export function announceUpgrade() {
  let build: string | null = null;
  try {
    build = sessionStorage.getItem(UPGRADED_KEY);
    sessionStorage.removeItem(UPGRADED_KEY);
  } catch {
    return;
  }
  if (build) toast.success(`已升级到构建 ${build}`, { description: "agent 一分钟后逐台升级" });
}
