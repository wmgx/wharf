import { ShieldAlertIcon } from "lucide-react";
import { Tip } from "@/components/kit";

const names: Record<string, string> = {
  privileged: "特权模式", docker_sock: "挂了 docker 套接字", host_root: "挂了宿主机根目录",
  host_sensitive: "挂了宿主机敏感目录", host_network: "host 网络", host_pid: "host 进程空间", cap_admin: "加了高危权限",
};
export const riskText = (risks: string[]) => risks.map((r) => names[r] ?? r).join("、");
export function ContainerRisk({ risks = [] }: { risks?: string[] }) {
  return risks.length ? <Tip text={riskText(risks)}><button type="button" aria-label={riskText(risks)} className="inline-flex shrink-0 text-warning" onClick={(e) => e.stopPropagation()}><ShieldAlertIcon className="size-4" /></button></Tip> : null;
}
