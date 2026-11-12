import { ago } from "@/components/common";
import type { DataKind, ImportRecord, ServiceStatus, ServiceView } from "@/types";

const ACTUAL: Record<ServiceStatus["actual"], string> = {
  running: "运行中",
  partial: "部分运行",
  stopped: "已停止",
  missing: "没有容器",
  offline: "服务器离线",
  unknown: "查不到",
};
const HEALTH: Record<ServiceStatus["health"], string> = {
  healthy: "健康",
  unhealthy: "不健康",
  starting: "启动中",
  none: "没配健康检查",
};
const OP: Record<NonNullable<ServiceStatus["last_op"]>["status"], string> = {
  running: "进行中",
  succeeded: "成功",
  failed: "失败",
};

/** 悬停时显示每一层。 */
export function statusLayers(s: ServiceStatus): string[] {
  const short = (h?: string) => h?.slice(0, 8) ?? "-";
  const op = s.last_op;
  return [
    `期望：${s.want_running ? "运行" : "停止"} · ${short(s.desired_hash)}`,
    `已应用：${s.applied ? `${short(s.applied.hash)} · ${ago(s.applied.at)}` : "没有版本"}`,
    `实际：${ACTUAL[s.actual]}${s.actual_hash ? ` · ${short(s.actual_hash)}` : ""}${s.observed_at ? ` · ${ago(s.observed_at)}看到` : ""}`,
    `健康：${HEALTH[s.health]}`,
    `执行：${op ? `${op.action}${OP[op.status]} · ${ago(op.at)}${op.error ? ` · ${op.error}` : ""}` : "-"}`,
  ];
}

export function importText(r: ImportRecord): string {
  const from =
    [
      r.project && `compose 项目 ${r.project}`,
      ...(r.containers ?? []).map((c) => `容器 ${c}`),
    ]
      .filter(Boolean)
      .join("、") || "同名 compose 项目";
  if (!r.done_at) return `${from} · 第一次部署时接管`;
  const retired = r.retired?.length
    ? ` · 旧容器 ${r.retired.join("、")} 已停止`
    : "";
  return `${from} · ${ago(r.done_at)}${retired}`;
}

export const DATA_KIND: Record<DataKind, string> = {
  managed: "Wharf 管理",
  external_dir: "外部目录",
  named_volume: "docker 卷",
};

export function dataSummary(svc: ServiceView): string {
  const data = svc.data ?? [];
  if (data.length === 0) return "没有数据卷";
  const outside = data.filter((m) => m.kind !== "managed").length;
  return outside
    ? `${data.length} 处挂载，${outside} 处不在备份范围`
    : `${data.length} 处挂载`;
}
