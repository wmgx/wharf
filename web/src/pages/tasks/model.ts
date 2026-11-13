import type { Tone } from "@/components/common";
import type { TaskSpec, TaskStatus } from "@/types";

export const STATUS: Record<TaskStatus, [Tone, string]> = {
  running: ["warn", "运行中"], succeeded: ["ok", "成功"], failed: ["bad", "失败"], timed_out: ["bad", "超时"], skipped: ["idle", "跳过"],
};
export const KIND = { exec: "在服务里执行", container: "一次性容器", host: "宿主机命令", ping: "外部报到" } as const;

export function cronText(expr: string): string | null {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const [m, h, day, month, weekday] = fields;
  const number = /^\d+$/;
  const step = /^\*\/(\d+)$/;
  const pad = (value: string) => value.padStart(2, "0");
  if (step.test(m) && h === "*" && day === "*" && month === "*" && weekday === "*") return `每 ${m.slice(2)} 分钟`;
  if (!number.test(m) || Number(m) > 59 || month !== "*") return null;
  if (h === "*" && day === "*" && weekday === "*") return `每小时第 ${m} 分`;
  if (step.test(h) && day === "*" && weekday === "*") return `每 ${h.slice(2)} 小时`;
  if (!number.test(h) || Number(h) > 23) return null;
  const time = `${pad(h)}:${pad(m)}`;
  if (day === "*" && weekday === "*") return `每天 ${time}`;
  if (day === "*" && /^[0-7]$/.test(weekday)) return `每周${["日", "一", "二", "三", "四", "五", "六", "日"][Number(weekday)]} ${time}`;
  if (number.test(day) && Number(day) >= 1 && Number(day) <= 31 && weekday === "*") return `每月 ${day} 号 ${time}`;
  return null;
}

export function where(spec: TaskSpec): string {
  return spec.kind === "exec" ? `${spec.server} · ${spec.service}` : spec.server;
}
