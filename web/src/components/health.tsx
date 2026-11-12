import { Tip } from "@/components/kit";
import type { CheckStatus, RouteDiagnosis, ServiceView, Status } from "@/types";
import { Dot, serviceTone, type Tone } from "./common";

export const LAYER: Record<string, string> = {
  dns: "解析",
  https: "HTTPS",
  gateway: "入口",
  link: "入口到服务",
  container: "容器",
};

const TONE: Record<CheckStatus, Tone> = { ok: "ok", warn: "warn", bad: "bad", skip: "idle" };

export function diagnosisOf(status: Status | null | undefined, hostname: string): RouteDiagnosis | undefined {
  return status?.health?.routes.find((r) => r.hostname === hostname);
}

/** 证书还剩几天，少于 14 天标黄。 */
export function CertDays({ d }: { d?: RouteDiagnosis }) {
  if (!d?.cert_expires) return null;
  const days = Math.floor((new Date(d.cert_expires).getTime() - Date.now()) / 86400000);
  return <span className={days < 14 ? "text-warning" : "text-muted-foreground"}>剩 {days} 天</span>;
}

/** 一个域名能不能打开：第一个不通的层就是原因。 */
export function routeTone(d?: RouteDiagnosis): { tone: Tone; text: string; detail?: string } {
  if (!d) return { tone: "idle", text: "还没检查" };
  const bad = d.checks.find((c) => c.status === "bad");
  if (bad) return { tone: "bad", text: `打不开 · ${LAYER[bad.layer] ?? bad.layer}`, detail: bad.detail };
  const warn = d.checks.find((c) => c.status === "warn");
  if (warn) return { tone: "warn", text: `能打开 · ${LAYER[warn.layer] ?? warn.layer}有提醒`, detail: warn.detail };
  return { tone: "ok", text: "能打开" };
}

/** 服务好不好：有域名时以域名能不能打开为准，没有域名时看容器。 */
export function serviceTruth(svc: ServiceView, status: Status | null | undefined): { tone: Tone; text: string; detail?: string } {
  const base = serviceTone(svc);
  const hosts = status?.routes.filter((r) => r.spec.service === svc.name).map((r) => r.spec.hostname) ?? [];
  for (const h of hosts) {
    const t = routeTone(diagnosisOf(status, h));
    if (t.tone === "bad") return { tone: "bad", text: hosts.length > 1 ? `${h} 打不开` : "打不开", detail: t.detail ?? undefined };
  }
  return base;
}

/** 检查灯：解析 → HTTPS → 入口 → 入口到服务 → 容器，悬停看每层的结果。 */
export function Lamps({ d }: { d?: RouteDiagnosis }) {
  if (!d) return <span className="text-xs text-muted-foreground">还没检查</span>;
  return (
    <span className="inline-flex items-center gap-1">
      {d.checks.map((c, i) => (
        <Tip key={`${c.layer}-${i}`} text={`${LAYER[c.layer] ?? c.layer} · ${c.subject}：${c.detail}`}>
          <span className="grid size-4 place-items-center"><Dot tone={TONE[c.status]} /></span>
        </Tip>
      ))}
    </span>
  );
}
