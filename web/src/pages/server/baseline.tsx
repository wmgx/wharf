import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { Notice } from "@/components/common";
import { Field, Segmented } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { ServerView } from "@/types";

type Baseline = {
  timezone?: string;
  swap_gb?: number;
  sysctl?: Record<string, string>;
  docker_log_size?: string;
  docker_log_files?: number;
  journal_max?: string;
  security_updates?: boolean;
};

const sysctlText = (m?: Record<string, string>) =>
  Object.entries(m ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

const parseSysctl = (text: string) =>
  Object.fromEntries(
    text
      .split("\n")
      .map((l) => l.split("="))
      .filter(([k, v]) => k?.trim() && v !== undefined)
      .map(([k, ...v]) => [k.trim(), v.join("=").trim()]),
  );

/** 机器基线：期望的时区、swap、内核参数、日志上限等，和实际不一致时 plan 纠正。 */
export function ServerBaseline({ server }: { server: ServerView }) {
  const actions = useActions();
  const cur = (server.settings.baseline ?? {}) as Baseline;
  const [timezone, setTimezone] = useState(cur.timezone ?? "");
  const [swap, setSwap] = useState(cur.swap_gb ? String(cur.swap_gb) : "");
  const [sysctl, setSysctl] = useState(sysctlText(cur.sysctl));
  const [logSize, setLogSize] = useState(cur.docker_log_size ?? "");
  const [logFiles, setLogFiles] = useState(cur.docker_log_files ? String(cur.docker_log_files) : "");
  const [journal, setJournal] = useState(cur.journal_max ?? "");
  const [updates, setUpdates] = useState<"" | "on" | "off">(cur.security_updates === undefined ? "" : cur.security_updates ? "on" : "off");
  const [checking, setChecking] = useState(false);
  const drift = server.baseline_drift ?? [];

  const swapNum = Number(swap.trim() || 0);
  const filesNum = Number(logFiles.trim() || 0);
  const valid = Number.isInteger(swapNum) && swapNum >= 0 && Number.isInteger(filesNum) && filesNum >= 0;
  const next: Baseline = {
    timezone: timezone.trim() || undefined,
    swap_gb: swapNum > 0 ? swapNum : undefined,
    sysctl: parseSysctl(sysctl),
    docker_log_size: logSize.trim() || undefined,
    docker_log_files: filesNum > 0 ? filesNum : undefined,
    journal_max: journal.trim() || undefined,
    security_updates: updates === "" ? undefined : updates === "on",
  };
  const norm = (b: Baseline) => JSON.stringify({ ...b, sysctl: b.sysctl ?? {} }, Object.keys(next).sort());
  const changed = norm(next) !== norm(cur);

  const check = async () => {
    setChecking(true);
    try {
      const r = await api.post<{ diffs: string[] }>(`/api/servers/${encodeURIComponent(server.name)}/baseline/check`, {});
      if (r.diffs.length) toast.warning(`${server.name} 有 ${r.diffs.length} 项和基线不一致`, { description: r.diffs.join("\n") });
      else toast.success(`${server.name} 符合基线`);
    } catch (e) {
      toast.error("检查失败", { description: (e as Error).message });
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="mb-6">
      {drift.length > 0 && (
        <Notice kind="warn" className="mb-3">
          和基线不一致：{drift.join("；")}。预览改动或下次 plan 会纠正。
        </Notice>
      )}
      <div className="grid max-w-2xl gap-4">
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="时区" htmlFor="bl-tz">
            <Input id="bl-tz" value={timezone} placeholder="不管" onChange={(e) => setTimezone(e.target.value)} />
          </Field>
          <Field label="swap（GB）" htmlFor="bl-swap" help="已有 swap 不改">
            <Input id="bl-swap" inputMode="numeric" value={swap} placeholder="不管" onChange={(e) => setSwap(e.target.value)} />
          </Field>
          <Field label="journald 上限" htmlFor="bl-journal">
            <Input id="bl-journal" value={journal} placeholder="例如 500M" onChange={(e) => setJournal(e.target.value)} />
          </Field>
          <Field label="容器日志单个文件" htmlFor="bl-logsize" help="只对新建的容器生效">
            <Input id="bl-logsize" value={logSize} placeholder="例如 20m" onChange={(e) => setLogSize(e.target.value)} />
          </Field>
          <Field label="容器日志保留个数" htmlFor="bl-logfiles">
            <Input id="bl-logfiles" inputMode="numeric" value={logFiles} placeholder="3" onChange={(e) => setLogFiles(e.target.value)} />
          </Field>
          <Field label="自动安全更新">
            <Segmented value={updates} options={[["", "不管"], ["on", "开"], ["off", "关"]]} onChange={setUpdates} />
          </Field>
        </div>
        <Field label="内核参数" htmlFor="bl-sysctl" help="每行 key=value，例如 net.ipv4.tcp_congestion_control=bbr">
          <Textarea id="bl-sysctl" rows={3} className="font-mono text-xs" value={sysctl} onChange={(e) => setSysctl(e.target.value)} />
        </Field>
        <div className="flex flex-wrap gap-2">
          <Button
            disabled={!changed || !valid}
            onClick={() =>
              actions.plan({
                title: `修改 ${server.name} 的基线`,
                changes: [{ op: "update_server", name: server.name, settings: { ...server.settings, baseline: next } }],
              })
            }
          >
            预览改动
          </Button>
          <Button variant="outline" disabled={checking || !server.online || !server.settings.baseline} onClick={check}>
            {checking ? "检查中…" : "立即检查"}
          </Button>
        </div>
      </div>
    </div>
  );
}
