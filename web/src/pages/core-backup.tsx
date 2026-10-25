import { ArchiveIcon, DownloadIcon, PlayIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { ago, CodeBlock, ErrorNote, Notice, SectionTitle, StatusBadge } from "@/components/common";
import { Field, Picker, serverOptions } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { CoreBackupView } from "@/types";

/** 控制面自身备份（design 2.11）：登录密码是恢复口令。 */
export function CoreBackup() {
  const { data, error, refresh } = usePoll<CoreBackupView>("/api/core-backup", 30000);
  const actions = useActions();
  const [asking, setAsking] = useState<"enable" | "key" | null>(null);
  const last = data?.records[0];

  const runNow = async () => {
    try {
      const { run_id } = await api.post<{ run_id: string }>("/api/core-backup/run", {});
      actions.watch(run_id, "备份控制面");
    } catch (e) {
      toast.error("没能开始备份", { description: (e as Error).message });
    }
  };

  return (
    <>
      <SectionTitle>控制面备份</SectionTitle>
      <ErrorNote error={error} />
      {data && (
        <div className="flex flex-col gap-3 rounded-xl border bg-card p-4 shadow-xs">
          <div className="flex flex-wrap items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg border bg-muted text-muted-foreground">
              <ArchiveIcon className="size-4" />
            </span>
            <div className="min-w-0">
              <div className="font-semibold">{data.to ? `每天备份到 ${data.to}` : "没有开启"}</div>
              {last && (
                <div className="text-xs text-muted-foreground">
                  上次 {ago(last.created_at)} · {last.ok ? "成功" : last.error}
                </div>
              )}
            </div>
            {last && <StatusBadge tone={last.ok ? "ok" : "bad"}>{last.ok ? "正常" : "失败"}</StatusBadge>}
            <div className="ml-auto flex gap-1">
              {data.to && (
                <Button variant="ghost" size="sm" onClick={runNow}>
                  <PlayIcon />
                  立即备份
                </Button>
              )}
              {data.to && (
                <Button variant="ghost" size="sm" onClick={() => setAsking("key")}>
                  <DownloadIcon />
                  恢复密钥
                </Button>
              )}
              <Button variant={data.to ? "ghost" : "default"} size="sm" onClick={() => setAsking("enable")}>
                {data.to ? "设置" : "开启"}
              </Button>
            </div>
          </div>
          {data.to && !data.user_key_current && <Notice kind="warn">登录密码改过，恢复口令还是旧密码</Notice>}
          {data.restore_command && (
            <details className="text-sm">
              <summary className="cursor-pointer text-muted-foreground">恢复命令</summary>
              <CodeBlock className="mt-2 break-all whitespace-pre-wrap">{data.restore_command}</CodeBlock>
            </details>
          )}
        </div>
      )}
      {asking === "enable" && (
        <Enable
          current={data?.to}
          onClose={() => setAsking(null)}
          onStarted={(runId) => {
            setAsking(null);
            actions.watch(runId, "备份控制面");
            refresh();
          }}
        />
      )}
      {asking === "key" && <RecoveryKey onClose={() => setAsking(null)} />}
    </>
  );
}

function Enable({ current, onClose, onStarted }: { current?: string; onClose: () => void; onStarted: (runId: string) => void }) {
  const { status } = useStatus();
  const options = serverOptions(status?.servers ?? []);
  const [to, setTo] = useState(current ?? "");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const { run_id } = await api.post<{ run_id: string }>("/api/core-backup", { to, password });
      setPassword("");
      onStarted(run_id);
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>控制面备份</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <Field label="备份到" help="不能是控制面所在的机器">
            <Picker value={to} options={options} onChange={setTo} placeholder="选择服务器" />
          </Field>
          <Field label="登录密码" htmlFor="cb-password" help="作为恢复口令">
            <Input id="cb-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!to || !password || saving} onClick={save}>
            {saving ? "开始中…" : "保存并备份"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** 后备：登录密码忘了也能恢复。文件直接下载，不在页面上显示。 */
function RecoveryKey({ onClose }: { onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const key = await api.post<{ filename: string; text: string }>("/api/core-backup/recovery-key", { password });
      setPassword("");
      const url = URL.createObjectURL(new Blob([key.text], { type: "text/plain" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = key.filename;
      a.click();
      URL.revokeObjectURL(url);
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>下载恢复密钥</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <Notice kind="warn">能打开所有备份，别放在被备份的机器上</Notice>
          <Field label="登录密码" htmlFor="rk-password">
            <Input id="rk-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <ErrorNote error={error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!password || busy} onClick={download}>
            <DownloadIcon />
            下载
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
