import { CheckIcon, CopyIcon, LoaderIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { Dot, Notice } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { CoreAddress, JoinInfo } from "@/types";

const KIND_HINT: Record<string, string> = {
  configured: "启动配置",
  page: "当前页面",
  public: "公网",
  tailscale: "Tailscale",
  lan: "内网",
};
const CUSTOM = "custom";

/** 候选地址：控制面列出的，加上浏览器当前访问的地址。https 的排在前面。 */
function candidates(list: CoreAddress[]): CoreAddress[] {
  const page = { url: window.location.origin, kind: "page" };
  const all = list.some((a) => a.url === page.url) ? list : [page, ...list];
  return [...all].sort((a, b) => Number(b.url.startsWith("https://")) - Number(a.url.startsWith("https://")));
}

/** 加服务器：选控制面地址，生成一条命令到目标机器上执行，等 agent 连上。 */
export function AddServer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const [name, setName] = useState("");
  const [addrs, setAddrs] = useState<CoreAddress[]>([]);
  const [url, setUrl] = useState("");
  const [custom, setCustom] = useState("");
  const [info, setInfo] = useState<JoinInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    api
      .get<CoreAddress[]>("/api/core/addresses")
      .catch(() => [])
      .then((list) => {
        const c = candidates(list);
        setAddrs(c);
        setUrl((u) => u || c[0]?.url || CUSTOM);
      });
  }, [open]);

  const close = () => {
    onClose();
    setName("");
    setInfo(null);
    setCopied(false);
  };
  const existing = status?.servers.find((s) => s.name === name);
  const server = info ? status?.servers.find((s) => s.name === info.server) : undefined;
  const connected = !!server?.joined && server.online;
  const coreUrl = url === CUSTOM ? custom.trim() : url;

  const submit = async () => {
    setBusy(true);
    try {
      setInfo(await api.post<JoinInfo>("/api/servers", { name, core_url: coreUrl, rejoin: !!existing?.joined }));
    } catch (e) {
      toast.error("生成失败", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const copy = async () => {
    if (!info) return;
    await navigator.clipboard.writeText(info.commands.script);
    setCopied(true);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{info ? `加入 ${info.server}` : "加服务器"}</DialogTitle>
        </DialogHeader>
        {!info ? (
          <>
            <Field label="名字" htmlFor="server-name">
              <Input id="server-name" autoFocus placeholder="server-2" value={name} onChange={(e) => setName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} />
            </Field>
            <Field label="控制面地址" htmlFor="core-url">
              <Picker
                id="core-url"
                value={url}
                options={[...addrs.map((a) => ({ value: a.url, label: a.url, hint: KIND_HINT[a.kind] ?? a.kind })), { value: CUSTOM, label: "其他地址" }]}
                onChange={setUrl}
              />
              {url === CUSTOM && (
                <Input className="mt-2 font-mono text-xs" placeholder="https://wharf.example.com" value={custom} onChange={(e) => setCustom(e.target.value)} />
              )}
            </Field>
            {existing?.joined && <Notice kind="warn">{name} 已加入，原来的 agent 会失效</Notice>}
            <DialogFooter>
              <Button variant="ghost" onClick={close}>
                取消
              </Button>
              <Button disabled={!name || !coreUrl || busy} onClick={submit}>
                {existing?.joined ? "重新生成" : "生成命令"}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <div className="relative">
              <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 pr-11 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">{info.commands.script}</pre>
              <Button variant="ghost" size="icon-xs" className="absolute top-2 right-2" aria-label="复制" onClick={copy}>
                {copied ? <CheckIcon /> : <CopyIcon />}
              </Button>
            </div>
            <div className="flex items-center gap-2 text-sm">
              {connected ? (
                <>
                  <Dot tone="ok" />
                  已连接
                  {server?.report && (
                    <span className="text-muted-foreground">
                      · {server.report.hostname} · {server.report.os}/{server.report.arch}
                      {server.report.docker_version ? ` · Docker ${server.report.docker_version}` : ""}
                    </span>
                  )}
                </>
              ) : (
                <>
                  <LoaderIcon className="size-3.5 animate-spin text-muted-foreground" />
                  <span className="text-muted-foreground">
                    等待连接 · 命令 {new Date(info.expires_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })} 前有效
                  </span>
                </>
              )}
            </div>
            <DialogFooter>
              <Button variant={connected ? "default" : "ghost"} onClick={close}>
                {connected ? "完成" : "关闭"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
