import { CheckIcon, CopyIcon, GlobeIcon, LoaderIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { Dot, Notice } from "@/components/common";
import { DomainChips, Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import type { CoreAddress, CoreAddresses, JoinInfo } from "@/types";

const KIND_HINT: Record<string, string> = {
  route: "公网",
  configured: "启动配置",
  page: "当前页面",
  public: "公网",
  tailscale: "Tailscale",
  lan: "内网",
};
const CUSTOM = "custom";

/** 公网地址必须 https，和控制面的校验一致。 */
const blocked = (a: CoreAddress) => a.kind === "public" && a.url.startsWith("http://");

/** 候选地址：控制面列出的，加上浏览器当前访问的 https 地址。 */
function candidates(list: CoreAddress[]): CoreAddress[] {
  const origin = window.location.origin;
  const page = origin.startsWith("https://") && !list.some((a) => a.url === origin) ? [{ url: origin, kind: "page" }] : [];
  return [...page, ...list];
}

// 上次填的镜像只记在这个浏览器里，方便下次加国内机器。
const IMAGE_KEY = "wharf.add-server.image";
function loadImage(): string {
  try {
    return localStorage.getItem(IMAGE_KEY) ?? "";
  } catch {
    return "";
  }
}
function saveImage(v: string) {
  try {
    if (v) localStorage.setItem(IMAGE_KEY, v);
    else localStorage.removeItem(IMAGE_KEY);
  } catch {
    // 存不了就算了
  }
}

function addressOption(a: CoreAddress) {
  const hint = blocked(a) ? "需要 https" : [KIND_HINT[a.kind] ?? a.kind, a.plaintext ? "明文" : ""].filter(Boolean).join(" · ");
  return { value: a.url, label: a.url, hint, disabled: blocked(a) };
}

/** 加服务器：选控制面地址，生成一条命令到目标机器上执行，等 agent 连上。 */
export function AddServer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { status } = useStatus();
  const [name, setName] = useState("");
  const [core, setCore] = useState<CoreAddresses | null>(null);
  const [addrs, setAddrs] = useState<CoreAddress[]>([]);
  const [opening, setOpening] = useState(false);
  const [url, setUrl] = useState("");
  const [custom, setCustom] = useState("");
  const [image, setImage] = useState(loadImage);
  const [info, setInfo] = useState<JoinInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    api
      .get<CoreAddresses>("/api/core/addresses")
      .catch(() => null)
      .then((res) => {
        const c = candidates(res?.addresses ?? []);
        setCore(res);
        setAddrs(c);
        setUrl((u) => u || c.find((a) => !blocked(a))?.url || CUSTOM);
      });
  }, [open]);

  const close = () => {
    onClose();
    setName("");
    setInfo(null);
    setCopied(false);
    setOpening(false);
  };
  const existing = status?.servers.find((s) => s.name === name);
  const server = info ? status?.servers.find((s) => s.name === info.server) : undefined;
  const connected = !!server?.joined && server.online;
  const coreUrl = url === CUSTOM ? custom.trim() : url;

  const submit = async () => {
    setBusy(true);
    try {
      setInfo(await api.post<JoinInfo>("/api/servers", { name, core_url: coreUrl, agent_image: image.trim() || undefined, rejoin: !!existing?.joined }));
      saveImage(image.trim());
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
                options={[...addrs.map(addressOption), { value: CUSTOM, label: "其他地址" }]}
                onChange={setUrl}
              />
              {url === CUSTOM && (
                <Input className="mt-2 font-mono text-xs" placeholder="https://wharf.example.com" value={custom} onChange={(e) => setCustom(e.target.value)} />
              )}
              {!opening && !addrs.some((a) => a.kind === "route") && (
                <Button variant="outline" size="xs" className="mt-2 w-fit" onClick={() => setOpening(true)}>
                  <GlobeIcon />
                  开放到公网
                </Button>
              )}
            </Field>
            {opening && core && <OpenPublic core={core} onDone={close} />}
            <Field label="agent 镜像" htmlFor="agent-image">
              <Input id="agent-image" className="font-mono text-xs" placeholder={core?.agent_image ?? "默认"} value={image} onChange={(e) => setImage(e.target.value)} />
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

/** 经网关给控制面开放一个 https 域名：新建一条指向控制面地址的路由。 */
function OpenPublic({ core, onDone }: { core: CoreAddresses; onDone: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const gateways = status?.gateways ?? [];
  const [gateway, setGateway] = useState(gateways.find((g) => g.spec.default)?.name ?? gateways[0]?.name ?? "");
  const [hostname, setHostname] = useState("");
  const gw = gateways.find((g) => g.name === gateway);
  // 网关和控制面在同一台机器用 127.0.0.1，否则用控制面那台的内网地址。
  const coreIp = status?.servers.find((s) => s.name === core.server)?.private_addr?.ip;
  const upstream = !gw || !core.server ? undefined : gw.spec.server === core.server ? `127.0.0.1:${core.port}` : coreIp && `${coreIp}:${core.port}`;
  const suffixes = [...new Set(status?.routes.map((r) => r.spec.hostname.split(".").slice(1).join(".")).filter(Boolean))];
  const submit = () => {
    if (!upstream) return;
    onDone();
    actions.plan({ title: "控制面开放到公网", changes: [{ op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), upstream, gateway } }] });
  };
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid grid-cols-2 gap-3">
        <Field label="网关" htmlFor="core-gateway">
          <Picker id="core-gateway" value={gateway} options={gateways.map((g) => ({ value: g.name, label: g.name, hint: g.spec.server }))} onChange={setGateway} />
        </Field>
        <Field label="域名" htmlFor="core-hostname">
          <Input id="core-hostname" placeholder="wharf.example.com" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </Field>
      </div>
      {!hostname && <DomainChips suggestions={suffixes.map((s) => `wharf.${s}`)} onPick={setHostname} />}
      {gw && !upstream && <Notice kind="warn">{core.server ? `${core.server} 没有内网地址` : "找不到控制面所在的服务器"}</Notice>}
      {upstream && <div className="font-mono text-xs text-muted-foreground">→ {upstream}</div>}
      <Button className="w-fit" disabled={!hostname.trim() || !upstream} onClick={submit}>
        生成计划
      </Button>
    </div>
  );
}
