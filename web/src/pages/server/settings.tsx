import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { CodeEditor } from "@/components/code-editor";
import { MODES, SectionTitle } from "@/components/common";
import { Field, Segmented, formatEnv, parseEnv } from "@/components/fields";
import { ConfirmDialog, Panel, SaveBar, useDraft } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { NetworkMode, NetworkView, ServerView } from "@/types";
import { EgressFields } from "./egress";
import { isPrivate, mirrorsText, parseMirrors } from "./format";

type Settings = ServerView["settings"] & {
  network_mode?: NetworkMode;
  public_ip?: string;
  lan_addrs?: string[];
  registry_mirrors?: Record<string, string[]>;
  mirrors_only?: boolean;
  build_env?: Record<string, string>;
  git_proxy?: string;
  pull_proxy?: string;
  github_mirror?: string;
  traffic_quota_gb?: number;
  traffic_reset_day?: number;
  renew_at?: string;
};

export function SettingsForm({ server, canRemove, active }: { server: ServerView; canRemove: boolean; active: boolean }) {
  const { draft, set, reset, dirty } = useDraft(server.settings as Settings);
  const [version, setVersion] = useState(0);
  const { hash } = useLocation();
  const actions = useActions();
  useEffect(() => { if (active && hash) document.getElementById(hash.slice(1))?.scrollIntoView(); }, [active, hash]);
  const groups: [string, (keyof Settings)[]][] = [
    ["网络", ["network_mode", "public_ip", "lan_addrs"]],
    ["访问外网", ["via", "egress", "git_proxy", "pull_proxy", "github_mirror"]],
    ["部署", ["registry_mirrors", "mirrors_only", "build_env"]],
    ["流量", ["traffic_quota_gb", "traffic_reset_day"]],
    ["续费", ["renew_at"]],
    ["权限", ["host_terminal", "host_exec"]],
  ];
  const changed = groups.filter(([, keys]) => dirty(keys)).map(([label]) => label);
  return <SettingsFields key={version} server={server} canRemove={canRemove} draft={draft} set={set} changed={changed} onReset={() => { reset(); setVersion((v) => v + 1); }} onSubmit={() => actions.plan({ title: `设置 ${server.name}`, changes: [{ op: "update_server", name: server.name, settings: draft }] })} />;
}

function SettingsFields({ server, canRemove, draft, set, changed, onReset, onSubmit }: { server: ServerView; canRemove: boolean; draft: Settings; set: (patch: Partial<Settings>) => void; changed: string[]; onReset: () => void; onSubmit: () => void }) {
  const nav = useNavigate();
  const { data: network } = usePoll<NetworkView>("/api/network", 30000);
  const detected = network?.servers.find((s) => s.name === server.name);
  const currentMode = detected && !detected.configured ? detected.mode : undefined;
  const [mirrors, setMirrors] = useState(mirrorsText(draft.registry_mirrors));
  const [buildEnv, setBuildEnv] = useState(formatEnv(draft.build_env));
  const [quota, setQuota] = useState(draft.traffic_quota_gb?.toString() ?? "");
  const [resetDay, setResetDay] = useState(draft.traffic_reset_day?.toString() ?? "");
  const [removing, setRemoving] = useState(false);
  const [textEdited, setTextEdited] = useState(false);
  useEffect(() => {
    if (!changed.length && !textEdited) {
      setMirrors(mirrorsText(draft.registry_mirrors));
      setBuildEnv(formatEnv(draft.build_env));
      setQuota(draft.traffic_quota_gb?.toString() ?? "");
      setResetDay(draft.traffic_reset_day?.toString() ?? "");
    }
  }, [draft, changed.length, textEdited]);
  const lanChoices = [...new Set([...(server.report?.lan_ips ?? []).filter(isPrivate), ...(draft.lan_addrs ?? [])])];
  const via = draft.via ?? "";
  const quotaNum = Number(quota.trim() || 0);
  const resetNum = Number(resetDay.trim() || 0);
  const trafficValid = Number.isInteger(quotaNum) && quotaNum >= 0 && Number.isInteger(resetNum) && resetNum >= 0 && resetNum <= 28;
  const remove = async () => {
    setRemoving(false);
    try { await api.del(`/api/servers/${encodeURIComponent(server.name)}`); toast.success(`已删除服务器 ${server.name}`); nav("/servers"); }
    catch(e) { toast.error(`不能删除 ${server.name}`, { description: (e as Error).message }); }
  };
  return <div className="max-w-2xl">
    <div id="network">
      <SectionTitle>网络</SectionTitle>
    </div>
    <Panel className="grid gap-4 p-4">
      <Field label="接入方式" help={`这台和其他机器怎么连。自动：按检测到的地址判断${currentMode ? `，现在是${MODES[currentMode]}` : ""}。`}>
        <div className="max-w-full overflow-x-auto"><Segmented value={draft.network_mode ?? "auto"} options={[["auto", "自动"], ["tailscale", "Tailscale"], ["lan", "内网直连"], ["public", "仅公网"]]} onChange={(v) => set({ network_mode: v === "auto" ? undefined : v })} /></div>
      </Field>
      <Field label="公网 IP" htmlFor="public-ip" help={`不填用探测到的${server.public_ip ? `（现在是 ${server.public_ip}）` : ""}。入口的 DNS 指向它。`}>
        <Input id="public-ip" value={draft.public_ip ?? ""} placeholder="自动探测" onChange={(e) => set({ public_ip: e.target.value || undefined })} />
      </Field>
      <Field label="局域网访问" help="勾选后，服务端口也绑到这些地址，同一个局域网里的设备可以直接打开。保存后这台机器上的服务会重建容器。">
        {lanChoices.length ? <div className="grid gap-2">
          {lanChoices.map((ip) => <label key={ip} className="flex items-center gap-2.5 font-mono text-sm">
            <Checkbox checked={(draft.lan_addrs ?? []).includes(ip)} onCheckedChange={(v) => { const list = v === true ? [...(draft.lan_addrs ?? []), ip] : (draft.lan_addrs ?? []).filter((x) => x !== ip); set({ lan_addrs: list.length ? list : undefined }); }} />
            {ip}
          </label>)}
        </div> : <span className="text-sm text-muted-foreground">agent 没有发现私有网段的地址</span>}
      </Field>
    </Panel>
    <div id="egress" className="mt-8">
      <SectionTitle>访问外网</SectionTitle>
    </div>
    <Panel className="grid gap-4 p-4">
      <EgressFields server={server.name} egress={draft.egress} onEgress={(egress) => set({ egress })} via={via} onVia={(value) => set({ via: value || undefined })} />
      <details open={!!(draft.git_proxy || draft.pull_proxy || draft.github_mirror) || undefined}>
        <summary className="cursor-pointer text-sm">手动代理</summary>
        <div className="mt-3 grid gap-4">
          <Field label="拉代码代理" htmlFor="git-proxy" help={via ? `已经经 ${via} 访问外网，这一项不生效。` : "只用于 git。"}>
            <Input id="git-proxy" disabled={!!via} value={draft.git_proxy ?? ""} placeholder="http://100.x.x.x:8118" onChange={(e) => set({ git_proxy: e.target.value || undefined })} />
          </Field>
          <Field label="拉镜像代理" htmlFor="pull-proxy" help={via ? `已经经 ${via} 访问外网，这一项不生效。` : "写进 dockerd 配置，保存时会重启 dockerd（容器不停）。"}>
            <Input id="pull-proxy" disabled={!!via} value={draft.pull_proxy ?? ""} placeholder="http://100.x.x.x:8118" onChange={(e) => set({ pull_proxy: e.target.value || undefined })} />
          </Field>
          <Field label="GitHub 镜像" htmlFor="github-mirror" help="拉代码时代替 https://github.com/ 的地址，可以用 [[密钥名]]。">
            <Input id="github-mirror" value={draft.github_mirror ?? ""} placeholder="https://gh.example.com/[[MIRROR_TOKEN]]" onChange={(e) => set({ github_mirror: e.target.value || undefined })} />
          </Field>
        </div>
      </details>
    </Panel>
    <SectionTitle>部署</SectionTitle>
    <Panel className="grid gap-4 p-4">
      <Field label="镜像源" htmlFor="mirrors" help="每行一个仓库，例如 docker.io=docker.1ms.run,docker.m.daocloud.io，按顺序尝试。">
        <Textarea id="mirrors" rows={3} className="font-mono text-xs" value={mirrors} onChange={(e) => { setTextEdited(true); setMirrors(e.target.value); set({ registry_mirrors: parseMirrors(e.target.value) }); }} />
      </Field>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={!!draft.mirrors_only} onCheckedChange={(v) => set({ mirrors_only: v === true })} />有镜像源时不再尝试原地址</label>
      <Field label="构建参数" htmlFor="build-env" help="每行 KEY=VALUE，传给内置模板。国内机器常配 PIP_INDEX_URL、GOPROXY。">
        <CodeEditor id="build-env" lang="env" className="min-h-16" value={buildEnv} onChange={(value) => { setTextEdited(true); setBuildEnv(value); set({ build_env: parseEnv(value) }); }} />
      </Field>
    </Panel>
    <SectionTitle>流量</SectionTitle>
    <Panel className="p-4">
      <Field label="流量" help="每月额度（GB）和重置日（1 到 28，北京时间），只用于显示本期用了多少。都不填按每月 1 号算、不显示额度。">
        <div className="flex gap-2">
          <Input aria-label="每月额度" inputMode="numeric" className="w-32" value={quota} placeholder="额度 GB" onChange={(e) => { const v = e.target.value; setTextEdited(true); setQuota(v); set({ traffic_quota_gb: v.trim() ? Number(v) : undefined }); }} />
          <Input aria-label="重置日" inputMode="numeric" className="w-32" value={resetDay} placeholder="重置日" onChange={(e) => { const v = e.target.value; setTextEdited(true); setResetDay(v); set({ traffic_reset_day: v.trim() ? Number(v) : undefined }); }} />
        </div>
      </Field>
    </Panel>
    <SectionTitle>续费</SectionTitle>
    <Panel className="p-4">
      <Field label="续费日" htmlFor="renew-at">
        <Input id="renew-at" type="date" value={draft.renew_at ?? ""} onChange={(e) => set({ renew_at: e.target.value || undefined })} />
      </Field>
    </Panel>
    <div id="access" className="mt-8">
      <SectionTitle>权限</SectionTitle>
    </div>
    <Panel className="grid gap-3 p-4">
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={draft.host_terminal} onCheckedChange={(v) => set({ host_terminal: v === true })} />
        <span>宿主机终端<span className="block text-xs text-muted-foreground">允许从页面打开这台机器的终端，以及浏览它的目录。</span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={draft.host_exec} onCheckedChange={(v) => set({ host_exec: v === true })} />
        <span>命令执行<span className="block text-xs text-muted-foreground">允许 CLI 和 AI 在这台机器上执行命令。</span>
        </span>
      </label>
    </Panel>
    <div className="mt-8 flex flex-wrap items-center gap-3 rounded-xl border border-destructive/30 p-4">
      <div className="grid flex-1 gap-0.5 text-sm">
        <span className="font-medium">删除服务器</span>
        <span className="text-xs text-muted-foreground">
          {canRemove ? "只删除 Wharf 里的记录，机器上的 agent 需要自己停掉。" : "上面还有服务或入口，先迁走或删掉。"}
        </span>
      </div>
      <Button variant="destructive" size="sm" disabled={!canRemove} onClick={() => setRemoving(true)}>删除</Button>
    </div>
    <ConfirmDialog open={removing} title={`删除服务器 ${server.name}？`} onCancel={() => setRemoving(false)} onConfirm={remove}>只删除 Wharf 里的记录，这台机器上的 agent 要自己停掉。</ConfirmDialog>
    <SaveBar changed={changed} disabled={trafficValid ? undefined : "流量额度或重置日不正确"} onReset={onReset} onSubmit={onSubmit} />
  </div>;
}
