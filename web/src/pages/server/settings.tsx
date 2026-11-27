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
  const { draft, set, reset, dirty, mergeInto } = useDraft(server.settings as Settings);
  const [version, setVersion] = useState(0);
  const { hash } = useLocation();
  const actions = useActions();
  useEffect(() => { if (active && hash) document.getElementById(hash.slice(1))?.scrollIntoView(); }, [active, hash]);
  const groups: [string, (keyof Settings)[]][] = [
    ["网络", ["public_ip", "lan_addrs"]],
    ["访问外网", ["via", "egress", "git_proxy", "pull_proxy", "github_mirror"]],
    ["部署", ["registry_mirrors", "mirrors_only", "build_env"]],
    ["流量", ["traffic_quota_gb", "traffic_reset_day"]],
    ["续费", ["renew_at"]],
    ["agent", ["agent_memory"]],
    ["权限", ["host_terminal", "host_exec", "host_docker", "host_system"]],
  ];
  const changed = groups.filter(([, keys]) => dirty(keys)).map(([label]) => label);
  return <SettingsFields key={version} server={server} canRemove={canRemove} draft={draft} set={set} dirty={dirty} changed={changed} onReset={() => { reset(); setVersion((v) => v + 1); }} onSubmit={() => actions.plan({ title: `设置 ${server.name}`, changes: [{ op: "update_server", name: server.name, settings: mergeInto(server.settings as Settings) }] })} />;
}

function SettingsFields({ server, canRemove, draft, set, dirty, changed, onReset, onSubmit }: { server: ServerView; canRemove: boolean; draft: Settings; set: (patch: Partial<Settings>) => void; dirty: (keys: (keyof Settings)[]) => boolean; changed: string[]; onReset: () => void; onSubmit: () => void }) {
  const nav = useNavigate();
  const [mirrors, setMirrors] = useState(mirrorsText(draft.registry_mirrors));
  const [buildEnv, setBuildEnv] = useState(formatEnv(draft.build_env));
  const [quota, setQuota] = useState(draft.traffic_quota_gb?.toString() ?? "");
  const [resetDay, setResetDay] = useState(draft.traffic_reset_day?.toString() ?? "");
  const [rotatingKey, setRotatingKey] = useState(false);
  const [rotatingBusy, setRotatingBusy] = useState(false);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const mirrorsDirty = dirty(["registry_mirrors"]);
  const buildEnvDirty = dirty(["build_env"]);
  const quotaDirty = dirty(["traffic_quota_gb"]);
  const resetDayDirty = dirty(["traffic_reset_day"]);
  const saved = server.settings as Settings;
  const savedMirrors = mirrorsText(saved.registry_mirrors);
  const savedBuildEnv = formatEnv(saved.build_env);
  const savedQuota = saved.traffic_quota_gb?.toString() ?? "";
  const savedResetDay = saved.traffic_reset_day?.toString() ?? "";
  useEffect(() => { if (!mirrorsDirty) setMirrors(savedMirrors); }, [mirrorsDirty, savedMirrors]);
  useEffect(() => { if (!buildEnvDirty) setBuildEnv(savedBuildEnv); }, [buildEnvDirty, savedBuildEnv]);
  useEffect(() => { if (!quotaDirty) setQuota(savedQuota); }, [quotaDirty, savedQuota]);
  useEffect(() => { if (!resetDayDirty) setResetDay(savedResetDay); }, [resetDayDirty, savedResetDay]);
  const lanChoices = [...new Set([...(server.report?.lan_ips ?? []).filter(isPrivate), ...(draft.lan_addrs ?? [])])];
  const via = draft.via ?? "";
  const quotaNum = Number(quota.trim() || 0);
  const resetNum = Number(resetDay.trim() || 0);
  const trafficValid = Number.isInteger(quotaNum) && quotaNum >= 0 && Number.isInteger(resetNum) && resetNum >= 0 && resetNum <= 28;
  const rotateKey = async () => {
    setRotatingBusy(true);
    try {
      const result = await api.post<{ key_fingerprint: string }>(`/api/servers/${encodeURIComponent(server.name)}/rotate-key`, {});
      setFingerprint(result.key_fingerprint);
      toast.success("通信密钥已轮换");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setRotatingKey(false);
      setRotatingBusy(false);
    }
  };
  const remove = async () => {
    setRemoving(false);
    try { await api.del(`/api/servers/${encodeURIComponent(server.name)}`); toast.success(`已删除服务器 ${server.name}`); nav("/servers"); }
    catch(e) { toast.error(`删除 ${server.name} 失败`, { description: (e as Error).message }); }
  };
  return <div className="max-w-2xl">
    <div id="network">
      <SectionTitle>网络</SectionTitle>
    </div>
    <Panel className="grid gap-4 p-4">
      <Button variant="outline" onClick={() => nav(`/servers/${encodeURIComponent(server.name)}?tab=network`)}>修改接入方式</Button>
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
        <Textarea id="mirrors" rows={3} className="font-mono text-xs" value={mirrors} onChange={(e) => { setMirrors(e.target.value); set({ registry_mirrors: parseMirrors(e.target.value) }); }} />
      </Field>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={!!draft.mirrors_only} onCheckedChange={(v) => set({ mirrors_only: v === true })} />有镜像源时不再尝试原地址</label>
      <Field label="构建参数" htmlFor="build-env" help="每行 KEY=VALUE，传给内置模板。国内机器常配 PIP_INDEX_URL、GOPROXY。">
        <CodeEditor id="build-env" lang="env" className="min-h-16" value={buildEnv} onChange={(value) => { setBuildEnv(value); set({ build_env: parseEnv(value) }); }} />
      </Field>
    </Panel>
    <SectionTitle>流量</SectionTitle>
    <Panel className="p-4">
      <Field label="流量" help="每月额度（GB）和重置日（1 到 28，北京时间），用于显示本期用了多少，用到 80% 时提醒（阈值在告警规则里改）。都不填按每月 1 号算、不显示额度。">
        <div className="flex gap-2">
          <Input aria-label="每月额度" inputMode="numeric" className="w-32" value={quota} placeholder="额度 GB" onChange={(e) => { const v = e.target.value; setQuota(v); set({ traffic_quota_gb: v.trim() ? Number(v) : undefined }); }} />
          <Input aria-label="重置日" inputMode="numeric" className="w-32" value={resetDay} placeholder="重置日" onChange={(e) => { const v = e.target.value; setResetDay(v); set({ traffic_reset_day: v.trim() ? Number(v) : undefined }); }} />
        </div>
      </Field>
    </Panel>
    <SectionTitle>续费</SectionTitle>
    <Panel className="p-4">
      <Field label="续费日" htmlFor="renew-at">
        <Input id="renew-at" type="date" value={draft.renew_at ?? ""} onChange={(e) => set({ renew_at: e.target.value || undefined })} />
      </Field>
    </Panel>
    <SectionTitle>agent</SectionTitle>
    <Panel className="p-4">
      <Field label="内存上限" htmlFor="agent-memory" help="例如 256M、1G，none 表示不限。">
        <Input id="agent-memory" value={draft.agent_memory ?? ""} placeholder="256M" onChange={(e) => set({ agent_memory: e.target.value || undefined })} />
      </Field>
    </Panel>
    {server.joined && <Panel className="mt-3 flex flex-wrap items-center gap-3 p-4">
      <div className="flex-1 text-sm">agent 公钥指纹 <code>{fingerprint ?? server.key_fingerprint}</code></div>
      <Button variant="outline" size="sm" disabled={!server.key_rotation || !server.online} onClick={() => setRotatingKey(true)}>轮换通信密钥</Button>
      {!server.key_rotation && <span className="text-xs text-muted-foreground">{server.online ? "请先升级 agent" : "agent 离线"}</span>}
    </Panel>}
    <ConfirmDialog open={rotatingKey} title="轮换 agent 通信密钥？" confirmText="轮换" busy={rotatingBusy} onCancel={() => setRotatingKey(false)} onConfirm={rotateKey} />
    <div id="access" className="mt-8">
      <SectionTitle>权限</SectionTitle>
    </div>
    <Panel className="grid gap-3 p-4">
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={draft.host_terminal} onCheckedChange={(v) => set({ host_terminal: v === true })} />
        <span>宿主机终端<span className="block text-xs text-muted-foreground">允许从页面打开这台机器的终端。</span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={draft.host_exec} onCheckedChange={(v) => set({ host_exec: v === true })} />
        <span>宿主机命令<span className="block text-xs text-muted-foreground">允许带 host 权限的令牌执行宿主机命令、浏览打包目录、安装 apt 更新、管理终端会话和运行宿主机命令任务。</span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={!!draft.host_docker} onCheckedChange={(v) => set({ host_docker: v === true })} />
        <span>特权与未纳管容器<span className="block text-xs text-muted-foreground">允许带 host 权限的令牌部署特权/host 网络/越界挂载容器、操作未纳管容器，以及修改网关镜像和本地四层转发。</span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={!!draft.host_system} onCheckedChange={(v) => set({ host_system: v === true })} />
        <span>宿主机系统配置<span className="block text-xs text-muted-foreground">允许带 host 权限的令牌修改服务器设置、基线、代理、Tailscale，以及查看监视宿主机程序。</span>
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

export function NetworkSettings({ server }: { server: ServerView }) {
  const { draft, set, reset, dirty } = useDraft(server.settings as Settings);
  const actions = useActions();
  const { data: network } = usePoll<NetworkView>("/api/network", 30000);
  const detected = network?.servers.find((s) => s.name === server.name);
  const currentMode = detected && !detected.configured ? detected.mode : undefined;
  return <div className="mt-4"><Panel className="p-4">
      <Field label="接入方式" help={`这台和其他机器怎么连。自动：按检测到的地址判断${currentMode ? `，现在是${MODES[currentMode]}` : ""}。`}>
        <div className="max-w-full overflow-x-auto"><Segmented value={draft.network_mode ?? "auto"} options={[["auto", "自动"], ["tailscale", "Tailscale"], ["lan", "内网直连"], ["public", "仅公网"]]} onChange={(v) => set({ network_mode: v === "auto" ? undefined : v })} /></div>
      </Field>
  </Panel><SaveBar changed={dirty(["network_mode"]) ? ["接入方式"] : []} onReset={reset} onSubmit={() => actions.plan({ title: `设置 ${server.name}`, changes: [{ op: "update_server", name: server.name, settings: { ...server.settings, network_mode: draft.network_mode } }] })} /></div>;
}
