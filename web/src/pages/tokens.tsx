import { ConfirmDialog } from "@/components/kit";
import { Panel } from "@/components/kit";
import { CopyIcon, PencilIcon, PlusIcon, TerminalIcon, Trash2Icon } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { api, ApiError, type Session, usePoll } from "@/api";
import { ago, CodeBlock, Empty, ErrorNote, Notice, SectionTitle } from "@/components/common";
import { Field, Segmented, toName } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CreatedToken, Perm, ServiceView, TokenSettings, TokenView } from "@/types";

const PERMS: [Perm, string, string][] = [
  ["read", "查看", "看所有状态、日志、配置（不含密钥明文）"],
  ["plan", "预览改动", "预览改动、探测网络"],
  ["apply", "执行改动", "执行不含高风险项的计划、上传代码、触发备份"],
  ["confirm", "确认高风险", "删数据、覆盖、公开到外网、从备份恢复"],
  ["exec", "容器执行", "容器终端、端口转发、改服务文件、容器/脚本任务"],
  ["host", "宿主机操作", "宿主机命令/目录/apt、特权或 host 网络容器、未纳管容器、系统配置（需目标服务器开对应开关；控制面所在机还需管理权限）"],
  ["admin", "管理", "服务器增删、厂商账号、密钥、访问令牌、审计、升级、SSO 与应用账号"],
];
const PERM_LABEL = Object.fromEntries(PERMS.map(([p, l]) => [p, l])) as Record<Perm, string>;

type Preset = "ai" | "read" | "all" | "custom";
const PRESETS: Record<Exclude<Preset, "custom">, Perm[]> = {
  ai: ["read", "plan", "apply", "exec"],
  read: ["read"],
  all: PERMS.map(([p]) => p),
};

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    toast.success("已复制");
  } catch {
    toast.error("复制失败，手动选中复制");
  }
}

function Command({ children }: { children: string }) {
  return (
    <div className="group relative">
      <CodeBlock className="pr-10 whitespace-pre-wrap break-all">{children}</CodeBlock>
      <Button variant="ghost" size="icon-xs" className="absolute top-2 right-2" aria-label="复制" onClick={() => copy(children)}>
        <CopyIcon />
      </Button>
    </div>
  );
}

// 只放一句指引，具体规则以 Skill（仓库里的 skill/SKILL.md）为准，避免两份说明对不上。
const AI_GUIDE = (origin: string) => `## Wharf（服务器管理）

用 \`wharf\` 命令管理服务器、服务、域名，控制面 ${origin}。
操作前先读 ${origin}/skill.md，按里面的守则执行。`;

/** 设置里的"CLI 与 AI 接入"：装 CLI、建 token、登录，以及给 AI 的说明。 */
export function Tokens() {
  const { data, error, refresh } = usePoll<TokenView[]>("/api/tokens", 30000);
  const coreKey = usePoll<Session>("/api/session", 600000).data?.core_key ?? "<控制面公钥>";
  const origin = window.location.origin;
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<TokenView | null>(null);
  // 刚建的 token 留在页面上，复制完登录命令还能回来复制它；刷新页面就没了。
  const [fresh, setFresh] = useState<CreatedToken | null>(null);
  const [guide, setGuide] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  const remove = async (name: string) => {
    setRemoving(null);
    try {
      await api.del(`/api/tokens/${encodeURIComponent(name)}`);
      toast.success(`已删除访问令牌 ${name}`);
      refresh();
    } catch (e) {
      toast.error(`删除 ${name} 失败`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <SectionTitle count={data?.length} action={<div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" size="sm" onClick={() => setGuide(true)}>
            <TerminalIcon />
            接入 CLI / AI
          </Button>
          <Button variant="outline" size="sm" onClick={() => setCreating(true)}>
            <PlusIcon />
            新建访问令牌
          </Button>
        </div>}>访问令牌</SectionTitle>
      <Dialog open={guide} onOpenChange={setGuide}>
        <DialogContent className="sm:max-w-2xl" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>接入 CLI / AI</DialogTitle>
          </DialogHeader>
          <div className="grid max-h-[70vh] gap-4 overflow-auto">
            <ol className="grid gap-4">
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">1. 建一个访问令牌，按用途选权限</span>
                <div className="flex flex-wrap items-start gap-2">
                  <Button variant="outline" size="sm" className="w-fit" onClick={() => setCreating(true)}>
                    <PlusIcon />
                    新建访问令牌
                  </Button>
                  {fresh && (
                    <div className="grid min-w-0 flex-1 gap-1">
                      <Command>{fresh.token}</Command>
                      <span className="text-xs text-warning">访问令牌 {fresh.name} 只显示这一次，刷新或离开页面就看不到了。</span>
                    </div>
                  )}
                </div>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">2. 在你的电脑上安装并登录（macOS、Linux）：提示输入访问令牌时粘贴上一步的令牌</span>
                <Command>{`curl -fsSL ${origin}/cli.sh | sh -s -- ${origin}`}</Command>
                <span className="text-xs text-muted-foreground">会同时把 wharf Skill 装到 ~/.agents/skills/wharf（Codex 等直接读），装了 Claude Code 的话再软链到 ~/.claude/skills/wharf。没有终端时脚本只打印登录命令：</span>
                <Command>{`wharf login --url ${origin} --core-key ${coreKey}`}</Command>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">3. 其他 AI 工具：下载 Skill 放进它的 skills 目录，或把这段贴进项目的 AGENTS.md</span>
                <Command>{`curl -fsSL ${origin}/skill.md`}</Command>
                <Command>{AI_GUIDE(origin)}</Command>
              </li>
            </ol>
          </div>
        </DialogContent>
      </Dialog>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>还没有访问令牌</Empty>
      ) : (
        data && (
          <Panel>
            <Table className="max-md:table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="max-md:w-[18%]">名称</TableHead>
                  <TableHead className="max-md:w-22">权限</TableHead>
                  <TableHead>限制</TableHead>
                  <TableHead className="hidden md:table-cell">最近使用</TableHead>
                  <TableHead className="hidden md:table-cell">创建</TableHead>
                  <TableHead className="w-10 max-md:w-16" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="font-medium max-md:break-all max-md:whitespace-normal">{t.name}</TableCell>
                    <TableCell className="max-md:px-1">
                      <span className="flex flex-wrap gap-1">
                        {t.perms.map((p) => (
                          <Badge key={p} variant={p === "admin" || p === "host" || p === "confirm" ? "default" : "secondary"} className="font-normal">
                            {PERM_LABEL[p] ?? p}
                          </Badge>
                        ))}
                      </span>
                    </TableCell>
                    <TableCell className="max-md:px-1"><Limits token={t} /></TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{t.last_used_at ? ago(t.last_used_at) : "没用过"}</TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{ago(t.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      <Button variant="ghost" size="xs" aria-label={`编辑 ${t.name}`} onClick={() => setEditing(t)}>
                        <PencilIcon />
                      </Button>
                      <Button variant="ghost" size="xs" aria-label={`删除 ${t.name}`} onClick={() => setRemoving(t.name)}>
                        <Trash2Icon />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>
        )
      )}
      {(creating || editing) && (
        <TokenDialog
          token={editing}
          taken={(data ?? []).map((t) => t.name)}
          onCreated={(t) => {
            setFresh(t);
            setGuide(true);
          }}
          onClose={() => {
            setCreating(false);
            setEditing(null);
            refresh();
          }}
        />
      )}
      <ConfirmDialog open={!!removing} title={`删除令牌 ${removing}？`} onCancel={() => setRemoving(null)} onConfirm={() => removing && remove(removing)}>用它的 CLI 和 AI 会立刻不能访问。</ConfirmDialog>
    </>
  );
}

const DAY = 86_400_000;
const MESH_RANGES = "100.64.0.0/10, fd7a:115c:a1e0::/48";

function expiryLabel(expires?: string | null) {
  if (!expires) return "永不过期";
  const remaining = Date.parse(expires) - Date.now();
  if (remaining <= 0) return "已过期";
  if (remaining >= DAY) return `剩 ${Math.floor(remaining / DAY)} 天`;
  if (remaining >= 3_600_000) return `剩 ${Math.floor(remaining / 3_600_000)} 小时`;
  return `剩 ${Math.max(1, Math.floor(remaining / 60_000))} 分钟`;
}

function Limits({ token }: { token: TokenView }) {
  const { expires_at, allowed_from = [], services = [] } = token;
  const expiry = expiryLabel(expires_at);
  if (!expires_at && !allowed_from.length && !services.length) return <span className="text-muted-foreground">不限</span>;
  const allowed = allowed_from.length ? `来源 ${allowed_from.join(", ")}` : "";
  const scoped = services.length ? `服务 ${services.join(", ")}` : "";
  return <span className="flex flex-wrap gap-1">
    {expires_at && <Badge variant={expiry === "已过期" ? "destructive" : "secondary"} className="max-w-full font-normal max-md:whitespace-normal">{expiry}</Badge>}
    {[allowed, scoped].filter(Boolean).map((limit) => <Badge key={limit} variant="secondary" className="max-w-full font-normal md:max-w-48" title={limit}>
      <span className="truncate">{limit}</span>
    </Badge>)}
  </span>;
}

function isSourceError(error: unknown): error is ApiError {
  return error instanceof ApiError && error.body.code === "InvalidInput" && error.body.message.startsWith("来源地址 ");
}

function TokenDialog({ token, taken, onCreated, onClose }: { token: TokenView | null; taken: string[]; onCreated: (t: CreatedToken) => void; onClose: () => void }) {
  const [name, setName] = useState(token?.name ?? "");
  const [preset, setPreset] = useState<Preset>(token ? "custom" : "ai");
  const [custom, setCustom] = useState<Perm[]>(token?.perms ?? PRESETS.ai);
  const [expiry, setExpiry] = useState(token ? "keep" : "never");
  const [from, setFrom] = useState(token?.allowed_from?.join(", ") ?? "");
  const [services, setServices] = useState<string[]>(token?.services ?? []);
  const serviceList = usePoll<ServiceView[]>("/api/services", 30000);
  const serviceNames = [...new Set([...(serviceList.data ?? []).map((s) => s.name), ...services])].sort();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const fromRevision = useRef(0);
  const sourceError = isSourceError(error) ? error : null;
  const changeFrom = (value: string) => {
    fromRevision.current++;
    setFrom(value);
    setError((current: unknown) => isSourceError(current) ? null : current);
  };
  const perms = preset === "custom" ? custom : PRESETS[preset];
  const expiryOptions: [string, string][] = [
    ...(token ? [[ "keep", `不改（${expiryLabel(token.expires_at)}）`] as [string, string]] : []),
    ["never", "永不过期"], ["1", "1 天"], ["7", "7 天"], ["30", "30 天"], ["90", "90 天"],
  ];

  const save = async () => {
    const submittedFrom = fromRevision.current;
    setSaving(true);
    setError(null);
    try {
      const expires_at = expiry === "keep" ? token?.expires_at ?? null : expiry === "never" ? null : new Date(Date.now() + Number(expiry) * DAY).toISOString();
      const settings: TokenSettings = { perms, expires_at, allowed_from: from.split(",").map((s) => s.trim()).filter(Boolean), services };
      if (token) {
        await api.put(`/api/tokens/${encodeURIComponent(name)}`, settings);
        toast.success(`已修改访问令牌 ${name}`);
      } else {
        onCreated(await api.post<CreatedToken>("/api/tokens", { name, ...settings }));
      }
      onClose();
    } catch (e) {
      if (!isSourceError(e) || submittedFrom === fromRevision.current) setError(e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>{token ? `修改访问令牌 ${name}` : "新建访问令牌"}</DialogTitle>
        </DialogHeader>
        <div className="grid max-h-[70vh] gap-4 overflow-auto">
          {!token && <Field label="名称" htmlFor="token-name" help="例如 laptop、claude">
            <Input id="token-name" value={name} onChange={(e) => setName(toName(e.target.value))} placeholder="laptop" />
          </Field>}
          <Field label="用途">
            <Segmented
              value={preset}
              options={[
                ["ai", "AI 运维"],
                ["read", "只读"],
                ["all", "全部"],
                ["custom", "自定义"],
              ]}
              onChange={setPreset}
            />
          </Field>
          <div className="grid gap-1.5">
            {PERMS.map(([p, label, hint]) => (
              <label key={p} className={`flex items-start gap-2.5 text-sm ${preset === "custom" && p !== "read" ? "cursor-pointer" : ""}`}>
                <Checkbox
                  className="mt-0.5"
                  checked={perms.includes(p)}
                  disabled={preset !== "custom" || p === "read"}
                  onCheckedChange={(v) => setCustom((c) => (v === true ? [...c, p] : c.filter((x) => x !== p)))}
                />
                <span className="grid">
                  <span>{label}</span>
                  <span className="text-xs text-muted-foreground">{hint}</span>
                </span>
              </label>
            ))}
          </div>
          <Field label="有效期">
            <div className="max-w-full overflow-x-auto whitespace-nowrap">
              <Segmented value={expiry} options={expiryOptions} onChange={setExpiry} />
            </div>
          </Field>
          <Field label="只允许从这些地址使用" htmlFor="token-from" help="留空表示不限。填组网网段就只能在组网内用">
            <Input id="token-from" value={from} onChange={(e) => changeFrom(e.target.value)} placeholder={MESH_RANGES} aria-invalid={!!sourceError} aria-describedby={sourceError ? "token-from-error" : undefined} />
            {sourceError && <div id="token-from-error" role="alert" className="break-all"><ErrorNote error={sourceError} /></div>}
            <Button className="w-fit" variant="outline" size="xs" onClick={() => changeFrom(MESH_RANGES)}>只允许组网内</Button>
          </Field>
          <Field label="只能操作这些服务" help="不勾表示不限。勾了以后这个令牌只能改这些服务，其他改动会被拒绝">
            <div className="grid max-h-48 gap-1.5 overflow-auto">
              {serviceNames.map((name) => <label key={name} className="flex cursor-pointer items-start gap-2.5 text-sm">
                <Checkbox className="mt-0.5" checked={services.includes(name)}
                  onCheckedChange={(v) => setServices((names) => v === true ? [...names, name] : names.filter((n) => n !== name))} />
                {name}
              </label>)}
            </div>
            <ErrorNote error={serviceList.error} />
          </Field>
          {preset === "ai" && <Notice>AI 能预览和执行普通改动、在容器里执行命令；触达宿主机需要 host 权限且服务器开对应开关，删数据、公开到外网等高风险项要确认。</Notice>}
          {!token && name && taken.includes(name) && <Notice kind="warn">已有同名访问令牌</Notice>}
          <ErrorNote error={sourceError ? null : error} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button disabled={!name || (!token && taken.includes(name)) || saving} onClick={save}>
            {token ? saving ? "保存中…" : "保存" : saving ? "创建中…" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
