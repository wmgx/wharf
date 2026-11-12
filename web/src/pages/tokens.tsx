import { ConfirmDialog } from "@/components/kit";
import { Panel } from "@/components/kit";
import { CopyIcon, PlusIcon, TerminalIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, type Session, usePoll } from "@/api";
import { ago, CodeBlock, Empty, ErrorNote, Notice, SectionTitle } from "@/components/common";
import { Field, Segmented, toName } from "@/components/fields";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CreatedToken, Perm, TokenView } from "@/types";

const PERMS: [Perm, string, string][] = [
  ["read", "查看", "看所有状态、日志、配置（不含密钥明文）"],
  ["plan", "预览改动", "预览改动、探测网络"],
  ["apply", "执行改动", "执行不含高风险项的计划、上传代码、触发备份"],
  ["confirm", "确认高风险", "删数据、覆盖、公开到外网、从备份恢复"],
  ["exec", "宿主机", "在宿主机执行命令、打开终端、改服务文件"],
  ["admin", "管理", "服务器、账号、密钥、token，升级 Wharf"],
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

const AI_GUIDE = (origin: string) => `## Wharf（服务器管理）

用 \`wharf\` 命令管理服务器、服务、域名，控制面 ${origin}。

- 一律加 \`--json\`，按 JSON 读结果；出错时看 \`hint\` 和 \`suggest\`。
- 改动先 \`wharf plan\`（或子命令不带 \`--apply\`）看计划，确认后 \`wharf apply <plan_id>\`。
- 计划里标了"需确认"的项（删数据、覆盖、公开）不要自己确认，交给用户。
- 字段说明：\`wharf schema <对象>\`；总览：\`wharf status --json\`；诊断域名：\`wharf doctor --json\`。
- 部署本机代码：\`wharf deploy <目录>\`；看日志：\`wharf service logs <服务>\`。
- 不打印、不写入 token 和密钥。`;

/** 设置里的"CLI 与 AI 接入"：装 CLI、建 token、登录，以及给 AI 的说明。 */
export function Tokens() {
  const { data, error, refresh } = usePoll<TokenView[]>("/api/tokens", 30000);
  const coreKey = usePoll<Session>("/api/session", 600000).data?.core_key ?? "<控制面公钥>";
  const origin = window.location.origin;
  const [creating, setCreating] = useState(false);
  // 刚建的 token 留在页面上，复制完登录命令还能回来复制它；刷新页面就没了。
  const [fresh, setFresh] = useState<CreatedToken | null>(null);
  const [guide, setGuide] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  const remove = async (name: string) => {
    setRemoving(null);
    try {
      await api.del(`/api/tokens/${encodeURIComponent(name)}`);
      toast.success(`已删除 token ${name}`);
      refresh();
    } catch (e) {
      toast.error(`不能删除 ${name}`, { description: (e as Error).message });
    }
  };

  return (
    <>
      <SectionTitle count={data?.length} action={<div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setGuide(true)}>
            <TerminalIcon />
            接入 CLI / AI
          </Button>
          <Button variant="outline" size="sm" onClick={() => setCreating(true)}>
            <PlusIcon />
            新建 token
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
                <span className="text-sm font-medium">1. 在你的电脑上装 wharf 命令（macOS、Linux）</span>
                <Command>{`curl -fsSL ${origin}/cli.sh | sh -s -- ${origin}`}</Command>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">2. 建一个 token，按用途选权限</span>
                <div className="flex flex-wrap items-start gap-2">
                  <Button variant="outline" size="sm" className="w-fit" onClick={() => setCreating(true)}>
                    <PlusIcon />
                    新建 token
                  </Button>
                  {fresh && (
                    <div className="grid min-w-0 flex-1 gap-1">
                      <Command>{fresh.token}</Command>
                      <span className="text-xs text-warning">token {fresh.name} 只显示这一次，刷新或离开页面就看不到了。</span>
                    </div>
                  )}
                </div>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">3. 登录：执行后提示输入 token 时，粘贴上一步的 token</span>
                <Command>{`wharf login --url ${origin} --core-key ${coreKey}`}</Command>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">4. 试一下</span>
                <Command>wharf status</Command>
              </li>
              <li className="grid gap-1.5">
                <span className="text-sm font-medium">5. 给 AI 用：把这段贴进项目的 AGENTS.md 或 CLAUDE.md</span>
                <Command>{AI_GUIDE(origin)}</Command>
              </li>
            </ol>
          </div>
        </DialogContent>
      </Dialog>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>还没有 token</Empty>
      ) : (
        data && (
          <Panel>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>权限</TableHead>
                  <TableHead>最近使用</TableHead>
                  <TableHead>创建</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell>
                      <span className="flex flex-wrap gap-1">
                        {t.perms.map((p) => (
                          <Badge key={p} variant={p === "admin" || p === "confirm" ? "default" : "secondary"} className="font-normal">
                            {PERM_LABEL[p] ?? p}
                          </Badge>
                        ))}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{t.last_used_at ? ago(t.last_used_at) : "没用过"}</TableCell>
                    <TableCell className="text-muted-foreground">{ago(t.created_at)}</TableCell>
                    <TableCell>
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
      {creating && (
        <CreateToken
          taken={(data ?? []).map((t) => t.name)}
          onCreated={(t) => {
            setFresh(t);
            setGuide(true);
          }}
          onClose={() => {
            setCreating(false);
            refresh();
          }}
        />
      )}
      <ConfirmDialog open={!!removing} title={`删除令牌 ${removing}？`} onCancel={() => setRemoving(null)} onConfirm={() => removing && remove(removing)}>用它的 CLI 和 AI 会立刻不能访问。</ConfirmDialog>
    </>
  );
}

/** 建好就关掉，token 交给页面显示。 */
function CreateToken({ taken, onCreated, onClose }: { taken: string[]; onCreated: (t: CreatedToken) => void; onClose: () => void }) {
  const [name, setName] = useState("");
  const [preset, setPreset] = useState<Preset>("ai");
  const [custom, setCustom] = useState<Perm[]>(PRESETS.ai);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const perms = preset === "custom" ? custom : PRESETS[preset];

  const create = async () => {
    setSaving(true);
    setError(null);
    try {
      onCreated(await api.post<CreatedToken>("/api/tokens", { name, perms }));
      onClose();
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
          <DialogTitle>新建 token</DialogTitle>
        </DialogHeader>
          <div className="grid gap-4">
            <Field label="名称" htmlFor="token-name" help="例如 laptop、claude">
              <Input id="token-name" value={name} onChange={(e) => setName(toName(e.target.value))} placeholder="laptop" />
            </Field>
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
            {preset === "ai" && <Notice>AI 能预览和执行普通改动、在宿主机执行命令；删数据、公开到外网这类高风险项要你在页面上确认。</Notice>}
            {name && taken.includes(name) && <Notice kind="warn">已有同名 token</Notice>}
            <ErrorNote error={error} />
          </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!name || taken.includes(name) || saving} onClick={create}>
            {saving ? "创建中…" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
