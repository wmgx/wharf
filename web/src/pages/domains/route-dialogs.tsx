import { useState } from "react";
import { CodeEditor } from "@/components/code-editor";
import { Field } from "@/components/fields";
import { TargetFields, sameTarget, targetError, type Target } from "@/components/target-fields";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";

/** 修改指向：只改详情里的本地状态，由底部“预览改动”统一提交。 */
export function EditTargetDialog({ hostname, target, onSave, onClose }: { hostname: string; target: Target; onSave: (t: Target) => void; onClose: () => void }) {
  const { status } = useStatus();
  const services = status?.services ?? [];
  const [value, setValue] = useState(target);
  const [touched, setTouched] = useState(false);
  const error = targetError(value, services);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle className="break-all">修改 {hostname} 的指向</DialogTitle></DialogHeader>
        <TargetFields value={value} onChange={(t) => { setValue(t); setTouched(true); }} services={services} idPrefix="edit-target" touched={touched} />
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button disabled={!!error || sameTarget(value, target)} onClick={() => { onSave(value); onClose(); }}>确定</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** 修改跳转目标。 */
export function EditRedirectDialog({ hostname, url, onSave, onClose }: { hostname: string; url: string; onSave: (url: string) => void; onClose: () => void }) {
  const [value, setValue] = useState(url);
  const trimmed = value.trim();
  const bad = !/^https?:\/\/\S+$/.test(trimmed);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle className="break-all">修改 {hostname} 的跳转</DialogTitle></DialogHeader>
        <Field label="跳转到" htmlFor="edit-redirect">
          <Input id="edit-redirect" className="font-mono" autoFocus value={value} onChange={(e) => setValue(e.target.value)} />
          {bad && trimmed !== url && <p className="text-xs text-destructive">以 http:// 或 https:// 开头</p>}
        </Field>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button disabled={bad || trimmed === url} onClick={() => { onSave(trimmed); onClose(); }}>确定</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** 路径要以 / 开头，不能有空白和 {}"#，和后端一致。 */
function pathError(path: string, taken: string[]): string | null {
  if (!path.startsWith("/") || /[\s{}"#]/.test(path)) return "以 / 开头，不能有空格和 {}\"#";
  if (taken.includes(path)) return "已经有这个路径的转发";
  return null;
}

/** 加一条按路径转发。 */
export function AddPathDialog({ taken, onAdd, onClose }: { taken: string[]; onAdd: (path: string, t: Target) => void; onClose: () => void }) {
  const { status } = useStatus();
  const services = status?.services ?? [];
  const [path, setPath] = useState("");
  const [target, setTarget] = useState<Target>({ kind: "service", service: "" });
  const [touched, setTouched] = useState(false);
  const p = path.trim();
  const perr = p ? pathError(p, taken) : null;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader><DialogTitle>加路径转发</DialogTitle></DialogHeader>
        <div className="grid gap-4">
          <Field label="路径" htmlFor="path-rule" help="/ws 只匹配这一个路径，/api/* 匹配它下面的全部">
            <Input id="path-rule" className="font-mono" autoFocus placeholder="/api/*" value={path} onChange={(e) => setPath(e.target.value)} />
            {perr && <p className="text-xs text-destructive">{perr}</p>}
          </Field>
          <TargetFields value={target} onChange={(t) => { setTarget(t); setTouched(true); }} services={services} idPrefix="path-target" touched={touched} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button disabled={!p || !!perr || !!targetError(target, services)} onClick={() => { onAdd(p, target); onClose(); }}>加上</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** 常用片段。`@m` 插入时换成没用过的匹配器名，同一个片段插两次也不冲突。 */
const SNIPPETS: [string, string, string][] = [
  ["禁止访问路径", "deny", "@m path /admin/*\nrespond @m 403"],
  ["路径只给内网", "outside", "@m {\n\tpath /admin/*\n\tnot remote_ip private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\n}\nrespond @m 403"],
  ["只允许这些 IP", "others", "@m not remote_ip 203.0.113.0/24 private_ranges 100.64.0.0/10 fd7a:115c:a1e0::/48\nrespond @m 403"],
  ["安全响应头", "", "header {\n\tStrict-Transport-Security \"max-age=31536000\"\n\tX-Frame-Options SAMEORIGIN\n\tX-Content-Type-Options nosniff\n\tReferrer-Policy strict-origin-when-cross-origin\n}"],
  ["禁止搜索引擎收录", "", "header X-Robots-Tag \"noindex, nofollow\""],
];

function insertSnippet(text: string, base: string, snippet: string): string {
  let name = base;
  for (let i = 2; base && new RegExp(`@${name}\\b`).test(text); i++) name = `${base}${i}`;
  const body = base ? snippet.replaceAll("@m", `@${name}`) : snippet;
  const head = text.trimEnd();
  return `${head}${head ? "\n\n" : ""}${body}\n`;
}

/** 自定义 Caddy 配置，原样插进这个域名的站点块。 */
export function CaddyDialog({ hostname, value, onSave, onClose }: { hostname: string; value: string; onSave: (text: string) => void; onClose: () => void }) {
  const [text, setText] = useState(value);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-2xl" aria-describedby={undefined}>
        <DialogHeader><DialogTitle className="break-all">{hostname} 的 Caddy 配置</DialogTitle></DialogHeader>
        <Field label="插进站点块的配置" htmlFor="route-caddy" help="下发前用 Caddy 校验，写错了不会生效">
          <CodeEditor id="route-caddy" lang="caddy" className="min-h-64" value={text} onChange={setText} placeholder={"@admin path /admin/*\nrespond @admin 403"} />
        </Field>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">插入</span>
          {SNIPPETS.map(([label, base, snippet]) => <Button key={label} variant="outline" size="xs" onClick={() => setText(insertSnippet(text, base, snippet))}>{label}</Button>)}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>取消</Button>
          <Button disabled={text === value} onClick={() => { onSave(text); onClose(); }}>确定</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
