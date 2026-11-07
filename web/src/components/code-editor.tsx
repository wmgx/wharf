import { useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, usePoll } from "@/api";
import { KeyRoundIcon, PlusIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import type { SecretView } from "@/types";

export type Lang = "yaml" | "shell" | "dockerfile" | "env";

const C = {
  comment: "text-muted-foreground italic",
  key: "text-foreground font-medium",
  strong: "text-sky-700 dark:text-sky-400 font-semibold",
  string: "text-emerald-700 dark:text-emerald-400",
  number: "text-amber-700 dark:text-amber-400",
  variable: "text-amber-700 dark:text-amber-400",
  secret: "text-amber-700 dark:text-amber-400",
  keyword: "text-fuchsia-700 dark:text-fuchsia-400",
  command: "text-sky-700 dark:text-sky-400 font-medium",
  bad: "underline decoration-destructive decoration-wavy underline-offset-4",
} as const;

type Rule = [RegExp, keyof typeof C | ((m: RegExpExecArray) => ReactNode[])];

const SECRET: Rule = [/\[\[[A-Za-z0-9_-]+\]\]/y, "secret"];
const VAR: Rule = [/\$\{[^}\s]*\}|\$[A-Za-z_][A-Za-z0-9_]*/y, "variable"];
const STRING: Rule = [/"(?:\\.|[^"\\])*"|'[^']*'/y, "string"];

const SHELL_KW = /^(?:if|then|else|elif|fi|for|in|do|done|while|case|esac|exec|export|set|cd|source|function|return)$/;

/** 每种语言的规则：在每个位置依次尝试，第一个匹配的生效。`^` 开头的规则只在行首（跳过缩进后）生效。 */
const RULES: Record<Lang, { lineStart?: Rule[]; inline: Rule[] }> = {
  yaml: {
    lineStart: [[/(-\s+)?([\w.-]+)(:)(?=\s|$)/y, (m) => [m[1] ?? "", span(["ports", "volumes", "image", "services"].includes(m[2]) ? "strong" : "key", m[2]), ":"]]],
    inline: [[/#.*/y, "comment"], SECRET, VAR, STRING, [/\b\d+(?:\.\d+)?(?::\d+)*(?:\/(?:tcp|udp))?\b/y, "number"]],
  },
  dockerfile: {
    lineStart: [[/[A-Za-z]+(?=\s)/y, (m) => [span(/^(FROM|RUN|CMD|COPY|ADD|WORKDIR|ENV|ARG|EXPOSE|ENTRYPOINT|USER|VOLUME|LABEL|HEALTHCHECK|SHELL|ONBUILD|STOPSIGNAL)$/i.test(m[0]) ? "keyword" : "bad", m[0])]]],
    inline: [[/#.*/y, "comment"], SECRET, VAR, STRING, [/\bAS\b/y, "keyword"], [/--[\w-]+/y, "key"]],
  },
  shell: {
    lineStart: [[/[\w./-]+/y, (m) => [span(SHELL_KW.test(m[0]) ? "keyword" : "command", m[0])]]],
    inline: [
      [/#.*/y, "comment"],
      SECRET,
      VAR,
      STRING,
      [/&&|\|\||[|;]/y, "keyword"],
      // 管道和 && 之后的第一个词也是命令。
      [/(?<=(?:&&|\|\||[|;])\s*)[\w./-]+/y, (m) => [span(SHELL_KW.test(m[0]) ? "keyword" : "command", m[0])]],
      [/(?<=\s)--?[\w-]+/y, "key"],
    ],
  },
  env: {
    lineStart: [
      [/#.*/y, "comment"],
      [/(export\s+)?([A-Za-z_][A-Za-z0-9_.]*)(=)/y, (m) => [m[1] ? span("keyword", m[1]) : "", span("key", m[2]), m[3]]],
      [/[^=\n]+(?:=|$)/y, "bad"],
    ],
    inline: [SECRET, VAR],
  },
};

function span(cls: keyof typeof C, text: string): ReactNode {
  return <span className={C[cls]}>{text}</span>;
}

function apply(rule: Rule, line: string, at: number): { nodes: ReactNode[]; end: number } | null {
  const re = rule[0];
  re.lastIndex = at;
  const m = re.exec(line);
  if (!m || m[0].length === 0) return null;
  const nodes = typeof rule[1] === "function" ? rule[1](m) : [span(rule[1], m[0])];
  return { nodes, end: at + m[0].length };
}

export function highlight(text: string, lang: Lang): ReactNode {
  const { lineStart = [], inline } = RULES[lang];
  return text.split("\n").map((line, li) => {
    const out: ReactNode[] = [];
    let i = line.length - line.trimStart().length;
    out.push(line.slice(0, i));
    let plain = "";
    const flush = () => {
      if (plain) out.push(plain);
      plain = "";
    };
    for (const rule of lineStart) {
      const hit = apply(rule, line, i);
      if (hit) {
        out.push(...hit.nodes);
        i = hit.end;
        break;
      }
    }
    outer: while (i < line.length) {
      for (const rule of inline) {
        const hit = apply(rule, line, i);
        if (hit) {
          flush();
          out.push(...hit.nodes);
          i = hit.end;
          continue outer;
        }
      }
      plain += line[i++];
    }
    flush();
    return (
      <span key={li}>
        {out.map((n, k) => (typeof n === "string" ? n : <span key={k}>{n}</span>))}
        {"\n"}
      </span>
    );
  });
}

/** 光标前正在输入的 `[[xxx`，用来补全密钥名。 */
function secretPrefix(text: string, caret: number): string | null {
  const m = /\[\[([A-Za-z0-9_-]*)$/.exec(text.slice(0, caret));
  return m ? m[1] : null;
}

/** 文本里引用了但不存在的密钥。 */
export function missingSecrets(text: string, secrets: SecretView[] | null | undefined): string[] {
  if (!secrets) return [];
  const known = new Set(secrets.map((s) => s.name));
  return [...new Set([...text.matchAll(/\[\[([A-Za-z0-9_-]+)\]\]/g)].map((m) => m[1]))].filter((n) => !known.has(n));
}

/** 环境变量里重复的名字。 */
function duplicateKeys(text: string): string[] {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const line of text.split("\n")) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)=/.exec(line);
    if (!m) continue;
    if (seen.has(m[1])) dup.add(m[1]);
    seen.add(m[1]);
  }
  return [...dup];
}

/**
 * 带高亮的代码输入框：透明 textarea 叠在高亮层上。
 * `secrets` 打开后，输入 `[[` 会列出已有密钥，方向键选、回车或 Tab 补全。
 */
export function CodeEditor({
  id,
  lang,
  value,
  onChange,
  placeholder,
  secrets = false,
  className,
}: {
  id?: string;
  lang: Lang;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  secrets?: boolean;
  className?: string;
}) {
  const pre = useRef<HTMLPreElement>(null);
  const area = useRef<HTMLTextAreaElement>(null);
  const { data: all, refresh } = usePoll<SecretView[]>(secrets ? "/api/secrets" : null, 60000);
  const [prefix, setPrefix] = useState<string | null>(null);
  const [pick, setPick] = useState(0);
  const options = useMemo(
    () => (prefix === null || !all ? [] : all.filter((s) => s.name.toLowerCase().includes(prefix.toLowerCase())).slice(0, 8)),
    [prefix, all],
  );
  const missing = useMemo(() => (secrets ? missingSecrets(value, all) : []), [secrets, value, all]);
  const dup = useMemo(() => (lang === "env" ? duplicateKeys(value) : []), [lang, value]);

  const replaceAt = (start: number, end: number, text: string) => {
    const el = area.current;
    if (!el) return;
    onChange(value.slice(0, start) + text + value.slice(end));
    const caret = start + text.length;
    requestAnimationFrame(() => el.setSelectionRange(caret, caret));
  };

  const complete = (name: string) => {
    const el = area.current;
    if (!el || prefix === null) return;
    const caret = el.selectionStart;
    const closing = value.slice(caret, caret + 2) === "]]" ? 2 : 0;
    replaceAt(caret - prefix.length - 2, caret + closing, `[[${name}]]`);
    setPrefix(null);
  };

  const track = (el: HTMLTextAreaElement) => {
    if (!secrets) return;
    const p = secretPrefix(el.value, el.selectionStart);
    setPrefix(p);
    if (p !== prefix) setPick(0);
  };

  const shared = cn("col-start-1 row-start-1 m-0 min-h-24 w-full whitespace-pre-wrap break-words rounded-md border px-3 py-2 font-mono text-xs leading-5", className);
  return (
    <div className="grid gap-1.5">
      <div className="relative grid">
        <pre ref={pre} aria-hidden className={cn(shared, "pointer-events-none overflow-hidden border-transparent bg-card dark:bg-input/30")}>
          {highlight(value, lang)}
          {"\n"}
        </pre>
        <textarea
          ref={area}
          id={id}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          value={value}
          placeholder={placeholder}
          onChange={(e) => {
            onChange(e.target.value);
            track(e.target);
          }}
          onSelect={(e) => track(e.currentTarget)}
          onBlur={() => setTimeout(() => setPrefix(null), 120)}
          onKeyDown={(e) => {
            if (options.length) {
              if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                e.preventDefault();
                setPick((p) => (p + (e.key === "ArrowDown" ? 1 : options.length - 1)) % options.length);
                return;
              }
              if (e.key === "Enter" || e.key === "Tab") {
                e.preventDefault();
                complete(options[Math.min(pick, options.length - 1)].name);
                return;
              }
              if (e.key === "Escape") {
                e.stopPropagation();
                setPrefix(null);
                return;
              }
            }
            // YAML、脚本里 Tab 缩进两格，不跳出输入框。
            if (e.key === "Tab" && !e.shiftKey && lang !== "env") {
              e.preventDefault();
              const el = e.currentTarget;
              replaceAt(el.selectionStart, el.selectionEnd, "  ");
            }
          }}
          onScroll={(e) => {
            if (pre.current) pre.current.scrollTop = e.currentTarget.scrollTop;
          }}
          className={cn(
            shared,
            "resize-y border-input bg-transparent text-transparent caret-foreground outline-none selection:bg-primary/25 placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring/50",
          )}
        />
        {options.length > 0 && (
          <div className="absolute inset-x-2 top-full z-20 mt-1 grid overflow-hidden rounded-md border bg-popover p-1 text-xs shadow-md">
            {options.map((s, i) => (
              <button
                key={s.name}
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  complete(s.name);
                }}
                className={cn("flex items-center gap-2 rounded px-2 py-1 text-left font-mono", i === pick && "bg-accent")}
              >
                <span className="text-amber-700 dark:text-amber-400">[[{s.name}]]</span>
                {s.used_by?.length ? <span className="ml-auto font-sans text-muted-foreground">{s.used_by.join("、")} 在用</span> : null}
              </button>
            ))}
          </div>
        )}
      </div>
      {secrets && lang === "env" && <EnvTools secrets={all ?? []} onAdd={(k, ref) => onChange(setVar(value, k, ref))} refresh={refresh} />}
      {dup.length > 0 && <div className="text-xs text-amber-700 dark:text-amber-400">{dup.join("、")} 写了不止一次，以最后一行为准</div>}
      {secrets && (
        <div className="text-xs text-muted-foreground">
          {missing.length ? (
            <span className="text-destructive">还没有密钥 {missing.join("、")}，部署会失败。先到{" "}
              <Link to="/settings?tab=secrets" target="_blank" className="underline underline-offset-2">
                设置 → 密钥
              </Link>{" "}
              里添加。
            </span>
          ) : (
            <>
              输入 <code className="rounded bg-muted px-1">[[</code> 引用密钥，部署时替换成真实值，页面和历史里只留名字
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** 密钥名转成环境变量名：my-db-pass → MY_DB_PASS。 */
const envName = (s: string) => s.toUpperCase().replace(/[^A-Z0-9_]+/g, "_").replace(/^(\d)/, "_$1");

/** 设置一个变量：已有同名的行就替换那一行，没有就加到最后。 */
export function setVar(text: string, key: string, value: string): string {
  const lines = text.split("\n");
  const i = lines.findIndex((l) => new RegExp(`^\\s*(?:export\\s+)?${key.replace(/[.]/g, "\\.")}=`).test(l));
  if (i >= 0) return lines.map((l, k) => (k === i ? `${key}=${value}` : l)).join("\n");
  return [...lines.filter((l, k) => l.trim() || k < lines.length - 1), `${key}=${value}`].join("\n");
}

/** 环境变量下面的快捷入口：引用已有配置，或者新建一个（可选加密存成密钥）。 */
function EnvTools({ secrets, onAdd, refresh }: { secrets: SecretView[]; onAdd: (key: string, value: string) => void; refresh: () => void }) {
  const [q, setQ] = useState("");
  const [pickOpen, setPickOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [key, setKey] = useState("");
  const [val, setVal] = useState("");
  const [busy, setBusy] = useState(false);
  const [encrypt, setEncrypt] = useState(true);
  const shown = secrets.filter((s) => !s.managed && s.name.toLowerCase().includes(q.toLowerCase()));
  const name = envName(key);
  const exists = secrets.some((s) => s.name === name);

  const reset = () => (setKey(""), setVal(""), setNewOpen(false));
  const create = async () => {
    if (!encrypt) {
      onAdd(name, val);
      return reset();
    }
    setBusy(true);
    try {
      await api.put(`/api/secrets/${encodeURIComponent(name)}`, { value: val });
      onAdd(name, `[[${name}]]`);
      refresh();
      toast.success(`已加密保存 ${name}，并加到环境变量`);
      reset();
    } catch (e) {
      toast.error("配置没有保存", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Popover open={pickOpen} onOpenChange={setPickOpen}>
        <PopoverTrigger asChild>
          <Button type="button" size="xs" variant="outline">
            <KeyRoundIcon />
            引用已有配置
          </Button>
        </PopoverTrigger>
        <PopoverContent inline align="start" className="w-80 p-1.5">
          <Input autoFocus placeholder="搜索配置" value={q} onChange={(e) => setQ(e.target.value)} className="mb-1 h-8" />
          <div className="grid max-h-64 overflow-auto">
            {shown.map((s) => (
              <button
                key={s.name}
                type="button"
                onClick={() => {
                  onAdd(envName(s.name), `[[${s.name}]]`);
                  setPickOpen(false);
                }}
                className="flex items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-accent"
              >
                <span className="font-mono text-amber-700 dark:text-amber-400">{s.name}</span>
                {s.used_by?.length ? <span className="ml-auto truncate text-muted-foreground">{s.used_by.join("、")} 在用</span> : null}
              </button>
            ))}
            {shown.length === 0 && <div className="px-2 py-3 text-center text-xs text-muted-foreground">没有匹配的配置</div>}
          </div>
        </PopoverContent>
      </Popover>
      <Popover open={newOpen} onOpenChange={setNewOpen}>
        <PopoverTrigger asChild>
          <Button type="button" size="xs" variant="outline">
            <PlusIcon />
            新建配置并引用
          </Button>
        </PopoverTrigger>
        <PopoverContent inline align="start" className="w-80">
          <form
            className="grid gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (name && val && !(encrypt && exists)) create();
            }}
          >
            <Input autoFocus placeholder="变量名，例如 DB_PASSWORD" value={key} onChange={(e) => setKey(e.target.value)} className="h-8 font-mono text-xs" />
            {key && name !== key && <div className="text-xs text-muted-foreground">会保存为 {name}</div>}
            {encrypt && exists && <div className="text-xs text-amber-700 dark:text-amber-400">已经有配置 {name}，直接用"引用已有配置"</div>}
            <label className="flex items-center gap-2 text-xs">
              <input type="checkbox" checked={encrypt} onChange={(e) => setEncrypt(e.target.checked)} />
              加密保存（存到 设置 → 密钥，环境变量里只留引用）
            </label>
            <Input type={encrypt ? "password" : "text"} autoComplete="new-password" placeholder={encrypt ? "值（加密保存，页面上不再显示）" : "值（明文写进环境变量）"} value={val} onChange={(e) => setVal(e.target.value)} className="h-8 font-mono text-xs" />
            <Button size="sm" type="submit" disabled={busy || !name || !val || (encrypt && exists)}>
              保存并加入
            </Button>
          </form>
        </PopoverContent>
      </Popover>
      <span className="text-xs text-muted-foreground">也可以直接粘贴 .env 内容</span>
    </div>
  );
}
