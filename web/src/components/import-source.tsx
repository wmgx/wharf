import { useState } from "react";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import type { ServiceDraft } from "@/types";

export type Imported = { kind: "run"; draft: ServiceDraft } | { kind: "url"; compose: string };

/** GitHub 网页链接换成原始文件：github.com/o/r/blob/<ref>/<路径> → raw.githubusercontent.com/o/r/<ref>/<路径>。 */
function rawUrl(url: string): string {
  const m = url.trim().match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
  return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}` : url.trim();
}

/** 在浏览器里取 compose 文件：15 秒超时，最大 1MB。网站不允许跨域读取时会失败。 */
async function fetchCompose(url: string): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    let res: Response;
    try {
      res = await fetch(rawUrl(url), { signal: ctrl.signal, credentials: "omit" });
    } catch {
      throw new Error("网页读不到这个网址，下载后贴进 compose.yaml");
    }
    if (!res.ok) throw new Error(`下载失败：HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > 1 << 20) throw new Error("文件超过 1MB，不像 compose 文件");
    if (!/^services\s*:/m.test(text)) throw new Error("内容里没有 services，不是 compose 文件");
    return text;
  } finally {
    clearTimeout(timer);
  }
}

/** 贴一条 docker run 命令或一个 compose 文件网址，识别后填进新建服务的表单。 */
export function ImportSource({ name, onImported }: { name?: string; onImported: (r: Imported) => void }) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);

  const run = async () => {
    const input = text.trim();
    if (!input || busy) return;
    setBusy(true);
    setError("");
    setWarnings([]);
    try {
      if (/^https?:\/\//.test(input)) {
        const compose = await fetchCompose(input);
        if (compose.includes("${")) setWarnings(["compose 里用了 ${变量}，原来靠 .env 文件提供的值要直接写进去，密码用 [[密钥名]]"]);
        onImported({ kind: "url", compose });
      } else {
        const draft = await api.post<ServiceDraft>("/api/convert/docker-run", { command: input, name: name || undefined });
        setWarnings(draft.warnings ?? []);
        onImported({ kind: "run", draft });
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-2">
      <div className="flex items-start gap-2">
        <Textarea
          rows={1}
          className="min-h-9 max-h-40 resize-none"
          placeholder="docker run … 或 compose 文件网址"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              run();
            }
          }}
        />
        <Button variant="outline" disabled={!text.trim() || busy} onClick={run}>
          {busy ? "识别中" : "识别"}
        </Button>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {warnings.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
          {warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
