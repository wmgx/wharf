import { Tip } from "@/components/kit";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  DownloadIcon,
  EraserIcon,
  PauseIcon,
  PlayIcon,
  SearchIcon,
} from "lucide-react";
import { followLogs } from "@/api";
import { Segmented } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dot } from "./common";

const MAX_LINES = 5000;
const ERROR_RE = /\b(error|fatal|panic|exception|failed|traceback)\b/i;

/** 实时日志面板。`path` 是 `/api/.../logs/stream`。可以过滤关键字、只看错误、往回多看几行、下载。 */
export function LogStream({ path }: { path: string }) {
  const [lines, setLines] = useState<string[]>([]);
  const [live, setLive] = useState(false);
  const [paused, setPaused] = useState(false);
  const [tail, setTail] = useState("200");
  const [query, setQuery] = useState("");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const stick = useRef(true);

  useEffect(() => {
    setLines([]);
    let pending: string[] = [];
    // 合并到下一帧再渲染，日志很快时不卡。
    let frame = 0;
    const flush = () => {
      frame = 0;
      const add = pending;
      pending = [];
      setLines((prev) => {
        const next = prev.concat(add);
        return next.length > MAX_LINES
          ? next.slice(next.length - MAX_LINES)
          : next;
      });
    };
    const stop = followLogs(
      path,
      (line) => {
        pending.push(line);
        if (!frame) frame = requestAnimationFrame(flush);
      },
      setLive,
      Number(tail),
    );
    return () => {
      stop();
      if (frame) cancelAnimationFrame(frame);
    };
  }, [path, tail]);

  const q = query.trim().toLowerCase();
  const shown = useMemo(
    () =>
      lines.filter(
        (l) =>
          (!errorsOnly || ERROR_RE.test(l)) &&
          (!q || l.toLowerCase().includes(q)),
      ),
    [lines, errorsOnly, q],
  );
  const filtering = errorsOnly || !!q;

  useEffect(() => {
    const el = box.current;
    if (el && stick.current && !paused) el.scrollTop = el.scrollHeight;
  }, [shown, paused]);

  const onScroll = () => {
    const el = box.current;
    if (el)
      stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  const download = () => {
    const blob = new Blob([shown.join("\n") + "\n"], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2 text-xs text-muted-foreground">
        <Dot tone={live ? "ok" : "idle"} />
        <span>{live ? "实时" : "连接中…"}</span>
        <div className="relative min-w-40 flex-1">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2" />
          <Input
            className="h-7 pl-7 text-xs"
            value={query}
            placeholder="过滤关键字"
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <Button
          variant={errorsOnly ? "secondary" : "ghost"}
          size="xs"
          onClick={() => setErrorsOnly((v) => !v)}
        >
          只看错误
        </Button>
        <Segmented
          value={tail}
          options={[
            ["200", "200 行"],
            ["1000", "1000"],
            ["5000", "5000"],
          ]}
          onChange={setTail}
        />
        <span className="tabular-nums">
          {filtering
            ? `${shown.length} / ${lines.length} 行`
            : `${lines.length} 行`}
        </span>
        <Tip text={paused ? "继续滚动" : "暂停滚动"}><Button
          variant="ghost"
          size="xs"
          onClick={() => setPaused((p) => !p)}
          aria-label={paused ? "继续滚动" : "暂停滚动"}
        >
          {paused ? <PlayIcon /> : <PauseIcon />}
        </Button></Tip>
        <Tip text="下载当前显示的日志"><Button
          variant="ghost"
          size="xs"
          onClick={download}
          disabled={!shown.length}
          aria-label="下载当前显示的日志"
        >
          <DownloadIcon />
        </Button></Tip>
        <Tip text="清屏"><Button
          variant="ghost"
          size="xs"
          onClick={() => setLines([])}
          aria-label="清屏"
        >
          <EraserIcon />
        </Button></Tip>
      </div>
      <div
        className="h-[60vh] min-h-72 overflow-auto bg-muted/30 px-3.5 py-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap"
        ref={box}
        onScroll={onScroll}
      >
        {shown.length === 0 && (
          <span className="text-muted-foreground">
            {filtering && lines.length ? "没有匹配的行" : "等待日志…"}
          </span>
        )}
        {shown.map((l, i) => (
          <LogLine key={i} line={l} query={q} />
        ))}
      </div>
    </div>
  );
}

/** compose 日志格式：`服务-1  | 2026-10-20T12:00:00.000Z 内容`。时间戳调暗，错误标红，匹配的关键字高亮。 */
function LogLine({ line, query }: { line: string; query: string }) {
  if (line.startsWith("[wharf]"))
    return <div className="text-warning">{line}</div>;
  const m = line.match(/^(.*?\|\s*)?(\d{4}-\d\d-\d\dT[\d:.]+Z?)\s(.*)$/);
  const time = m ? m[2].slice(11, 19) : null;
  const body = m ? m[3] : line;
  return (
    <div>
      {time && <span className="text-muted-foreground">{time} </span>}
      <span className={ERROR_RE.test(body) ? "text-destructive" : undefined}>
        {mark(body, query)}
      </span>
    </div>
  );
}

function mark(text: string, query: string) {
  if (!query) return text;
  const parts: React.ReactNode[] = [];
  const lower = text.toLowerCase();
  let at = 0;
  for (let i = lower.indexOf(query); i >= 0; i = lower.indexOf(query, at)) {
    parts.push(
      text.slice(at, i),
      <mark key={i} className="rounded-sm bg-warning/40 text-inherit">
        {text.slice(i, i + query.length)}
      </mark>,
    );
    at = i + query.length;
  }
  parts.push(text.slice(at));
  return parts;
}
