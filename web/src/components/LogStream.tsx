import { useEffect, useRef, useState } from "react";
import { followLogs } from "../api";

const MAX_LINES = 3000;

/** 实时日志面板。`path` 是 `/api/.../logs/stream`。 */
export function LogStream({ path }: { path: string }) {
  const [lines, setLines] = useState<string[]>([]);
  const [live, setLive] = useState(false);
  const [paused, setPaused] = useState(false);
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
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      });
    };
    const stop = followLogs(
      path,
      (line) => {
        pending.push(line);
        if (!frame) frame = requestAnimationFrame(flush);
      },
      setLive,
    );
    return () => {
      stop();
      if (frame) cancelAnimationFrame(frame);
    };
  }, [path]);

  useEffect(() => {
    const el = box.current;
    if (el && stick.current && !paused) el.scrollTop = el.scrollHeight;
  }, [lines, paused]);

  const onScroll = () => {
    const el = box.current;
    if (el) stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <div>
      <div className="console-bar">
        <span className={`light ${live ? "go" : ""}`} />
        <span>{live ? "LIVE · 实时" : "连接中…"}</span>
        <span className="grow" />
        <span>{lines.length} 行</span>
        <button className="btn small ghost" onClick={() => setPaused((p) => !p)}>
          {paused ? "继续滚动" : "暂停滚动"}
        </button>
        <button className="btn small ghost" onClick={() => setLines([])}>
          清屏
        </button>
      </div>
      <div className="console" ref={box} onScroll={onScroll}>
        {lines.length === 0 && <span className="ts">等待日志…</span>}
        {lines.map((l, i) => (
          <LogLine key={i} line={l} />
        ))}
      </div>
    </div>
  );
}

/** compose 日志格式：`服务-1  | 2026-10-20T12:00:00.000Z 内容`。把时间戳调暗。 */
function LogLine({ line }: { line: string }) {
  if (line.startsWith("[wharf]")) return <div className="sys">{line}</div>;
  const m = line.match(/^(.*?\|\s*)?(\d{4}-\d\d-\d\dT[\d:.]+Z?)\s(.*)$/);
  if (!m) return <div>{line}</div>;
  const time = m[2].slice(11, 19);
  const isErr = /\b(error|fatal|panic|exception)\b/i.test(m[3]);
  return (
    <div>
      <span className="ts">{time} </span>
      <span className={isErr ? "err" : undefined}>{m[3]}</span>
    </div>
  );
}
