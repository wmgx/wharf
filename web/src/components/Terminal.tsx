import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { RotateCwIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dot } from "./common";

type State = "connecting" | "open" | "closed";

/** 容器终端。`service` 是 compose 里的服务名，多容器时用。 */
export default function Terminal({ name, service }: { name: string; service?: string }) {
  const box = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<State>("connecting");
  const [round, setRound] = useState(0);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: '"Geist Mono", ui-monospace, monospace',
      fontSize: 13,
      theme: { background: "#0a0a0a" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();

    const q = new URLSearchParams({ cols: String(term.cols), rows: String(term.rows) });
    if (service) q.set("service", service);
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/services/${encodeURIComponent(name)}/terminal?${q}`);
    ws.binaryType = "arraybuffer";
    setState("connecting");
    const send = (m: object) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(m));
    ws.onopen = () => {
      setState("open");
      term.focus();
    };
    ws.onmessage = (e) => term.write(typeof e.data === "string" ? e.data : new Uint8Array(e.data));
    ws.onclose = () => setState("closed");
    const input = term.onData((data) => send({ data }));
    const resize = term.onResize(({ cols, rows }) => send({ cols, rows }));
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(el);

    return () => {
      observer.disconnect();
      input.dispose();
      resize.dispose();
      ws.close();
      term.dispose();
    };
  }, [name, service, round]);

  return (
    <div className="overflow-hidden rounded-xl border bg-[#0a0a0a]">
      <div className="flex items-center gap-2 border-b border-white/10 px-3 py-1.5 text-xs text-neutral-400">
        <Dot tone={state === "open" ? "ok" : state === "connecting" ? "warn" : "idle"} />
        {state === "open" ? "已连接" : state === "connecting" ? "连接中" : "已断开"}
        {state === "closed" && (
          <Button size="xs" variant="ghost" className="ml-auto text-neutral-300" onClick={() => setRound((n) => n + 1)}>
            <RotateCwIcon />
            重新连接
          </Button>
        )}
      </div>
      <div ref={box} className="h-[calc(100svh-22rem)] min-h-80 p-2" />
    </div>
  );
}
