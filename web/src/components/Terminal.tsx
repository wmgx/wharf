import { FitAddon } from "@xterm/addon-fit";
import { Terminal as XTerm } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { ArrowLeftIcon, ClipboardPasteIcon, RotateCwIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Dot } from "./common";

type State = "connecting" | "open" | "closed";
type Target = "service" | "host";

const FONT_KEY = "wharf-terminal-font-size";

function initialFontSize() {
  try {
    const value = Number(localStorage.getItem(FONT_KEY));
    return value >= 10 && value <= 20 ? value : 13;
  } catch {
    return 13;
  }
}

function modifiedInput(data: string, ctrl: boolean, alt: boolean) {
  if (data.length !== 1) return data;
  let output = data;
  if (ctrl) {
    const code = data.toUpperCase().charCodeAt(0);
    if (code >= 64 && code <= 95) output = String.fromCharCode(code & 31);
  }
  return alt ? `\x1b${output}` : output;
}

/** 服务容器和宿主机共用的终端。 */
export default function Terminal({
  name,
  service,
  target = "service",
  fullScreen = false,
  title,
  onBack,
}: {
  name: string;
  service?: string;
  target?: Target;
  fullScreen?: boolean;
  title?: string;
  onBack?: () => void;
}) {
  const root = useRef<HTMLDivElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const sendRef = useRef<(data: string) => void>(() => {});
  const forwardRef = useRef<(data: string, modifiers: boolean) => void>(() => {});
  const fitFrame = useRef<number | null>(null);
  const ctrlRef = useRef(false);
  const altRef = useRef(false);
  const [state, setState] = useState<State>("connecting");
  const [round, setRound] = useState(0);
  const [fontSize, setFontSize] = useState(initialFontSize);
  const [ctrl, setCtrl] = useState(false);
  const [alt, setAlt] = useState(false);
  const [pasteVisible, setPasteVisible] = useState(() => window.isSecureContext && !!navigator.clipboard?.readText);

  const scheduleFit = useCallback(() => {
    if (fitFrame.current != null) cancelAnimationFrame(fitFrame.current);
    fitFrame.current = requestAnimationFrame(() => {
      fitFrame.current = null;
      fitRef.current?.fit();
    });
  }, []);

  const clearModifiers = useCallback(() => {
    ctrlRef.current = false;
    altRef.current = false;
    setCtrl(false);
    setAlt(false);
  }, []);

  forwardRef.current = (data, modifiers) => {
    if (modifiers && (ctrlRef.current || altRef.current)) {
      const ctrlDown = ctrlRef.current;
      const altDown = altRef.current;
      clearModifiers();
      data = modifiedInput(data, ctrlDown, altDown);
    }
    sendRef.current(data);
    termRef.current?.focus();
  };

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    clearModifiers();
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: '"Geist Mono", ui-monospace, monospace',
      fontSize,
      scrollback: 2000,
      theme: { background: "#0a0a0a" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    termRef.current = term;
    fitRef.current = fit;
    const textarea = term.textarea;
    textarea?.setAttribute("autocapitalize", "off");
    textarea?.setAttribute("autocorrect", "off");
    if (textarea) textarea.spellcheck = false;
    const clearOnPaste = () => clearModifiers();
    textarea?.addEventListener("paste", clearOnPaste, true);
    textarea?.addEventListener("compositionstart", clearOnPaste, true);
    scheduleFit();

    const q = new URLSearchParams({ cols: String(term.cols), rows: String(term.rows) });
    if (service) q.set("service", service);
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const path = target === "host" ? `/api/servers/${encodeURIComponent(name)}/terminal` : `/api/services/${encodeURIComponent(name)}/terminal`;
    const ws = new WebSocket(`${proto}://${location.host}${path}?${q}`);
    ws.binaryType = "arraybuffer";
    setState("connecting");
    const send = (m: object) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(m));
    sendRef.current = (data) => send({ data });
    ws.onopen = () => {
      setState("open");
      send({ cols: term.cols, rows: term.rows });
      term.focus();
    };
    ws.onmessage = (e) => term.write(typeof e.data === "string" ? e.data : new Uint8Array(e.data));
    ws.onclose = () => setState("closed");
    const input = term.onData((data) => forwardRef.current(data, true));
    const resize = term.onResize(({ cols, rows }) => send({ cols, rows }));
    const observer = new ResizeObserver(scheduleFit);
    observer.observe(el);

    return () => {
      observer.disconnect();
      textarea?.removeEventListener("paste", clearOnPaste, true);
      textarea?.removeEventListener("compositionstart", clearOnPaste, true);
      input.dispose();
      resize.dispose();
      sendRef.current = () => {};
      ws.onopen = null;
      ws.onmessage = null;
      ws.onclose = null;
      ws.close();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [clearModifiers, name, round, scheduleFit, service, target]);

  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.options.fontSize = fontSize;
    scheduleFit();
  }, [fontSize, scheduleFit]);

  useEffect(() => {
    if (!fullScreen) return;
    const el = root.current;
    if (!el) return;
    const viewport = window.visualViewport;
    const resize = () => {
      el.style.top = `${viewport?.offsetTop ?? 0}px`;
      el.style.left = `${viewport?.offsetLeft ?? 0}px`;
      el.style.width = `${viewport?.width ?? window.innerWidth}px`;
      el.style.height = `${viewport?.height ?? window.innerHeight}px`;
      scheduleFit();
    };
    resize();
    (viewport ?? window).addEventListener("resize", resize);
    viewport?.addEventListener("scroll", resize);
    return () => {
      (viewport ?? window).removeEventListener("resize", resize);
      viewport?.removeEventListener("scroll", resize);
    };
  }, [fullScreen, scheduleFit]);

  useEffect(
    () => () => {
      if (fitFrame.current != null) cancelAnimationFrame(fitFrame.current);
    },
    [],
  );

  const changeFont = (next: number) => {
    next = Math.max(10, Math.min(20, next));
    setFontSize(next);
    try {
      localStorage.setItem(FONT_KEY, String(next));
    } catch {
      // 浏览器禁用本地存储时，只在当前页面生效。
    }
  };

  const toggleCtrl = () =>
    setCtrl((value) => {
      ctrlRef.current = !value;
      return !value;
    });
  const toggleAlt = () =>
    setAlt((value) => {
      altRef.current = !value;
      return !value;
    });
  const sendKey = (data: string, modifiers = false) => forwardRef.current(data, modifiers);
  const sendArrow = (key: "A" | "B" | "C" | "D") => sendKey(`\x1b${termRef.current?.modes.applicationCursorKeysMode ? "O" : "["}${key}`);
  const paste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      clearModifiers();
      termRef.current?.paste(text);
      termRef.current?.focus();
    } catch {
      setPasteVisible(false);
    }
  };

  return (
    <div
      ref={root}
      className={cn("overflow-hidden bg-[#0a0a0a]", fullScreen ? "fixed z-50 flex flex-col" : "rounded-xl border")}
    >
      <div className="flex min-h-10 flex-wrap items-center gap-2 border-b border-white/10 px-2 py-1.5 text-xs text-neutral-400">
        {onBack && (
          <Button size="xs" variant="ghost" className="text-neutral-300" onClick={onBack}>
            <ArrowLeftIcon />
            返回
          </Button>
        )}
        {title && <span className="font-medium text-neutral-200">{title}</span>}
        <Dot tone={state === "open" ? "ok" : state === "connecting" ? "warn" : "idle"} />
        {state === "open" ? "已连接" : state === "connecting" ? "连接中" : "已断开"}
        <div className="ml-auto flex items-center gap-1">
          <Button aria-label="减小字号" size="xs" variant="ghost" className="text-neutral-300" disabled={fontSize <= 10} onClick={() => changeFont(fontSize - 1)}>
            A−
          </Button>
          <span className="w-5 text-center tabular-nums">{fontSize}</span>
          <Button aria-label="增大字号" size="xs" variant="ghost" className="text-neutral-300" disabled={fontSize >= 20} onClick={() => changeFont(fontSize + 1)}>
            A+
          </Button>
          {pasteVisible && (
            <Button size="xs" variant="ghost" className="text-neutral-300" onClick={paste}>
              <ClipboardPasteIcon />
              粘贴
            </Button>
          )}
          {state === "closed" && (
            <Button size="xs" variant="ghost" className="text-neutral-300" onClick={() => setRound((n) => n + 1)}>
              <RotateCwIcon />
              重连
            </Button>
          )}
        </div>
      </div>
      <div ref={box} className={cn("overscroll-contain p-2", fullScreen ? "min-h-0 flex-1" : "h-[calc(100svh-22rem)] min-h-80")} />
      <div className="flex shrink-0 gap-1 overflow-x-auto border-t border-white/10 p-1.5 text-neutral-200">
        <TerminalKey label="Esc" onPress={() => sendKey("\x1b")} />
        <TerminalKey label="Tab" onPress={() => sendKey("\t")} />
        <TerminalKey label="Ctrl" active={ctrl} onPress={toggleCtrl} />
        <TerminalKey label="Alt" active={alt} onPress={toggleAlt} />
        <TerminalKey label="↑" aria="上" onPress={() => sendArrow("A")} />
        <TerminalKey label="↓" aria="下" onPress={() => sendArrow("B")} />
        <TerminalKey label="←" aria="左" onPress={() => sendArrow("D")} />
        <TerminalKey label="→" aria="右" onPress={() => sendArrow("C")} />
        {["|", "/", "-", "~"].map((key) => (
          <TerminalKey key={key} label={key} onPress={() => sendKey(key, true)} />
        ))}
      </div>
    </div>
  );
}

function TerminalKey({ label, aria, active, onPress }: { label: string; aria?: string; active?: boolean; onPress: () => void }) {
  return (
    <button
      type="button"
      aria-label={aria ?? label}
      aria-pressed={active == null ? undefined : active}
      className={cn(
        "h-10 min-w-11 shrink-0 rounded-md border border-white/15 bg-white/5 px-2 text-sm active:bg-white/20",
        active && "border-primary bg-primary/25 text-white",
      )}
      onPointerDown={(event) => event.preventDefault()}
      onClick={onPress}
    >
      {label}
    </button>
  );
}
