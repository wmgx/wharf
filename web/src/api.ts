import { useCallback, useEffect, useRef, useState } from "react";
import type { ApiErrorBody, Change, Plan, Run } from "./types";

const TOKEN_KEY = "wharf.token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // 隐私模式下存不了，只在本次页面里有效。
  }
}

export class ApiError extends Error {
  constructor(
    public body: ApiErrorBody,
    public status: number,
  ) {
    super(body.message);
  }
}

/** 登录失效时通知外层回到登录页。 */
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function headers(json: boolean): HeadersInit {
  const h: Record<string, string> = {};
  const token = getToken();
  if (token) h.Authorization = `Bearer ${token}`;
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers: headers(body !== undefined),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError({ code: "Network", message: "连不上控制面，检查网络或控制面是否在运行" }, 0);
  }
  const text = await resp.text();
  if (!resp.ok) {
    if (resp.status === 401) onUnauthorized();
    let parsed: ApiErrorBody;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { code: "Http", message: `控制面返回 HTTP ${resp.status}` };
    }
    throw new ApiError(parsed, resp.status);
  }
  return (text ? JSON.parse(text) : null) as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown) => request<T>("POST", path, body),
  put: <T,>(path: string, body: unknown) => request<T>("PUT", path, body),
  plan: (changes: Change[]) => request<Plan>("POST", "/api/plan", { changes }),
  apply: (plan_id: string, confirm: string[]) =>
    request<{ run_id: string }>("POST", "/api/apply", { plan_id, confirm }),
  run: (id: string) => request<Run>("GET", `/api/runs/${id}`),
  cancelRun: (id: string) => request<unknown>("POST", `/api/runs/${id}/cancel`, {}),
};

/**
 * 读取分块的日志流，每收到一行调用一次 onLine。返回的函数用于停止。
 * 连接断开后 3 秒自动重连（控制面那边的跟随有最长时长）。
 */
export function followLogs(path: string, onLine: (line: string) => void, onState: (live: boolean) => void) {
  let stopped = false;
  let controller: AbortController | null = null;
  let tail = 200;

  const connect = async () => {
    controller = new AbortController();
    try {
      const resp = await fetch(`${path}?tail=${tail}`, { headers: headers(false), signal: controller.signal });
      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`);
      onState(true);
      // 重连时不再重复拉历史。
      tail = 0;
      const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += value;
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        lines.forEach(onLine);
      }
    } catch {
      // 断开或被停止，下面统一处理。
    }
    onState(false);
    if (!stopped) setTimeout(connect, 3000);
  };
  connect();
  return () => {
    stopped = true;
    controller?.abort();
  };
}

/** 定时拉取一个接口。返回数据、错误和手动刷新。 */
export function usePoll<T>(path: string | null, intervalMs = 5000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const pathRef = useRef(path);
  pathRef.current = path;

  const refresh = useCallback(async () => {
    const p = pathRef.current;
    if (!p) return;
    try {
      const v = await api.get<T>(p);
      if (pathRef.current === p) {
        setData(v);
        setError(null);
      }
    } catch (e) {
      setError(e as ApiError);
    }
  }, []);

  useEffect(() => {
    setData(null);
    refresh();
    if (!path) return;
    const t = setInterval(refresh, intervalMs);
    const onFocus = () => refresh();
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(t);
      window.removeEventListener("focus", onFocus);
    };
  }, [path, intervalMs, refresh]);

  return { data, error, refresh };
}
