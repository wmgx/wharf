import { Tip } from "@/components/kit";
import { PencilIcon, PlusIcon, XIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, ApiError, usePoll } from "@/api";
import Terminal from "@/components/Terminal";
import { cn } from "@/lib/utils";

interface HostSession {
  name: string;
  attached: number;
  created: number;
}

const DEFAULT = "wharf";
const label = (name: string) => (name === DEFAULT ? "默认" : name.replace(/^wharf-/, "会话 "));

const VALID = /^[A-Za-z0-9_-]{1,64}$/;
const unique = (xs: string[]) => [...new Set(xs)];

/** 宿主机终端的多个会话：每个标签是宿主机上的一个 tmux 会话，关掉页面也还在。 */
export function HostSessions({ server }: { server: string }) {
  const path = `/api/servers/${encodeURIComponent(server)}/sessions`;
  const { data, refresh } = usePoll<HostSession[]>(path, 15000);
  // 页面上已经有的标签。会话列表读得慢或者读失败时，标签也不会消失；
  // 新建的会话要等终端连上才在机器上出现，也先记在这里。
  const [tabs, setTabs] = useState<string[]>([]);
  const [current, setCurrent] = useState<string | undefined>(undefined);

  const live = data?.map((s) => s.name) ?? [];
  const shown = unique([...tabs, ...live]);
  const names = shown.length ? shown : [DEFAULT];
  const active = current && names.includes(current) ? current : names[0];

  const create = () => {
    let n = 2;
    while (names.includes(`${DEFAULT}-${n}`)) n++;
    const name = `${DEFAULT}-${n}`;
    setTabs(unique([...names, name]));
    setCurrent(name);
  };

  const close = async (name: string) => {
    if (!window.confirm(`结束「${label(name)}」？里面还在运行的程序会一起结束。`)) return;
    try {
      if (live.includes(name)) await api.del(`${path}/${encodeURIComponent(name)}`);
      const rest = names.filter((x) => x !== name);
      setTabs(rest);
      if (name === active) setCurrent(rest[0]);
      refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "结束会话失败");
    }
  };

  const rename = async (name: string) => {
    const to = window.prompt("新的会话名（字母、数字、_、-）", name === DEFAULT ? "" : name)?.trim();
    if (!to || to === name) return;
    if (!VALID.test(to)) return toast.error("会话名只能用字母、数字、_ 和 -，最长 64 个字符");
    if (names.includes(to)) return toast.error(`已经有叫 ${to} 的会话了`);
    try {
      if (live.includes(name)) await api.put(`${path}/${encodeURIComponent(name)}`, { to });
      setTabs(names.map((x) => (x === name ? to : x)));
      if (name === active) setCurrent(to);
      refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "改名失败");
    }
  };

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-1">
        {names.map((name) => {
          const attached = data?.find((s) => s.name === name)?.attached ?? 0;
          return (
            <div
              key={name}
              className={cn(
                "group flex items-center rounded-md border text-sm transition-colors",
                name === active ? "bg-card font-medium shadow-xs" : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <button type="button" className="py-1 pr-1 pl-2.5" title="双击改名" onClick={() => setCurrent(name)} onDoubleClick={() => rename(name)}>
                {label(name)}
                {name !== active && attached > 0 && <span className="ml-1 text-xs text-muted-foreground">· 使用中</span>}
              </button>
              <Tip text="改名"><button
                type="button"
                aria-label={`给${label(name)}改名`}
                className="grid size-5 place-items-center rounded text-muted-foreground opacity-0 group-hover:opacity-60 hover:bg-accent hover:opacity-100 pointer-coarse:opacity-60"
                onClick={() => rename(name)}
              >
                <PencilIcon className="size-3" />
              </button></Tip>
              <Tip text="结束这个会话"><button
                type="button"
                aria-label={`结束${label(name)}`}
                className="mr-1 grid size-5 place-items-center rounded text-muted-foreground opacity-60 hover:bg-accent hover:opacity-100"
                onClick={() => close(name)}
              >
                <XIcon className="size-3.5" />
              </button></Tip>
            </div>
          );
        })}
        <button
          type="button"
          className="flex items-center gap-1 rounded-md px-2 py-1 text-sm text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={create}
        >
          <PlusIcon className="size-4" />
          新建会话
        </button>
      </div>
      <Terminal key={active} name={server} target="host" session={active} title={`${server} · ${label(active)}`} onConnected={refresh} />
    </div>
  );
}
