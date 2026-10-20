import { CheckIcon, ChevronsUpDownIcon, PlusIcon, XIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import type { GatewayView, PortSpec, ServerView } from "@/types";
import { Dot, serverText, serverTone, type Tone } from "./common";

/** `KEY=VALUE` 一行一个，和 .env 一样写法。 */
export function parseEnv(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i <= 0) continue;
    env[line.slice(0, i).trim()] = line.slice(i + 1);
  }
  return env;
}

export function formatEnv(env?: Record<string, string>): string {
  return Object.entries(env ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
}

/** 名称规则和后端一致：小写字母、数字、减号。 */
export function toName(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

/** `ghcr.io/foo/bar-app:1.2` → `bar-app` */
export function nameFromImage(image: string): string {
  const last = image.split("@")[0].split("/").pop() ?? "";
  return toName(last.split(":")[0]);
}

export function Field({ label, htmlFor, help, children }: { label?: ReactNode; htmlFor?: string; help?: ReactNode; children: ReactNode }) {
  return (
    <div className="grid gap-2">
      {label && <Label htmlFor={htmlFor}>{label}</Label>}
      {children}
      {help && <p className="text-xs text-muted-foreground">{help}</p>}
    </div>
  );
}

/** 两三个选项的分段选择。 */
export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex w-fit gap-0.5 rounded-lg border bg-muted p-0.5">
      {options.map(([v, label]) => (
        <button
          key={v}
          type="button"
          onClick={() => onChange(v)}
          className={cn(
            "h-7 rounded-md border border-transparent px-3 text-sm text-muted-foreground transition-colors hover:text-foreground",
            value === v && "border-border bg-card font-medium text-foreground shadow-sm dark:border-input dark:bg-input/60",
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

export function PortsEditor({ ports, onChange }: { ports: PortSpec[]; onChange: (p: PortSpec[]) => void }) {
  const set = (i: number, patch: Partial<PortSpec>) => onChange(ports.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  return (
    <div className="grid gap-2">
      {ports.map((p, i) => (
        <div className="flex gap-2" key={i}>
          <Input placeholder="名称，例如 http" value={p.name} onChange={(e) => set(i, { name: toName(e.target.value) })} />
          <Input type="number" placeholder="容器端口" value={p.port || ""} onChange={(e) => set(i, { port: Number(e.target.value) })} />
          <Button type="button" variant="ghost" size="icon" aria-label="移除端口" onClick={() => onChange(ports.filter((_, j) => j !== i))}>
            <XIcon />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-fit"
        onClick={() => onChange([...ports, { name: ports.length ? `p${ports.length + 1}` : "http", port: 0 }])}
      >
        <PlusIcon />
        端口
      </Button>
    </div>
  );
}

interface Option {
  value: string;
  label: string;
  tone?: Tone;
  hint?: string;
  disabled?: boolean;
}

/** 可以输入筛选的下拉选择。 */
export function Picker({ id, value, options, onChange, placeholder }: { id?: string; value: string; options: Option[]; onChange: (v: string) => void; placeholder?: string }) {
  const [open, setOpen] = useState(false);
  const current = options.find((o) => o.value === value);
  return (
    // modal：放在抽屉或对话框里时，弹层自己也要能接收点击。
    <Popover open={open} onOpenChange={setOpen} modal>
      <PopoverTrigger asChild>
        <Button id={id} variant="outline" role="combobox" aria-expanded={open} className="w-full justify-between font-normal">
          {current ? (
            <span className="flex min-w-0 items-center gap-2">
              {current.tone && <Dot tone={current.tone} />}
              <span className="truncate">{current.label}</span>
              {current.hint && <span className="text-xs text-muted-foreground">{current.hint}</span>}
            </span>
          ) : (
            <span className="text-muted-foreground">{placeholder ?? "选择…"}</span>
          )}
          <ChevronsUpDownIcon className="opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-(--radix-popover-trigger-width) p-0" align="start">
        <Command>
          <CommandInput placeholder="输入筛选…" />
          <CommandList>
            <CommandEmpty>没有匹配的选项</CommandEmpty>
            <CommandGroup>
              {options.map((o) => (
                <CommandItem
                  key={o.value}
                  value={`${o.label} ${o.hint ?? ""}`}
                  disabled={o.disabled}
                  onSelect={() => {
                    onChange(o.value);
                    setOpen(false);
                  }}
                >
                  {o.tone && <Dot tone={o.tone} />}
                  <span>{o.label}</span>
                  {o.hint && <span className="text-xs text-muted-foreground">{o.hint}</span>}
                  <CheckIcon className={cn("ml-auto", o.value === value ? "opacity-100" : "opacity-0")} />
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

export function serverOptions(servers: ServerView[]): Option[] {
  return [...servers]
    .sort((a, b) => Number(b.online) - Number(a.online))
    .map((s) => ({ value: s.name, label: s.name, tone: serverTone(s), hint: serverText(s) }));
}

export function gatewayOptions(gateways: GatewayView[]): Option[] {
  return gateways.map((g) => ({ value: g.name, label: g.name, hint: `${g.spec.server}${g.spec.default ? " · 默认" : ""}` }));
}

/** 域名建议：已有域名的后缀 + 厂商账号里的 zone。 */
export function DomainChips({ suggestions, onPick }: { suggestions: string[]; onPick: (s: string) => void }) {
  if (!suggestions.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {suggestions.map((s) => (
        <button
          type="button"
          key={s}
          onClick={() => onPick(s)}
          className="h-6 rounded-full border px-2.5 font-mono text-xs text-muted-foreground transition-colors hover:border-primary hover:bg-primary/5 hover:text-primary"
        >
          {s}
        </button>
      ))}
    </div>
  );
}
