import { useState } from "react";
import { usePoll } from "@/api";
import { Field, Picker } from "@/components/fields";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { EgressPreset, EgressSpec } from "@/types";

/** 服务器设置里的出口：提供出口（规则）和经哪台出口。 */
export function EgressFields({
  server,
  egress,
  onEgress,
  via,
  onVia,
}: {
  server: string;
  egress?: EgressSpec;
  onEgress: (v: EgressSpec | undefined) => void;
  via: string;
  onVia: (v: string) => void;
}) {
  const { data } = usePoll<{ presets: EgressPreset[] }>("/api/egress", 60000);
  const { status } = useStatus();
  const presets = data?.presets ?? [];
  const exits = (status?.servers ?? [])
    .filter((s) => s.name !== server && s.settings.egress)
    .map((s) => s.name);
  const [domains, setDomains] = useState((egress?.domains ?? []).join("\n"));

  const update = (patch: Partial<EgressSpec>) =>
    onEgress({ ...egress, ...patch });
  const togglePreset = (name: string, on: boolean) => {
    const cur = egress?.presets ?? [];
    update({ presets: on ? [...cur, name] : cur.filter((p) => p !== name) });
  };
  const setDomainText = (text: string) => {
    setDomains(text);
    const list = text
      .split(/[\s,]+/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    update({ domains: list.length ? list : undefined });
  };

  return (
    <>
      <Field
        label="访问外网经过"
        help="这台访问 GitHub、海外镜像仓库等被墙的网站时，借选中的机器转发，其余照常直连；那台连不上时也直连。设了它，下面两项单独的代理不再生效。"
      >
        <Picker
          value={via}
          options={[
            { value: "", label: "不借道，直接访问" },
            ...exits.map((n) => ({ value: n, label: n })),
            ...(via && !exits.includes(via)
              ? [{ value: via, label: via, hint: "那台没开代理" }]
              : []),
          ]}
          onChange={onVia}
        />
      </Field>
      <div className="grid gap-3 rounded-lg border p-3">
        <label className="flex cursor-pointer items-center gap-2.5 text-sm font-medium">
          <Checkbox
            checked={!!egress}
            onCheckedChange={(v) =>
              onEgress(v === true ? { presets: ["github"] } : undefined)
            }
          />
          给其他机器当代理
          <span className="font-normal text-muted-foreground">
            （其他机器可以借这台访问外网，只在内网开放、需要口令）
          </span>
        </label>
        {egress && (
          <>
            <label className="flex cursor-pointer items-center gap-2.5 text-sm">
              <Checkbox
                checked={!!egress.all}
                onCheckedChange={(v) =>
                  update({ all: v === true || undefined })
                }
              />
              所有网站都可以借道（不只下面勾选的）
            </label>
            {!egress.all && (
              <>
                <div className="grid gap-2 sm:grid-cols-2">
                  {presets.map((p) => (
                    <label
                      key={p.name}
                      className="flex cursor-pointer items-start gap-2.5 text-sm"
                      title={p.domains.join("\n")}
                    >
                      <Checkbox
                        className="mt-0.5"
                        checked={(egress.presets ?? []).includes(p.name)}
                        onCheckedChange={(v) =>
                          togglePreset(p.name, v === true)
                        }
                      />
                      <span>
                        {p.label}
                        <span className="block text-xs text-muted-foreground">
                          {p.domains.slice(0, 2).join("、")}
                          {p.domains.length > 2 ? " 等" : ""}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
                <Field help="自定义域名，一行一个。example.com 只匹配它自己，*.example.com 匹配所有子域名。">
                  <Textarea
                    className="min-h-16 font-mono text-xs"
                    value={domains}
                    placeholder={"api.example.com\n*.example.org"}
                    onChange={(e) => setDomainText(e.target.value)}
                  />
                </Field>
              </>
            )}
          </>
        )}
      </div>
    </>
  );
}
