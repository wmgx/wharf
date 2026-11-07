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
        label="经哪台出口"
        help="本机起分流代理：拉镜像、构建、拉代码按那台出口的规则走，其余直连；出口连不上时直连。设了它，下面两项代理不再生效。"
      >
        <Picker
          value={via}
          options={[
            { value: "", label: "不经出口" },
            ...exits.map((n) => ({ value: n, label: n })),
            ...(via && !exits.includes(via)
              ? [{ value: via, label: via, hint: "没有提供出口" }]
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
          提供出口
          <span className="font-normal text-muted-foreground">
            （在内网地址上起要口令的 HTTP 代理）
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
              全部走出口（内网地址除外）
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
