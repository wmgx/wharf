import { useState } from "react";
import { usePoll } from "@/api";
import { Field, Picker, Segmented } from "@/components/fields";
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
  const users = (status?.servers ?? []).filter((s) => s.settings.via === server).map((s) => s.name);
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
        label="访问外网"
        help="访问 GitHub、海外镜像仓库这类地址时经选中的机器出去，其余直接访问；那台连不上时也直接访问。"
      >
        <Picker
          value={via}
          options={[
            { value: "", label: "直接访问" },
            ...exits.map((n) => ({ value: n, label: `经 ${n}` })),
            ...(via && !exits.includes(via)
              ? [{ value: via, label: `经 ${via}`, hint: "那台没开出口" }]
              : []),
          ]}
          onChange={onVia}
        />
      </Field>
      <div className="grid gap-3 rounded-lg border p-3">
        <label className="flex cursor-pointer items-center gap-2.5 text-sm font-medium">
          <Checkbox
            checked={!!egress}
            disabled={users.length > 0}
            onCheckedChange={(v) =>
              onEgress(v === true ? { presets: ["github"] } : undefined)
            }
          />
          允许其他机器经这台访问外网
        </label>
        <span className="text-xs text-muted-foreground">{users.length ? `${users.join("、")} 正经这台访问外网，先改它们的设置。` : "只在内网地址上开放，带口令。"}</span>
        {egress && (
          <>
            <Field label="范围">
              <Segmented value={egress.all ? "all" : "sites"} options={[["sites", "指定的网站"], ["all", "全部"]]} onChange={(v) => update({ all: v === "all" || undefined })} />
            </Field>
            {!egress.all && (
              <>
                <span className="text-sm">常用网站</span>
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
                <Field label="其他域名" help="一行一个。example.com 只匹配它自己，*.example.com 匹配所有子域名。">
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
