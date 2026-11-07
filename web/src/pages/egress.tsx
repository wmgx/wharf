import { GlobeIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { SectionTitle } from "@/components/common";
import { Picker } from "@/components/fields";
import { useStatus } from "@/status";

/** 控制面调厂商 API（Cloudflare、Tailscale）用的出口。 */
export function Egress() {
  const { data, refresh } = usePoll<{ via?: string }>("/api/egress", 30000);
  const { status } = useStatus();
  const [saving, setSaving] = useState(false);
  const exits = (status?.servers ?? [])
    .filter((s) => s.settings.egress)
    .map((s) => s.name);
  const current = data?.via ?? "";

  const save = async (v: string) => {
    setSaving(true);
    try {
      await api.put("/api/egress", { via: v || null });
      toast.success(
        v ? `调厂商 API 改为按 ${v} 出口的规则分流` : "调厂商 API 改为直连",
      );
      refresh();
    } catch (e) {
      toast.error("没能保存", { description: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SectionTitle>出口</SectionTitle>
      {data && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border bg-card p-4 shadow-xs">
          <span className="grid size-9 place-items-center rounded-lg border bg-muted text-muted-foreground">
            <GlobeIcon className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="font-semibold">调厂商 API</div>
            <div className="text-xs text-muted-foreground">
              Cloudflare、Tailscale
            </div>
          </div>
          <div className="w-full sm:ml-auto sm:w-56">
            <Picker
              value={current}
              options={[
                { value: "", label: "直连" },
                ...exits.map((n) => ({
                  value: n,
                  label: `按 ${n} 出口的规则`,
                })),
                ...(current && !exits.includes(current)
                  ? [{ value: current, label: current }]
                  : []),
              ]}
              onChange={(v) => !saving && v !== current && save(v)}
            />
          </div>
        </div>
      )}
    </>
  );
}
