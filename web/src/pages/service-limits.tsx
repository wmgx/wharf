import { GaugeIcon } from "lucide-react";
import { useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Field } from "@/components/fields";
import { bytes } from "@/components/metrics";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { ServiceView } from "@/types";

interface MetricsView {
  series: Record<string, [number, number][]>;
}

export function LimitsCard({ svc }: { svc: ServiceView }) {
  const actions = useActions();
  const cur = svc.spec.limits;
  const [editing, setEditing] = useState(false);
  const [memory, setMemory] = useState(cur?.memory_mb?.toString() ?? "");
  const [cpus, setCpus] = useState(cur?.cpu_milli ? String(cur.cpu_milli / 1000) : "");
  const compose = "compose" in svc.spec.source;
  const { data } = usePoll<MetricsView>(compose ? null : `/api/metrics?subject=${encodeURIComponent(svc.name)}&range=7d`, 60000);
  const points = data?.series["svc.mem"] ?? [];
  const peak = points.reduce((max, [, value]) => Math.max(max, value), 0);
  const memoryNum = memory.trim() ? Number(memory) : undefined;
  const cpuNum = cpus.trim() ? Number(cpus) : undefined;
  const valid =
    (memoryNum === undefined || (Number.isInteger(memoryNum) && memoryNum >= 32 && memoryNum <= 4294967295)) &&
    (cpuNum === undefined || (Number.isFinite(cpuNum) && cpuNum >= 0.01 && cpuNum * 1000 <= 4294967295));

  if (compose) return null;

  const save = () => {
    const limits = memoryNum === undefined && cpuNum === undefined ? undefined : {
      memory_mb: memoryNum,
      cpu_milli: cpuNum === undefined ? undefined : Math.round(cpuNum * 1000),
    };
    actions.plan({
      title: `设置 ${svc.name} 的资源上限`,
      changes: [{ op: "upsert_service", name: svc.name, spec: { ...svc.spec, limits } }],
    });
    setEditing(false);
  };

  return (
    <Card className="gap-3 py-5 shadow-xs">
      <CardContent className="grid gap-3 px-5">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <GaugeIcon className="size-4 text-muted-foreground" />
          <span className="font-medium">资源上限</span>
          <span className="text-muted-foreground">
            {[
              cur?.memory_mb === undefined ? "" : `内存 ${cur.memory_mb} MB`,
              cur?.cpu_milli === undefined ? "" : `CPU ${cur.cpu_milli / 1000} 核`,
            ].filter(Boolean).join(" · ") || "不限"}
          </span>
          {!editing && (
            <Button variant="ghost" size="xs" className="ml-auto" onClick={() => {
              setMemory(cur?.memory_mb?.toString() ?? "");
              setCpus(cur?.cpu_milli === undefined ? "" : String(cur.cpu_milli / 1000));
              setEditing(true);
            }}>
              修改
            </Button>
          )}
        </div>
        {editing && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="内存（MB）" htmlFor={`${svc.name}-memory-limit`}>
              <Input id={`${svc.name}-memory-limit`} type="number" min={32} step={1} value={memory} onChange={(e) => setMemory(e.target.value)} />
              {points.length > 0 && <span className="text-xs text-muted-foreground">近 7 天最高 {bytes(peak)}</span>}
            </Field>
            <Field label="CPU（核）" htmlFor={`${svc.name}-cpu-limit`}>
              <Input id={`${svc.name}-cpu-limit`} type="number" min={0.01} step={0.01} value={cpus} onChange={(e) => setCpus(e.target.value)} />
            </Field>
            <div className="flex flex-wrap gap-2 sm:col-span-2">
              <Button size="sm" disabled={!valid} onClick={save}>预览改动</Button>
              <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>取消</Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
