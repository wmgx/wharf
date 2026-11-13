import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { SectionTitle } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { Panel, Tip } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { EgressPreset, EgressSpec, Status } from "@/types";

export function egressText(egress: EgressSpec | undefined, presets: EgressPreset[]): string {
  if (!egress) return "-";
  if (egress.all) return "全部网站";
  const names = egress.presets ?? [];
  const labels = names.slice(0, 2).map((name) => presets.find((p) => p.name === name)?.label ?? name);
  const domains = egress.domains?.length ?? 0;
  return `${labels.join("、")}${names.length ? `等 ${names.length} 组` : ""}${domains ? `${names.length ? " + " : ""}${domains} 个域名` : ""}` || "-";
}

export function Egress({ status }: { status: Status }) {
  const nav = useNavigate();
  const { data, refresh } = usePoll<{ via?: string; presets: EgressPreset[] }>("/api/egress", 30000);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const current = data?.via ?? "";
  useEffect(() => { setValue(current); }, [current]);
  const exits = status.servers.filter((s) => s.settings.egress).map((s) => s.name);
  const save = async () => { setSaving(true); try { await api.put("/api/egress", { via: value || null }); toast.success("已保存"); refresh(); } catch(e) { toast.error("没能保存", { description: (e as Error).message }); } finally { setSaving(false); } };
  return <>
    <SectionTitle>各台机器</SectionTitle>
    {!status.servers.some((s) => s.settings.egress || s.settings.via) && <p className="mb-3 text-sm text-muted-foreground">所有机器都直接访问外网。</p>}
    <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>服务器</TableHead>
            <TableHead>访问外网</TableHead>
            <TableHead>作为出口</TableHead>
            <TableHead>谁在用</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {status.servers.map((s) => {
            const via = s.settings.via;
            const missing = via && !exits.includes(via);
            const users = status.servers.filter((x) => x.settings.via === s.name).map((x) => x.name);
            return <TableRow key={s.name}>
              <TableCell>
                {s.name}
              </TableCell>
              <TableCell>
                {missing ? <Tip text={`${via} 没开出口，现在其实是直接访问`}>
                  <span className="text-warning">经 {via}
                  </span>
                </Tip> : via ? `经 ${via}` : "直接访问"}
              </TableCell>
              <TableCell>
                {egressText(s.settings.egress, data?.presets ?? [])}
              </TableCell>
              <TableCell>
                {users.join("、") || "-"}
              </TableCell>
              <TableCell>
                <Button variant="ghost" size="xs" onClick={() => nav(`/servers/${encodeURIComponent(s.name)}?tab=settings#egress`)}>修改</Button>
              </TableCell>
            </TableRow>;
          })}
        </TableBody>
      </Table>
    </Panel>
    <SectionTitle>控制面</SectionTitle>
    <Panel className="p-4">
      <Field label="访问厂商接口" help="控制面调 Cloudflare、Tailscale 的接口时怎么出去。">
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-48 flex-1">
            <Picker value={value} options={[{ value: "", label: "直接访问" }, ...exits.map((name) => ({ value: name, label: `经 ${name}` })), ...(value && !exits.includes(value) ? [{ value, label: `经 ${value}` }] : [])]} onChange={setValue} />
          </div>
          <Button disabled={!data || saving || value === current} onClick={save}>保存</Button>
        </div>
      </Field>
    </Panel>
  </>;
}
