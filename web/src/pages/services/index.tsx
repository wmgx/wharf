import { PlusIcon } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CardsSkeleton, Empty, PageHeader, SectionTitle } from "@/components/common";
import { Segmented } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useStatus } from "@/status";
import { UnmanagedList, useUnmanaged } from "../containers";
import { EdgeList } from "../edge";
import { NewService } from "../NewService";
import { rowsOf, ServiceTable } from "./table";

export function ServicesPage() {
  const { status, refresh } = useStatus();
  const unmanaged = useUnmanaged();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [problems, setProblems] = useState(false);
  const server = params.get("server") ?? "";
  const rows = status ? rowsOf(status) : [];
  const problemCount = rows.filter((r) => r.tone === "warn" || r.tone === "bad").length;
  const filtered = rows.filter((r) => (!server || (r.svc ? r.where === server : server === "cloudflare")) &&
    [r.name, ...r.domains].some((s) => s.toLowerCase().includes(query.toLowerCase())) &&
    (!problems || r.tone === "warn" || r.tone === "bad"));
  const options: [string, string][] = [["", "全部"], ...(status?.servers.map((s): [string, string] => [s.name, s.name]) ?? []), ...(status?.edge_apps?.length ? [["cloudflare", "Cloudflare"] as [string, string]] : [])];
  const count = unmanaged.items.reduce((n, item) => n + item.containers.length, 0) + (status?.edge_unmanaged?.length ?? 0);
  const deploy = <Button onClick={() => { const next = new URLSearchParams(params); next.set("new", "1"); setParams(next); }}><PlusIcon />部署服务</Button>;
  return (
    <>
      <PageHeader title="服务" count={status ? rows.length : undefined} actions={deploy} />
      {status && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="max-w-full overflow-x-auto"><Segmented value={server} options={options} onChange={(value) => { const next = new URLSearchParams(params); if (value) next.set("server", value); else next.delete("server"); setParams(next); }} /></div>
          <Input className="w-48" placeholder="搜索" value={query} onChange={(e) => setQuery(e.target.value)} />
          {problemCount > 0 && <Button variant={problems ? "secondary" : "outline"} size="sm" onClick={() => setProblems(!problems)}>只看有问题的</Button>}
        </div>
      )}
      {!status ? <CardsSkeleton /> : rows.length === 0 ? <Empty action={deploy}>还没有服务</Empty> : filtered.length === 0 ? <Empty>没有符合条件的服务</Empty> : <ServiceTable status={status} rows={filtered} />}
      {count > 0 && <section className="mt-8"><SectionTitle count={count}>没纳管的</SectionTitle><div className="mt-3 grid gap-3"><UnmanagedList {...unmanaged} /><EdgeList /></div></section>}
      <NewService open={params.get("new") === "1"} onClose={() => { const next = new URLSearchParams(params); next.delete("new"); setParams(next); refresh(); }} />
    </>
  );
}
