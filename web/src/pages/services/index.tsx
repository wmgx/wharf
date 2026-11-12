import { PlusIcon } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { CardsSkeleton, PageHeader } from "@/components/common";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useStatus } from "@/status";
import { UnmanagedList } from "../containers";
import { EdgeList } from "../edge";
import { NewService } from "../NewService";
import { ServiceTable } from "./table";

export function ServicesPage() {
  const { status, refresh } = useStatus();
  const [params, setParams] = useSearchParams();
  const [server, setServer] = useState<string | undefined>();
  const where = status ? [...status.servers.map((s) => s.name), ...(status.edge_apps?.length ? ["cloudflare"] : [])] : [];
  return (
    <>
      <PageHeader title="服务" count={status ? status.services.length + (status.edge_apps?.length ?? 0) : undefined} actions={<Button onClick={() => setParams({ new: "1" })}><PlusIcon />部署服务</Button>} />
      {status && (
        <div className="mb-4 flex flex-wrap items-center gap-1">
          {[undefined, ...where].map((w) => (
            <button key={w ?? "all"} type="button" onClick={() => setServer(w)} className={cn("rounded-md px-2.5 py-1 text-sm text-muted-foreground transition-colors hover:text-foreground", server === w && "bg-accent font-medium text-foreground")}>
              {w === undefined ? "全部" : w === "cloudflare" ? "Cloudflare" : w}
            </button>
          ))}
        </div>
      )}
      {status ? <ServiceTable status={status} server={server} /> : <CardsSkeleton />}
      <UnmanagedList />
      <EdgeList />
      <NewService open={params.get("new") === "1"} onClose={() => { setParams({}); refresh(); }} />
    </>
  );
}
