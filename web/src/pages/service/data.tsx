import { Empty, SectionTitle } from "@/components/common";
import { Row, Rows } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { ServiceView } from "@/types";
import { Backups } from "./backups";
import { Files } from "./files";
import { DATA_KIND } from "./status-text";

export function DataTab({ svc, onSettings }: { svc: ServiceView; onSettings: () => void }) {
  return (
    <div className="grid gap-6">
      <div>
        <SectionTitle>挂载</SectionTitle>
        {!svc.data?.length ? (
          <Empty>这个服务没有数据卷</Empty>
        ) : (
          <Rows>
            {svc.data.map((m, i) => (
              <Row key={i} className="gap-2 font-mono text-xs">
                <span>{m.source || "匿名卷"}</span>
                <span className="text-muted-foreground">→ {m.target}</span>
                <Badge
                  variant={m.kind === "managed" ? "secondary" : "outline"}
                  className={
                    m.kind === "managed"
                      ? "ml-auto font-normal"
                      : "ml-auto border-warning/50 font-normal text-warning"
                  }
                >
                  {DATA_KIND[m.kind]}
                </Badge>
              </Row>
            ))}
          </Rows>
        )}
      </div>
      <div>
        <SectionTitle>备份</SectionTitle>
        <Backups svc={svc} onSettings={onSettings} />
        {svc.spec.backup?.to && <Button variant="outline" className="mt-3" onClick={onSettings}>在设置中关闭自动备份</Button>}
      </div>
      <div>
        <SectionTitle>文件</SectionTitle>
        <Files name={svc.name} />
      </div>
    </div>
  );
}
