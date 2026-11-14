import { Link } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { SectionTitle } from "@/components/common";
import { Facts, Panel } from "@/components/kit";
import { checkUpdate, type VersionView } from "@/components/upgrade";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";
import { CoreBackup } from "../core-backup";

export function Core() {
  const { data: version, refresh } = usePoll<VersionView>("/api/version", 600000);
  const { status } = useStatus();
  const actions = useActions();
  const outdated = (status?.servers ?? []).filter((s) => s.agent_outdated);
  return <>
    <SectionTitle action={<div className="flex flex-wrap gap-2">
      <Button variant="outline" size="sm" onClick={async () => (await checkUpdate()) && refresh()}>检查更新</Button>
      {version?.newer && <Button size="sm" onClick={actions.upgrade}>升级</Button>}
    </div>}>版本</SectionTitle>
    <Panel className="p-4">
      <Facts items={[["当前版本", version?.version ?? "-"], ["最新版本", version?.newer ? <>
        {version.newer} <Badge>可升级</Badge>
      </> : version?.checked_at && !version.check_error ? "已是最新" : "-"]]} />
      {outdated.length > 0 && <p className="mt-3 text-sm text-muted-foreground">
        {outdated.length} 台服务器的 agent 可以升级：{outdated.map((s, i) => <span key={s.name}>
          {i > 0 && "、"}<Link className="hover:underline" to={`/servers/${encodeURIComponent(s.name)}`}>
            {s.name}
          </Link>
        </span>)}
      </p>}
    </Panel>
    <CoreBackup />
  </>;
}
