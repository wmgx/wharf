import { RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useActions } from "@/components/actions";
import { AptUpgrade } from "@/components/apt-upgrade";
import { Empty, Notice, SectionTitle, ago } from "@/components/common";
import { Panel, Tip } from "@/components/kit";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { HostInfo, ServerView } from "@/types";
import { ServerBaseline } from "./baseline";
import { ServerDisk } from "./disk";
import { size } from "./format";

const DOCKER_KIND: Record<string, string> = {
  Images: "镜像",
  Containers: "容器",
  "Local Volumes": "数据卷",
  "Build Cache": "构建缓存",
};

export function SystemInfo({ info, server, onRefresh, loading }: { info: HostInfo; server: ServerView; onRefresh: () => void; loading: boolean }) {
  const actions = useActions();
  return (
    <>
      <SectionTitle action={<Tip text="重新读取"><Button aria-label="重新读取" variant="ghost" size="icon-sm" disabled={loading} onClick={onRefresh}><RefreshCwIcon className={loading ? "animate-spin" : undefined} /></Button></Tip>}>更新</SectionTitle>
      {info.reboot_required && (
        <Notice kind="warn" className="mb-3">
          装了需要重启才生效的更新
        </Notice>
      )}
      {info.updates && <AptUpgrade server={server.name} enabled={server.online && !!server.settings.host_terminal} count={info.updates.length} onDone={onRefresh} />}
      {!info.updates ? (
        <Empty>这台不是 apt 系统，看不了待装更新</Empty>
      ) : info.updates.length === 0 ? (
        <Empty>没有待装的更新</Empty>
      ) : (
        <Panel>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>包</TableHead>
                <TableHead>当前</TableHead>
                <TableHead>新版本</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {[...info.updates]
                .sort((a, b) => Number(b.security) - Number(a.security))
                .map((u) => (
                  <TableRow key={u.name}>
                    <TableCell className="font-mono text-xs">
                      {u.name}
                      {u.security && (
                        <Badge variant="destructive" className="ml-2">
                          安全
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {u.from || "新装"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{u.to}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </Panel>
      )}
      <SectionTitle action={<Button variant="outline" size="sm" onClick={() => actions.prune(server.name)}><Trash2Icon />清理没在用的镜像</Button>}>磁盘</SectionTitle>
      <Panel>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>类型</TableHead>
              <TableHead className="text-right">数量</TableHead>
              <TableHead className="text-right">占用</TableHead>
              <TableHead className="text-right">可回收</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {info.docker.map((d) => (
              <TableRow key={d.kind}>
                <TableCell>{DOCKER_KIND[d.kind] ?? d.kind}</TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {d.total}
                  <span className="text-muted-foreground">
                    {" "}
                    / {d.active} 在用
                  </span>
                </TableCell>
                <TableCell className="text-right font-mono text-xs">
                  {d.size}
                </TableCell>
                <TableCell className="text-right font-mono text-xs text-muted-foreground">
                  {d.reclaimable}
                </TableCell>
              </TableRow>
            ))}
            <LogRow label="容器日志" bytes={info.container_logs} />
            <LogRow label="journal" bytes={info.journal} />
            <LogRow label="/var/log" bytes={info.var_log} />
          </TableBody>
        </Table>
      </Panel>
      <div className="mt-3"><ServerDisk server={server.name} online={server.online} /></div>
      <SectionTitle>基线</SectionTitle>
      <ServerBaseline server={server} />
      {!!info.ssh_logins?.length && (
        <>
          <SectionTitle>SSH 登录</SectionTitle>
          <Panel>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>用户</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>方式</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {info.ssh_logins.map((l, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Tip text={new Date(l.at).toLocaleString("zh-CN")}><span>
                        {ago(l.at)}
                      </span></Tip>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {l.user}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {l.from}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {l.method}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>
        </>
      )}
    </>
  );
}

function LogRow({ label, bytes }: { label: string; bytes?: number }) {
  return (
    <TableRow>
      <TableCell>{label}</TableCell>
      <TableCell />
      <TableCell className="text-right font-mono text-xs">
        {size(bytes)}
      </TableCell>
      <TableCell />
    </TableRow>
  );
}
