import { ArrowLeftIcon } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import Terminal from "@/components/Terminal";
import { Button } from "@/components/ui/button";
import { useStatus } from "@/status";

export function HostTerminal() {
  const { name = "" } = useParams();
  const navigate = useNavigate();
  const { status } = useStatus();
  const server = status?.servers.find((item) => item.name === name);
  const back = () => navigate(`/servers/${encodeURIComponent(name)}`);
  const unavailable = server && (!server.settings.host_terminal ? "未开启" : !server.online ? "离线" : !server.host_shell ? "待升级" : undefined);

  if (!server || unavailable) {
    return (
      <div className="fixed inset-0 z-50 flex flex-col bg-background">
        <div className="flex h-12 items-center gap-2 border-b px-3">
          <Button size="sm" variant="ghost" onClick={back}>
            <ArrowLeftIcon />
            返回
          </Button>
          <span className="font-medium">{name}</span>
          <span className="text-sm text-muted-foreground">root</span>
        </div>
        <div className="grid flex-1 place-items-center text-sm text-muted-foreground">{unavailable ?? "连接中"}</div>
      </div>
    );
  }

  return <Terminal name={name} target="host" fullScreen title={`${name} · root`} onBack={back} />;
}
