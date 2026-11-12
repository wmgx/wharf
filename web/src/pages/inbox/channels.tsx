import { Panel } from "@/components/kit";
import { BellIcon, SendIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { SectionTitle, StatusBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import type { SecretView } from "@/types";
import { SetSecret } from "../secrets";

const WEBHOOK = "NOTIFY_FEISHU_WEBHOOK";
const SIGN = "NOTIFY_FEISHU_SECRET";

/** 通知渠道：飞书群机器人，Webhook 地址和签名密钥存成密钥。 */
export function Notify() {
  const { data, refresh } = usePoll<SecretView[]>("/api/secrets", 30000);
  const [editing, setEditing] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const has = (n: string) => !!data?.some((s) => s.name === n);

  const test = async () => {
    setSending(true);
    try {
      await api.post("/api/notify/test", {});
      toast.success("已发送测试消息");
    } catch (e) {
      toast.error("发送失败", { description: (e as Error).message });
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <SectionTitle>通知渠道</SectionTitle>
      {data && (
        <Panel className="flex flex-wrap items-center gap-3 p-4">
          <span className="grid size-9 place-items-center rounded-lg border bg-muted text-muted-foreground">
            <BellIcon className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="font-semibold">飞书群机器人</div>
            <div className="text-xs text-muted-foreground">
              {has(SIGN) ? "已开签名校验" : "未设签名密钥"}
            </div>
          </div>
          <StatusBadge tone={has(WEBHOOK) ? "ok" : "idle"}>
            {has(WEBHOOK) ? "已配置" : "未配置"}
          </StatusBadge>
          <div className="ml-auto flex gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setEditing(WEBHOOK)}
            >
              Webhook 地址
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setEditing(SIGN)}>
              签名密钥
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={!has(WEBHOOK) || sending}
              onClick={test}
            >
              <SendIcon />
              发测试消息
            </Button>
          </div>
        </Panel>
      )}
      {editing && (
        <SetSecret
          initial={editing}
          fresh={false}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}
    </>
  );
}
