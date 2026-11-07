import { ActivityIcon } from "lucide-react";
import { useState } from "react";
import { useActions } from "@/components/actions";
import { Dot, ago } from "@/components/common";
import { Field, Picker } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { MonitorSpec, ServiceView } from "@/types";

/** 自定义监控：显示最近结果，就地修改（走计划）。 */
export function MonitorCard({ svc }: { svc: ServiceView }) {
  const actions = useActions();
  const cur = svc.spec.monitor;
  const ports = svc.spec.ports ?? [];
  const [editing, setEditing] = useState(false);
  const [path, setPath] = useState(cur?.path ?? "/");
  const [port, setPort] = useState(cur?.port ?? "");
  const [expect, setExpect] = useState(cur?.expect ? String(cur.expect) : "");
  const [keyword, setKeyword] = useState(cur?.keyword ?? "");
  const expectNum = Number(expect.trim() || 0);
  const valid =
    path.startsWith("/") &&
    Number.isInteger(expectNum) &&
    (expectNum === 0 || (expectNum >= 100 && expectNum < 600));

  const save = (monitor: MonitorSpec | undefined) => {
    actions.plan({
      title: monitor ? `设置 ${svc.name} 的监控` : `关闭 ${svc.name} 的监控`,
      changes: [
        {
          op: "upsert_service",
          name: svc.name,
          spec: { ...svc.spec, monitor },
        },
      ],
    });
    setEditing(false);
  };

  const m = svc.monitor;
  return (
    <Card className="gap-3 py-5 shadow-xs">
      <CardContent className="grid gap-3 px-5">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <ActivityIcon className="size-4 text-muted-foreground" />
          <span className="font-medium">监控</span>
          {cur ? (
            <span className="font-mono text-[13px] text-muted-foreground">
              {cur.path}
              {cur.expect ? ` → ${cur.expect}` : ""}
              {cur.keyword ? ` 含“${cur.keyword}”` : ""}
            </span>
          ) : (
            <span className="text-muted-foreground">
              没开。开了以后每分钟从服务所在机器请求一次，连续 3 次不正常推送。
            </span>
          )}
          {m && (
            <span
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"
              title={`${ago(new Date(m.at).toISOString())}检查`}
            >
              <Dot tone={m.ok ? "ok" : m.fails >= 3 ? "bad" : "warn"} />
              <span className={!m.ok && m.fails >= 3 ? "text-destructive" : ""}>
                {m.detail}
                {!m.ok && m.fails > 1 ? `（连续 ${m.fails} 次）` : ""}
              </span>
            </span>
          )}
          {!editing && (
            <Button
              variant="ghost"
              size="xs"
              className="ml-auto"
              disabled={!ports.length}
              onClick={() => setEditing(true)}
            >
              {cur ? "修改" : "开启"}
            </Button>
          )}
        </div>
        {editing && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="路径">
              <Input
                value={path}
                placeholder="/health"
                onChange={(e) => setPath(e.target.value)}
              />
            </Field>
            <Field label="端口">
              <Picker
                value={port}
                options={[
                  { value: "", label: `默认（${ports[0]?.name ?? "-"}）` },
                  ...ports.map((p) => ({ value: p.name, label: p.name })),
                ]}
                onChange={setPort}
              />
            </Field>
            <Field label="期望状态码" help="不填时 2xx、3xx 都算正常。">
              <Input
                inputMode="numeric"
                value={expect}
                placeholder="200"
                onChange={(e) => setExpect(e.target.value)}
              />
            </Field>
            <Field label="应答里要包含" help="不填就只看状态码。">
              <Input
                value={keyword}
                placeholder="ok"
                onChange={(e) => setKeyword(e.target.value)}
              />
            </Field>
            <div className="flex flex-wrap gap-2 sm:col-span-2">
              <Button
                size="sm"
                disabled={!valid}
                onClick={() =>
                  save({
                    path: path.trim(),
                    port: port || undefined,
                    expect: expectNum || undefined,
                    keyword: keyword.trim() || undefined,
                  })
                }
              >
                生成计划
              </Button>
              {cur && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => save(undefined)}
                >
                  关闭监控
                </Button>
              )}
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setEditing(false)}
              >
                取消
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
