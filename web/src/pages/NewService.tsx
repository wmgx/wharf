import { ArrowRightIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { Notice } from "@/components/common";
import { DomainChips, Field, Picker, PortsEditor, Segmented, gatewayOptions, nameFromImage, parseEnv, serverOptions, toName } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useStatus } from "@/status";
import type { AccountView, Change, PortSpec, ServiceSpec } from "@/types";

/**
 * 新建服务：选来源、选服务器、（可选）加域名，然后看计划、确认、看日志。
 * 服务和路由放在同一个计划里，一步完成。
 */
export function NewService({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl">
        <SheetHeader className="border-b">
          <SheetTitle>新建服务</SheetTitle>
          <SheetDescription>填好后生成计划，确认后一次部署完成。</SheetDescription>
        </SheetHeader>
        {open && <Form onClose={onClose} />}
      </SheetContent>
    </Sheet>
  );
}

function Form({ onClose }: { onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 60000);

  const [kind, setKind] = useState<"image" | "compose">("image");
  const [image, setImage] = useState("");
  const [compose, setCompose] = useState("");
  const [name, setName] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const servers = status?.servers ?? [];
  const [server, setServer] = useState("");
  const [ports, setPorts] = useState<PortSpec[]>([{ name: "http", port: 80 }]);
  const [envText, setEnvText] = useState("");
  const [hostname, setHostname] = useState("");
  const gateways = status?.gateways ?? [];
  const [gateway, setGateway] = useState("");

  const svcName = nameTouched ? name : kind === "image" ? nameFromImage(image) : name;
  const chosenServer = server || serverOptions(servers)[0]?.value || "";
  const chosenGateway = gateway || gateways.find((g) => g.spec.default)?.name || gateways[0]?.name || "";

  // 域名建议：已有路由的后缀 + 厂商账号里的 zone。
  const suggestions = useMemo(() => {
    const suffixes = new Set<string>();
    status?.routes.forEach((r) => {
      const i = r.spec.hostname.indexOf(".");
      if (i > 0) suffixes.add(r.spec.hostname.slice(i + 1));
    });
    accounts?.forEach((a) => a.zones.forEach((z) => suffixes.add(z)));
    return svcName ? [...suffixes].map((s) => `${svcName}.${s}`) : [];
  }, [status, accounts, svcName]);

  const source = kind === "image" ? image.trim() : compose.trim();
  const portsOk = ports.every((p) => p.name && p.port > 0 && p.port < 65536);
  const ready = !!svcName && !!source && !!chosenServer && portsOk && (!hostname || !!chosenGateway);

  const submit = () => {
    const spec: ServiceSpec = {
      server: chosenServer,
      source: kind === "image" ? { image: source } : { compose: { content: source } },
      ports: ports.length ? ports : undefined,
      env: kind === "image" && envText.trim() ? parseEnv(envText) : undefined,
    };
    const changes: Change[] = [{ op: "upsert_service", name: svcName, spec }];
    if (hostname.trim()) {
      changes.push({ op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service: svcName, gateway: chosenGateway || undefined } });
    }
    onClose();
    actions.plan({ title: `部署 ${svcName}`, changes, then: `/services/${svcName}` });
  };

  return (
    <>
      <div className="grid flex-1 content-start gap-5 overflow-auto p-4">
        <Field label="来源">
          <Segmented
            value={kind}
            onChange={setKind}
            options={[
              ["image", "镜像"],
              ["compose", "Compose 文件"],
            ]}
          />
        </Field>

        {kind === "image" ? (
          <Field label="镜像" htmlFor="image">
            <Input id="image" autoFocus placeholder="例如 nginxdemos/hello 或 ghcr.io/owner/app:1.0" value={image} onChange={(e) => setImage(e.target.value)} />
          </Field>
        ) : (
          <Field label="compose.yaml" htmlFor="compose" help="compose 来源原样使用，端口按文件里发布的宿主机端口填写。">
            <Textarea
              id="compose"
              className="min-h-40 font-mono text-xs"
              placeholder={"services:\n  app:\n    image: nginx\n    ports:\n      - 127.0.0.1:8080:80"}
              value={compose}
              onChange={(e) => setCompose(e.target.value)}
            />
          </Field>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Field label="名称" htmlFor="name">
            <Input
              id="name"
              value={svcName}
              placeholder="自动取镜像名"
              onChange={(e) => {
                setNameTouched(true);
                setName(toName(e.target.value));
              }}
            />
          </Field>
          <Field label="服务器" htmlFor="server">
            <Picker id="server" value={chosenServer} options={serverOptions(servers)} onChange={setServer} />
          </Field>
        </div>

        <Field
          label="端口"
          help={kind === "image" ? "容器里监听的端口。宿主机端口自动分配，只绑定 127.0.0.1 和内网地址。" : "compose 里已经发布的宿主机端口。"}
        >
          <PortsEditor ports={ports} onChange={setPorts} />
        </Field>

        {kind === "image" && (
          <Field
            label="环境变量"
            htmlFor="env"
            help={
              <>
                一行一个。密钥用 <code className="font-mono">[[名称]]</code> 引用，值不会出现在配置里。
              </>
            }
          >
            <Textarea id="env" className="min-h-24 font-mono text-xs" placeholder={"KEY=value\nTOKEN=[[MY_SECRET]]"} value={envText} onChange={(e) => setEnvText(e.target.value)} />
          </Field>
        )}

        <Separator />

        <Field
          label={
            <>
              域名 <span className="font-normal text-muted-foreground">可选</span>
            </>
          }
          htmlFor="hostname"
        >
          <Input id="hostname" placeholder="例如 app.example.com，留空就只在内网访问" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          {!hostname && <DomainChips suggestions={suggestions} onPick={setHostname} />}
        </Field>
        {hostname && gateways.length > 1 && (
          <Field label="经过哪个网关" htmlFor="gw">
            <Picker id="gw" value={chosenGateway} options={gatewayOptions(gateways)} onChange={setGateway} />
          </Field>
        )}
        {hostname && gateways.length === 0 && <Notice kind="warn">还没有网关，先在「网关」页新建一个。</Notice>}
      </div>
      <SheetFooter className="flex-row justify-end border-t">
        <Button variant="ghost" onClick={onClose}>
          取消
        </Button>
        <Button disabled={!ready} onClick={submit}>
          生成计划
          <ArrowRightIcon />
        </Button>
      </SheetFooter>
    </>
  );
}
