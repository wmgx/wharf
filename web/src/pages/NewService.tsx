import { ArrowRightIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { usePoll } from "@/api";
import { useActions } from "@/components/actions";
import { BuildEditor, type BuildHow, cleanHow, howReady } from "@/components/build-editor";
import { EntryField, useEntry } from "@/components/entry";
import { DomainChips, Field, Picker, PortsEditor, Segmented, portsFor, portsValid, nameFromImage, parseEnv, serverOptions, toName } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
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
      <SheetContent className="w-full gap-0 sm:max-w-xl" aria-describedby={undefined}>
        <SheetHeader className="border-b">
          <SheetTitle>新建服务</SheetTitle>
        </SheetHeader>
        {open && <Form onClose={onClose} />}
      </SheetContent>
    </Sheet>
  );
}

type Kind = "image" | "compose" | "git";

/** 从仓库地址取服务名：https://github.com/owner/my-app.git → my-app。 */
function nameFromRepo(repo: string): string {
  const last = repo.trim().replace(/\/+$/, "").split("/").pop() ?? "";
  return toName(last.replace(/\.git$/, ""));
}

interface Draft {
  kind: Kind;
  image: string;
  compose: string;
  repo: string;
  gitRef: string;
  path: string;
  how: BuildHow;
  name: string;
  nameTouched: boolean;
  server: string;
  ports: PortSpec[];
  envText: string;
  hostname: string;
  entry: string;
}

/** 上一次提交的表单。计划生成失败或想改时点"返回修改"，用它恢复。 */
let lastDraft: Draft | null = null;

/** 回到新建服务表单，恢复上一次填写的内容。 */
export const NEW_SERVICE_DRAFT_URL = "/services?new=1&draft=1";

function Form({ onClose }: { onClose: () => void }) {
  const { status } = useStatus();
  const actions = useActions();
  const { data: accounts } = usePoll<AccountView[]>("/api/accounts", 60000);
  const [params] = useSearchParams();
  const [draft] = useState(() => (params.get("draft") === "1" ? lastDraft : null));

  const [kind, setKind] = useState<Kind>(draft?.kind ?? "image");
  const [image, setImage] = useState(draft?.image ?? "");
  const [compose, setCompose] = useState(draft?.compose ?? "");
  const [repo, setRepo] = useState(draft?.repo ?? "");
  const [gitRef, setGitRef] = useState(draft?.gitRef ?? "main");
  const [path, setPath] = useState(draft?.path ?? "");
  const [how, setHow] = useState<BuildHow>(draft?.how ?? {});
  const [name, setName] = useState(draft?.name ?? "");
  const [nameTouched, setNameTouched] = useState(draft?.nameTouched ?? false);
  const servers = status?.servers ?? [];
  const [server, setServer] = useState(draft?.server ?? "");
  const [ports, setPorts] = useState<PortSpec[]>(draft?.ports ?? [{ name: "http", container: 80 }]);
  const [envText, setEnvText] = useState(draft?.envText ?? "");
  const [hostname, setHostname] = useState(draft?.hostname ?? "");

  const svcName = nameTouched ? name : kind === "image" ? nameFromImage(image) : kind === "git" ? nameFromRepo(repo) : name;
  const chosenServer = server || serverOptions(servers)[0]?.value || "";
  const entry = useEntry(chosenServer);
  const [entryRestored, setEntryRestored] = useState(false);
  if (draft?.entry && !entryRestored && entry.options.some((o) => o.value === draft.entry)) {
    setEntryRestored(true);
    entry.setChoice(draft.entry);
  }

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

  const source = kind === "image" ? image.trim() : kind === "git" ? repo.trim() : compose.trim();
  const repoOk = kind !== "git" || (/^https:\/\/[^\s@]+$/.test(repo.trim()) && !!gitRef.trim() && howReady(how));
  const portsOk = portsValid(ports, kind === "compose");
  const ready = !!svcName && !!source && repoOk && !!chosenServer && portsOk && (!hostname.trim() || entry.ready);
  const withEnv = kind !== "compose";

  const submit = () => {
    const spec: ServiceSpec = {
      server: chosenServer,
      source:
        kind === "image"
          ? { image: source }
          : kind === "git"
            ? { build: { git: { repo: source.replace(/\/+$/, ""), ref: gitRef.trim() }, path: path.trim() || undefined, ...cleanHow(how) } }
            : { compose: { content: source } },
      ports: ports.length ? portsFor(ports, kind === "compose") : undefined,
      env: withEnv && envText.trim() ? parseEnv(envText) : undefined,
    };
    const changes: Change[] = [{ op: "upsert_service", name: svcName, spec }];
    if (hostname.trim()) {
      const { gateway, changes: gatewayChanges } = entry.resolve();
      changes.push(...gatewayChanges, { op: "upsert_route", spec: { hostname: hostname.trim().toLowerCase(), service: svcName, gateway } });
    }
    lastDraft = { kind, image, compose, repo, gitRef, path, how, name: svcName, nameTouched, server: chosenServer, ports, envText, hostname, entry: entry.chosen };
    onClose();
    actions.plan({ title: `部署 ${svcName}`, changes, then: `/services/${svcName}`, back: NEW_SERVICE_DRAFT_URL });
  };

  return (
    <>
      <div className="grid flex-1 content-start gap-5 overflow-auto p-4">
        <Field label="来源">
          <Segmented
            value={kind}
            onChange={(k) => {
              setKind(k);
              // 端口还是默认值时，换成这种来源常用的端口。
              const untouched = ports.length === 1 && ports[0].name === "http" && !ports[0].host && [80, 8080].includes(ports[0].container ?? 0);
              if (untouched && k !== "compose") setPorts([{ name: "http", container: k === "git" ? 8080 : 80 }]);
              if (untouched && k === "compose") setPorts([]);
            }}
            options={[
              ["image", "镜像"],
              ["git", "代码（git）"],
              ["compose", "Compose 文件"],
            ]}
          />
        </Field>

        {kind === "git" ? (
          <>
            <Field
              label="仓库"
              htmlFor="repo"
            >
              <Input id="repo" autoFocus placeholder="https://github.com/owner/app" value={repo} onChange={(e) => setRepo(e.target.value)} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="分支 / 标签" htmlFor="ref">
                <Input id="ref" value={gitRef} onChange={(e) => setGitRef(e.target.value)} />
              </Field>
              <Field label="子目录" htmlFor="path">
                <Input id="path" placeholder="仓库根目录" value={path} onChange={(e) => setPath(e.target.value)} />
              </Field>
            </div>
            <BuildEditor value={how} onChange={setHow} />
          </>
        ) : kind === "image" ? (
          <Field label="镜像" htmlFor="image">
            <Input id="image" autoFocus placeholder="例如 nginxdemos/hello 或 ghcr.io/owner/app:1.0" value={image} onChange={(e) => setImage(e.target.value)} />
          </Field>
        ) : (
          <Field label="compose.yaml" htmlFor="compose">
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
              placeholder={kind === "git" ? "自动取仓库名" : "自动取镜像名"}
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
        >
          <PortsEditor ports={ports} onChange={setPorts} compose={kind === "compose"} />
        </Field>

        {withEnv && (
          <Field
            label="环境变量"
            htmlFor="env"
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
        {hostname.trim() && <EntryField entry={entry} />}
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
