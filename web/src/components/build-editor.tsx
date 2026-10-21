import { Field, Picker, Segmented } from "@/components/fields";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { BuildSource } from "@/types";

/** 怎么构建的那几个字段。 */
export type BuildHow = Pick<BuildSource, "dockerfile" | "template" | "base" | "install" | "start" | "dockerfile_content">;

/** 和 crates/api-types/src/build.rs 的 TEMPLATES 一致。 */
const TEMPLATES: { id: string; label: string; base: string; install: boolean }[] = [
  { id: "python", label: "Python", base: "python:3.13-slim", install: true },
  { id: "node", label: "Node", base: "node:22-bookworm-slim", install: true },
  { id: "go", label: "Go", base: "golang:1.25-alpine", install: false },
  { id: "static", label: "静态站", base: "caddy:2-alpine", install: false },
];

const AUTO = "auto";

export function howOf(b: BuildSource | null | undefined): BuildHow {
  if (!b) return {};
  const { dockerfile, template, base, install, start, dockerfile_content } = b;
  return { dockerfile, template, base, install, start, dockerfile_content };
}

/** 去掉空字符串，按方式清掉另一种方式的字段。 */
export function cleanHow(h: BuildHow): BuildHow {
  const t = (s?: string) => (s?.trim() ? s.replace(/\s+$/, "") : undefined);
  if (h.dockerfile_content !== undefined) return { dockerfile_content: t(h.dockerfile_content) };
  const template = h.template && h.template !== AUTO ? h.template : undefined;
  const withInstall = !template || TEMPLATES.find((x) => x.id === template)?.install;
  return {
    dockerfile: template ? undefined : t(h.dockerfile),
    template,
    base: t(h.base),
    install: withInstall ? t(h.install) : undefined,
    start: t(h.start),
  };
}

export function howReady(h: BuildHow): boolean {
  return h.dockerfile_content === undefined || !!h.dockerfile_content.trim();
}

export function BuildEditor({ value, onChange }: { value: BuildHow; onChange: (v: BuildHow) => void }) {
  const mode = value.dockerfile_content !== undefined ? "dockerfile" : "template";
  const template = value.template ?? AUTO;
  const meta = TEMPLATES.find((x) => x.id === template);
  const set = (patch: BuildHow) => onChange({ ...value, ...patch });
  return (
    <>
      <Field label="构建">
        <Segmented
          value={mode}
          onChange={(m) => onChange(m === "dockerfile" ? { ...value, dockerfile_content: value.dockerfile_content ?? "" } : { ...value, dockerfile_content: undefined })}
          options={[
            ["template", "模板"],
            ["dockerfile", "Dockerfile"],
          ]}
        />
      </Field>
      {mode === "dockerfile" ? (
        <Field label="Dockerfile" htmlFor="dockerfile-content">
          <Textarea
            id="dockerfile-content"
            className="min-h-48 font-mono text-xs"
            placeholder={"FROM python:3.13-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"main.py\"]"}
            value={value.dockerfile_content ?? ""}
            onChange={(e) => set({ dockerfile_content: e.target.value })}
          />
        </Field>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3">
            <Field label="模板" htmlFor="template">
              <Picker
                id="template"
                value={template}
                options={[{ value: AUTO, label: "自动识别", hint: "有 Dockerfile 就用" }, ...TEMPLATES.map((x) => ({ value: x.id, label: x.label }))]}
                onChange={(v) => set({ template: v === AUTO ? undefined : v })}
              />
            </Field>
            <Field label="基础镜像" htmlFor="base">
              <Input id="base" placeholder={meta?.base ?? "模板默认"} value={value.base ?? ""} onChange={(e) => set({ base: e.target.value })} />
            </Field>
          </div>
          {(!meta || meta.install) && (
            <Field label="安装命令" htmlFor="install">
              <Input id="install" className="font-mono text-xs" placeholder="模板默认" value={value.install ?? ""} onChange={(e) => set({ install: e.target.value })} />
            </Field>
          )}
          <Field label="启动命令 / 脚本" htmlFor="start">
            <Textarea
              id="start"
              className="min-h-20 font-mono text-xs"
              placeholder={"自动识别\n\n例如：\nalembic upgrade head\nexec uvicorn main:app --host 0.0.0.0 --port $PORT"}
              value={value.start ?? ""}
              onChange={(e) => set({ start: e.target.value })}
            />
          </Field>
        </>
      )}
    </>
  );
}
