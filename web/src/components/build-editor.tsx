import { Field, Picker, Segmented } from "@/components/fields";
import { Input } from "@/components/ui/input";
import { CodeEditor } from "@/components/code-editor";
import { AUTO, TEMPLATES, type BuildHow } from "@/lib/build-how";

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
          <CodeEditor
            id="dockerfile-content"
            lang="dockerfile"
            className="min-h-48"
            placeholder={"FROM python:3.13-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"main.py\"]"}
            value={value.dockerfile_content ?? ""}
            onChange={(v) => set({ dockerfile_content: v })}
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
            <CodeEditor
              id="start"
              lang="shell"
              className="min-h-20"
              placeholder={"自动识别\n\n例如：\nalembic upgrade head\nexec uvicorn main:app --host 0.0.0.0 --port $PORT"}
              value={value.start ?? ""}
              onChange={(v) => set({ start: v })}
            />
          </Field>
        </>
      )}
    </>
  );
}
