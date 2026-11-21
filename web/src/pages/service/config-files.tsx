import { PlusIcon } from "lucide-react";
import { CodeEditor, type Lang } from "@/components/code-editor";
import { Field } from "@/components/fields";
import { Panel } from "@/components/kit";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ServiceSpec } from "@/types";

type FileSpec = NonNullable<ServiceSpec["files"]>[number];

/** 和后端校验一致：容器内绝对路径，没有空白、冒号、`.` 和 `..`。 */
export function filePathOk(path: string): boolean {
  return path.startsWith("/") && !path.endsWith("/") && !/[\s:]/.test(path) && !path.split("/").some((p) => p === "." || p === "..");
}

function langOf(path: string): Lang {
  if (/\.(sh|bash)$/.test(path)) return "shell";
  if (/\.env$/.test(path)) return "env";
  if (/Caddyfile$/.test(path)) return "caddy";
  return "yaml";
}

/** 配置文件：路径和内容，改动跟服务设置一起保存、出计划。 */
export function ConfigFiles({ files, onChange }: { files: FileSpec[]; onChange: (files: FileSpec[]) => void }) {
  const update = (i: number, patch: Partial<FileSpec>) => onChange(files.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  return (
    <div className="grid gap-3">
      {files.map((f, i) => (
        <Panel key={i} className="grid gap-3 p-4">
          <div className="flex items-end gap-2">
            <Field label="容器内路径" htmlFor={`service-file-${i}`}>
              <Input id={`service-file-${i}`} className="font-mono" placeholder="/etc/app/config.yaml" value={f.path} onChange={(e) => update(i, { path: e.target.value.trim() })} />
            </Field>
            <Button variant="ghost" onClick={() => onChange(files.filter((_, j) => j !== i))}>
              删除
            </Button>
          </div>
          {f.path && !filePathOk(f.path) && <span className="text-xs text-destructive">路径要写容器内的绝对路径</span>}
          <CodeEditor lang={langOf(f.path)} className="min-h-40" value={f.content} onChange={(content) => update(i, { content })} />
        </Panel>
      ))}
      <div>
        <Button variant="outline" onClick={() => onChange([...files, { path: "", content: "" }])}>
          <PlusIcon />
          添加配置文件
        </Button>
      </div>
    </div>
  );
}
