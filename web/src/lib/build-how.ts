import type { BuildSource } from "@/types";

/** 怎么构建的那几个字段。 */
export type BuildHow = Pick<BuildSource, "dockerfile" | "template" | "base" | "install" | "start" | "dockerfile_content">;

/** 和 crates/api-types/src/build.rs 的 TEMPLATES 一致。 */
export const TEMPLATES: { id: string; label: string; base: string; install: boolean }[] = [
  { id: "python", label: "Python", base: "python:3.13-slim", install: true },
  { id: "node", label: "Node", base: "node:22-bookworm-slim", install: true },
  { id: "go", label: "Go", base: "golang:1.25-alpine", install: false },
  { id: "static", label: "静态站", base: "caddy:2-alpine", install: false },
];

export const AUTO = "auto";

export function howOf(b: BuildSource | null | undefined): BuildHow {
  if (!b) return {};
  const { dockerfile, template, base, install, start, dockerfile_content } = b;
  return { dockerfile, template, base, install, start, dockerfile_content };
}

/** 去掉空字符串，按方式清掉另一种方式的字段。 */
export function cleanHow(h: BuildHow): BuildHow {
  const t = (s?: string | null) => (s?.trim() ? s.replace(/\s+$/, "") : undefined);
  const clear = { dockerfile: undefined, dockerfile_content: undefined, template: undefined, base: undefined, install: undefined, start: undefined };
  if (h.dockerfile_content != null) return { ...clear, dockerfile_content: t(h.dockerfile_content) };
  const template = h.template && h.template !== AUTO ? h.template : undefined;
  const base = t(h.base);
  const install = !template || TEMPLATES.find((x) => x.id === template)?.install ? t(h.install) : undefined;
  const start = t(h.start);
  return {
    ...clear,
    dockerfile: template || base || install || start ? undefined : t(h.dockerfile),
    template,
    base,
    install,
    start,
  };
}

export function howReady(h: BuildHow): boolean {
  return h.dockerfile_content == null || !!h.dockerfile_content.trim();
}
