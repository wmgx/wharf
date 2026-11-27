import type { ServiceSpec } from "@/types";

const norm = (v: unknown) => v === undefined || v === "" || (Array.isArray(v) && !v.length) || (v && typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length) ? null : v;

function canonical(value: unknown) {
  return JSON.stringify(norm(value), (_key, v: unknown) => {
    if (!v || typeof v !== "object" || Array.isArray(v)) return v;
    return Object.fromEntries(Object.entries(v).sort(([a], [b]) => a < b ? -1 : Number(a > b)));
  });
}

export function draftPatch<T extends object>(base: T, edits: Partial<T>): Partial<T> {
  const patch = { ...edits };
  for (const key of Object.keys(patch) as (keyof T)[]) {
    if (canonical(patch[key]) === canonical(base[key])) delete patch[key];
  }
  return patch;
}

export function editableServiceSpec(spec: ServiceSpec): ServiceSpec {
  if (!("build" in spec.source)) return spec;
  return { ...spec, source: { build: { ...spec.source.build, upload: undefined } } };
}
