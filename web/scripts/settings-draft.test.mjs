import assert from "node:assert/strict";
import { test } from "node:test";
import { cleanHow } from "../src/lib/build-how.ts";
import { draftPatch, editableServiceSpec } from "../src/lib/draft.ts";

test("restoring build settings clears the draft after a code upload", () => {
  const saved = (upload) => ({
    source: { build: { upload, base: "python:3.13", template: "python" } },
  });
  const before = editableServiceSpec(saved("old-sha"));
  const modified = { source: { build: { template: "node", base: "python:3.13" } } };
  assert.deepEqual(draftPatch(before, modified), modified);
  const after = editableServiceSpec(saved("new-sha"));
  const restored = { source: { build: { template: "python", base: "python:3.13" } } };
  assert.deepEqual(draftPatch(after, restored), {});
});

test("自动识别模板填写启动命令时清除旧 Dockerfile 路径", () => {
  const saved = { dockerfile: "Dockerfile.prod" };
  assert.equal(cleanHow(saved).dockerfile, "Dockerfile.prod");
  const next = cleanHow({ ...saved, start: "node app.js" });
  assert.equal(next.dockerfile, undefined);
  assert.equal(next.template, undefined);
  assert.equal(next.start, "node app.js");
});
