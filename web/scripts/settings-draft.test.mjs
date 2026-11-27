import assert from "node:assert/strict";
import { test } from "node:test";
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
