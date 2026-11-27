import assert from "node:assert/strict";
import test from "node:test";
import { gunzipSync, strFromU8, strToU8, zipSync } from "fflate";
import { packZip } from "../src/lib/zip-pack.ts";

test("保留 zip 里的执行权限和脚本权限，剥掉规范化后的顶层目录", async () => {
  const zip = zipSync({
    "./app/exec": [strToU8("exec"), { os: 3, attrs: 0o100755 << 16 }],
    "./app/run.sh": strToU8("#!/bin/sh\nexit 0"),
  });
  const packed = await packZip(new File([zip], "app.zip"));
  const tar = gunzipSync(new Uint8Array(await packed.blob.arrayBuffer()));
  const header = (offset) => [
    strFromU8(tar.subarray(offset, offset + 100)).split("\0")[0],
    parseInt(strFromU8(tar.subarray(offset + 100, offset + 108)), 8),
  ];
  assert.deepEqual(header(0), ["exec", 0o755]);
  assert.deepEqual(header(1024), ["run.sh", 0o755]);
});

test("拒绝指向父目录的文件", async () => {
  const zip = zipSync({ "../evil.txt": strToU8("data") });
  await assert.rejects(packZip(new File([zip], "app.zip")), /不安全路径/);
});
