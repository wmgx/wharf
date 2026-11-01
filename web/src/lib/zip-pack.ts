import { unzipSync } from "fflate";

/**
 * 把上传的 zip 转成和 CLI 一样的代码包：tar.gz、按路径排序、时间和属主固定。
 * 去掉 `.git/`、`__MACOSX/`；zip 里只有一个顶层目录时（GitHub 下载的就是这样）去掉这一层。
 * 不按 .gitignore 过滤：zip 是用户自己挑过的内容。
 */
export const MAX_PACK = 512 * 1024 * 1024;

export interface Packed {
  blob: Blob;
  sha256: string;
  files: number;
  size: number;
}

function skip(path: string): boolean {
  return path.endsWith("/") || /(^|\/)(\.git|__MACOSX)\//.test(path) || /(^|\/)\.DS_Store$/.test(path);
}

function stripTop(paths: string[]): (p: string) => string {
  const tops = new Set(paths.map((p) => p.split("/")[0]));
  if (tops.size === 1 && paths.every((p) => p.includes("/"))) {
    const top = [...tops][0].length + 1;
    return (p) => p.slice(top);
  }
  return (p) => p;
}

const enc = new TextEncoder();

function field(buf: Uint8Array, offset: number, len: number, value: string) {
  buf.set(enc.encode(value).slice(0, len), offset);
}

function octal(buf: Uint8Array, offset: number, len: number, n: number) {
  field(buf, offset, len, n.toString(8).padStart(len - 1, "0") + "\0");
}

/** ustar 头；路径超过 100 字节时拆到 prefix（最长 155）。 */
function header(name: string, size: number): Uint8Array {
  const h = new Uint8Array(512);
  let prefix = "";
  let base = name;
  if (enc.encode(name).length > 100) {
    const cut = name.lastIndexOf("/", name.length - 1);
    for (let i = cut; i > 0; i = name.lastIndexOf("/", i - 1)) {
      if (enc.encode(name.slice(i + 1)).length <= 100 && enc.encode(name.slice(0, i)).length <= 155) {
        prefix = name.slice(0, i);
        base = name.slice(i + 1);
        break;
      }
    }
    if (!prefix) throw new Error(`文件路径太长：${name}`);
  }
  field(h, 0, 100, base);
  octal(h, 100, 8, 0o644);
  octal(h, 108, 8, 0);
  octal(h, 116, 8, 0);
  octal(h, 124, 12, size);
  octal(h, 136, 12, 0);
  h.fill(0x20, 148, 156);
  h[156] = 0x30;
  field(h, 257, 6, "ustar\0");
  field(h, 263, 2, "00");
  field(h, 345, 155, prefix);
  const sum = h.reduce((a, b) => a + b, 0);
  field(h, 148, 8, sum.toString(8).padStart(6, "0") + "\0 ");
  return h;
}

export async function packZip(file: File): Promise<Packed> {
  const entries = unzipSync(new Uint8Array(await file.arrayBuffer()));
  const raw = Object.keys(entries).filter((p) => !skip(p));
  if (raw.length === 0) throw new Error("zip 里没有文件");
  const strip = stripTop(raw);
  const items = raw.map((p) => ({ name: strip(p), data: entries[p] })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const parts: Uint8Array[] = [];
  let size = 0;
  for (const it of items) {
    parts.push(header(it.name, it.data.length), it.data);
    const pad = (512 - (it.data.length % 512)) % 512;
    if (pad) parts.push(new Uint8Array(pad));
    size += 512 + it.data.length + pad;
    if (size > MAX_PACK) throw new Error("代码超过 512 MiB，去掉依赖目录和构建产物再打包");
  }
  parts.push(new Uint8Array(1024));
  const tar = new Blob(parts as BlobPart[]);
  const gz = await new Response(tar.stream().pipeThrough(new CompressionStream("gzip"))).blob();
  const digest = await crypto.subtle.digest("SHA-256", await gz.arrayBuffer());
  const sha256 = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { blob: gz, sha256, files: items.length, size: gz.size };
}
