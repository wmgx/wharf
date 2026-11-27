import { strFromU8, Unzip, UnzipInflate } from "fflate";

/**
 * 把上传的 zip 转成和 CLI 一样的代码包：tar.gz、按路径排序、时间和属主固定。
 * 去掉 `.git/`、`__MACOSX/`；zip 里只有一个顶层目录时（GitHub 下载的就是这样）去掉这一层。
 * 不按 .gitignore 过滤：zip 是用户自己挑过的内容。
 */
export const MAX_PACK = 512 * 1024 * 1024;

const MAX_ENTRIES = 100_000;
const ZIP_CHUNK = 16 * 1024;
const tooBig = () => new Error("代码超过 512 MiB，去掉依赖目录和构建产物再打包");

function cleanPath(raw: string): string {
  const segments = raw.split("/");
  if (raw.startsWith("/") || /^[a-z]:/i.test(raw) || raw.includes("\\") || raw.includes("\0") || segments.includes("..")) {
    throw new Error(`压缩包里包含不安全路径：${raw}`);
  }
  const path = segments.filter((p) => p && p !== ".").join("/");
  return path && raw.endsWith("/") ? `${path}/` : path;
}

function readZipModes(bytes: Uint8Array): Map<string, number> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const badZip = () => new Error("zip 目录损坏或格式不支持");
  let end = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65_557)) {
    if (view.getUint32(end, true) === 0x06054b50 && end + 22 + view.getUint16(end + 20, true) === bytes.length) break;
    end--;
  }
  if (end < Math.max(0, bytes.length - 65_557)) throw badZip();
  let offset = view.getUint32(end + 16, true);
  let size = view.getUint32(end + 12, true);
  let total = view.getUint16(end + 10, true);
  if (view.getUint32(end + 4, true) !== 0) throw badZip();
  const locator = end - 20;
  if (locator >= 0 && view.getUint32(locator, true) === 0x07064b50) {
    const directory = Number(view.getBigUint64(locator + 8, true));
    if (directory < 0 || directory + 56 > locator || view.getUint32(directory, true) !== 0x06064b50
      || view.getUint32(directory + 16, true) !== 0 || view.getUint32(directory + 20, true) !== 0) throw badZip();
    total = Number(view.getBigUint64(directory + 32, true));
    size = Number(view.getBigUint64(directory + 40, true));
    offset = Number(view.getBigUint64(directory + 48, true));
  }
  const limit = offset + size;
  if (limit > end) throw badZip();
  if (total > MAX_ENTRIES) throw new Error("zip 文件条目过多");
  const modes = new Map<string, number>();
  const decoder = new TextDecoder();
  let count = 0;
  while (offset < limit) {
    if (offset + 46 > limit || view.getUint32(offset, true) !== 0x02014b50) throw badZip();
    if (++count > MAX_ENTRIES) throw new Error("zip 文件条目过多");
    const nameEnd = offset + 46 + view.getUint16(offset + 28, true);
    const next = nameEnd + view.getUint16(offset + 30, true) + view.getUint16(offset + 32, true);
    if (next > limit) throw badZip();
    const name = bytes.subarray(offset + 46, nameEnd);
    const path = cleanPath(view.getUint16(offset + 8, true) & 0x800 ? decoder.decode(name) : strFromU8(name, true));
    if (modes.has(path)) throw new Error(`zip 路径重复：${path}`);
    const mode = view.getUint8(offset + 5) === 3 ? view.getUint16(offset + 40, true) : 0;
    modes.set(path, mode);
    offset = next;
  }
  if (count !== total) throw badZip();
  return modes;
}

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
function header(name: string, size: number, mode: number): Uint8Array {
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
  octal(h, 100, 8, mode);
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
  if (file.size > MAX_PACK) throw tooBig();
  const bytes = new Uint8Array(await file.arrayBuffer());
  const modes = readZipModes(bytes);
  const entries = new Map<string, { chunks: Uint8Array[]; size: number; done: boolean }>();
  let expanded = 0;
  let count = 0;
  const unzip = new Unzip((file) => {
    if (++count > MAX_ENTRIES) throw new Error("zip 文件条目过多");
    const name = cleanPath(file.name);
    if (!name || skip(name)) return;
    if (!modes.has(name) || entries.has(name)) throw new Error(`zip 路径不一致：${name}`);
    const entry = { chunks: [] as Uint8Array[], size: 0, done: false };
    entries.set(name, entry);
    file.ondata = (error, chunk, done) => {
      if (error) throw error;
      expanded += chunk.length;
      if (expanded > MAX_PACK) throw tooBig();
      entry.size += chunk.length;
      if (chunk.length) entry.chunks.push(chunk);
      entry.done = done;
    };
    file.start();
  });
  unzip.register(UnzipInflate);
  for (let i = 0; i < bytes.length; i += ZIP_CHUNK) {
    const end = Math.min(i + ZIP_CHUNK, bytes.length);
    unzip.push(bytes.subarray(i, end), end === bytes.length);
  }
  const raw = [...entries.keys()].sort();
  if (!raw.length) throw new Error("zip 里没有文件");
  if (raw.length !== [...modes.keys()].filter((p) => p && !skip(p)).length) throw new Error("zip 文件目录不完整");
  const strip = stripTop(raw);

  const parts: Uint8Array[] = [];
  let size = 1024;
  for (const path of raw) {
    const { chunks, size: length, done } = entries.get(path)!;
    if (!done) throw new Error(`zip 文件不完整：${path}`);
    const mode = modes.get(path) ?? 0;
    const start: number[] = [];
    for (const chunk of chunks) {
      for (const byte of chunk.subarray(0, 3 - start.length)) start.push(byte);
      if (start.length >= 3) break;
    }
    const executable = (mode & 0o111) !== 0 || (!mode && start.join(",") === "35,33,47");
    const pad = (512 - (length % 512)) % 512;
    size += 512 + length + pad;
    if (size > MAX_PACK) throw tooBig();
    parts.push(header(strip(path), length, executable ? 0o755 : 0o644));
    for (const chunk of chunks) parts.push(chunk);
    if (pad) parts.push(new Uint8Array(pad));
  }
  parts.push(new Uint8Array(1024));
  const tar = new Blob(parts as BlobPart[]);
  const gz = await new Response(tar.stream().pipeThrough(new CompressionStream("gzip"))).blob();
  const digest = await crypto.subtle.digest("SHA-256", await gz.arrayBuffer());
  const sha256 = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { blob: gz, sha256, files: entries.size, size: gz.size };
}
