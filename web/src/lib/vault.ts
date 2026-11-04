import { api } from "@/api";

/**
 * 备注里的私密内容，在浏览器里加密，控制面只存密文。
 *
 * 两层密钥：
 * - 数据密钥（随机 AES-256）加密备注内容；
 * - 登录密码派生出的密钥（PBKDF2）把数据密钥包起来，包好的结果存在控制面（`/api/vault`）。
 * 改密码只需要用新密码把数据密钥重新包一次，备注不用重新加密。
 * 查看私密内容要二次验证：解开的数据密钥只放在内存里 5 分钟，不落盘；过期或刷新页面后要再输登录密码。
 */

const PREFIX = "wharf-enc:v1:";
const GRACE_MS = 5 * 60 * 1000;
const ITERATIONS = 600_000;

interface Wrapped {
  v: 1;
  salt: string;
  iv: string;
  key: string;
}

const enc = new TextEncoder();
const b64 = (buf: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const supported = () => typeof crypto !== "undefined" && !!crypto.subtle;

/** 把备注拆成公开部分和密文（如果有）。 */
export function splitNote(note: string): { plain: string; sealed: string | null } {
  const lines = note.split("\n");
  const i = lines.findIndex((l) => l.startsWith(PREFIX));
  if (i < 0) return { plain: note, sealed: null };
  return { plain: lines.filter((_, k) => k !== i).join("\n").trim(), sealed: lines[i] };
}

export function joinNote(plain: string, sealed: string | null): string {
  return [plain.trim(), sealed ?? ""].filter(Boolean).join("\n");
}

// 旧版本把密钥存在 localStorage，清掉。
try {
  localStorage.removeItem("wharf.vault");
} catch {
  // ignore
}

let cached: { key: CryptoKey; until: number } | null = null;

async function remember(raw: ArrayBuffer | Uint8Array) {
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  cached = { key, until: Date.now() + GRACE_MS };
}

export function isUnlocked(): boolean {
  return !!cached && cached.until > Date.now();
}

function dataKey(): CryptoKey | null {
  return isUnlocked() ? cached!.key : null;
}

export function lock() {
  cached = null;
}

async function kek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function wrap(raw: ArrayBuffer | Uint8Array, password: string): Promise<Wrapped> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(password, salt), raw);
  return { v: 1, salt: b64(salt), iv: b64(iv), key: b64(key) };
}

async function unwrap(w: Wrapped, password: string): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(w.iv) }, await kek(password, unb64(w.salt)), unb64(w.key));
}

async function loadWrapped(): Promise<Wrapped | null> {
  const { vault } = await api.get<{ vault: string | null }>("/api/vault");
  return vault ? (JSON.parse(vault) as Wrapped) : null;
}

const saveWrapped = (w: Wrapped) => api.put("/api/vault", { vault: JSON.stringify(w) });

/**
 * 登录成功后调用：用登录密码解开数据密钥；第一次用时生成一个。
 * 返回 "stale" 表示密码重置过、旧的数据密钥还是旧密码包的，需要 `migrate` 一次。
 */
export async function afterLogin(password: string): Promise<"ok" | "stale" | "skip"> {
  if (!supported()) return "skip";
  try {
    const w = await loadWrapped();
    if (!w) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      await saveWrapped(await wrap(raw, password));
      await remember(raw);
      return "ok";
    }
    await remember(await unwrap(w, password).catch(() => Promise.reject("stale")));
    return "ok";
  } catch (e) {
    return e === "stale" ? "stale" : "skip";
  }
}

/** 密码重置后：用旧密码解开数据密钥，再用现在的密码包好存回去。 */
export async function migrate(oldPassword: string, password: string): Promise<void> {
  const w = await loadWrapped();
  if (!w) return;
  const raw = await unwrap(w, oldPassword).catch(() => Promise.reject(new Error("旧密码不对")));
  await saveWrapped(await wrap(raw, password));
  await remember(raw);
}

/** 二次验证：输登录密码解开数据密钥，5 分钟内有效：输一次登录密码解开。 */
export async function unlock(password: string): Promise<void> {
  if (!supported()) throw new Error("加密需要用 https 打开 Wharf");
  const w = await loadWrapped();
  if (!w) return void (await afterLogin(password));
  const raw = await unwrap(w, password).catch(() => Promise.reject(new Error("密码不对。如果最近重置过密码，退出后重新登录一次，按提示同步")));
  await remember(raw);
}

export async function open(sealed: string): Promise<string> {
  const key = dataKey();
  if (!key) throw new Error("需要再输一次登录密码");
  const [iv, data] = sealed.slice(PREFIX.length).split(":");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(data)).catch(() => Promise.reject(new Error("解不开这段内容")));
  return new TextDecoder().decode(plain);
}

export async function seal(text: string): Promise<string> {
  const key = dataKey();
  if (!key) throw new Error("需要再输一次登录密码");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return `${PREFIX}${b64(iv)}:${b64(data)}`;
}
