/**
 * 备注里的私密内容：在浏览器里用口令加密（PBKDF2 → AES-GCM），服务器只存密文。
 * 口令本身不保存；派生出的密钥存在本机 localStorage，过期前不用再输口令。
 * 口令忘了就解不开，没有找回。
 */

const PREFIX = "wharf-enc:v1:";
const STORE = "wharf.vault";
const REMEMBER_MS = 7 * 24 * 3600 * 1000;
// 一个人用的系统，所有备注共用同一个口令，盐固定，换机器输同一个口令就能解开。
const SALT = new TextEncoder().encode("wharf-note-vault-v1");
const ITERATIONS = 600_000;

const b64 = (buf: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

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

let cached: CryptoKey | null = null;

function readStore(): { key: string; until: number } | null {
  try {
    const v = JSON.parse(localStorage.getItem(STORE) ?? "null");
    return v && v.until > Date.now() ? v : null;
  } catch {
    return null;
  }
}

/** 本机是否已解锁（口令派生的密钥还在有效期内）。 */
export async function unlockedKey(): Promise<CryptoKey | null> {
  if (cached) return cached;
  const v = readStore();
  if (!v) return null;
  cached = await crypto.subtle.importKey("raw", unb64(v.key), "AES-GCM", false, ["encrypt", "decrypt"]);
  return cached;
}

export function isUnlocked(): boolean {
  return !!cached || !!readStore();
}

/** 用口令解锁；`check` 是已有密文时，先确认口令能解开它。 */
export async function unlock(passphrase: string, check?: string | null): Promise<void> {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: SALT, iterations: ITERATIONS, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  if (check) await decryptWith(key, check).catch(() => Promise.reject(new Error("口令不对")));
  const raw = await crypto.subtle.exportKey("raw", key);
  try {
    localStorage.setItem(STORE, JSON.stringify({ key: b64(raw), until: Date.now() + REMEMBER_MS }));
  } catch {
    // 存不了就只在这个页面里有效。
  }
  cached = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function lock() {
  cached = null;
  try {
    localStorage.removeItem(STORE);
  } catch {
    // ignore
  }
}

async function decryptWith(key: CryptoKey, sealed: string): Promise<string> {
  const [iv, data] = sealed.slice(PREFIX.length).split(":");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(data));
  return new TextDecoder().decode(plain);
}

export async function open(sealed: string): Promise<string> {
  const key = await unlockedKey();
  if (!key) throw new Error("还没解锁");
  return decryptWith(key, sealed).catch(() => Promise.reject(new Error("这段内容不是用当前口令加密的")));
}

export async function seal(text: string): Promise<string> {
  const key = await unlockedKey();
  if (!key) throw new Error("还没解锁");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
  return `${PREFIX}${b64(iv)}:${b64(data)}`;
}
