import { ArrowUpIcon, FileArchiveIcon, FolderIcon, LoaderIcon, PackageCheckIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "@/api";
import { ErrorNote, Notice } from "@/components/common";
import { Field, Picker, Segmented, serverOptions } from "@/components/fields";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { packZip } from "@/lib/zip-pack";
import { useStatus } from "@/status";

/** 打好、已在控制面上的代码包。 */
export interface CodePackage {
  sha256: string;
  files: number;
  size: number;
  /** 给人看的来源，例如 `app.zip`、`home:/opt/app`；也用来推服务名。 */
  label: string;
  /** 来源目录的最后一段或 zip 文件名（去掉扩展名），用作默认服务名。 */
  stem: string;
}

type How = "zip" | "dir";

const kib = (n: number) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KiB` : `${(n / 1024 / 1024).toFixed(1)} MiB`);

/**
 * 代码包来源：上传 zip，或打包某台服务器上的目录。两种都产出控制面上的同一种代码包
 * （和 `wharf deploy` 一样），之后的构建、版本、回滚都一样。
 */
export function CodePackageField({
  value,
  onChange,
  service,
  initial,
}: {
  value: CodePackage | null;
  onChange: (p: CodePackage | null) => void;
  /** 已有服务：服务器目录打包时记下来源目录。 */
  service?: string;
  initial?: { server: string; path: string } | null;
}) {
  const { status } = useStatus();
  const servers = status?.servers ?? [];
  const [how, setHow] = useState<How>(initial ? "dir" : "zip");
  const [server, setServer] = useState(initial?.server ?? "");
  const [path, setPath] = useState(initial?.path ?? "/");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const chosen = server || serverOptions(servers)[0]?.value || "";
  const hostOk = !!servers.find((s) => s.name === chosen)?.settings.host_terminal;

  const run = async (fn: () => Promise<CodePackage>) => {
    setBusy(true);
    setError(null);
    onChange(null);
    try {
      onChange(await fn());
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const fromZip = (file: File) =>
    run(async () => {
      const p = await packZip(file);
      await api.upload(`/api/uploads/${p.sha256}`, p.blob);
      return { sha256: p.sha256, files: p.files, size: p.size, label: file.name, stem: file.name.replace(/\.zip$/i, "") };
    });

  const fromDir = () =>
    run(async () => {
      const p = await api.post<{ sha256: string; size: number; files: number }>(`/api/servers/${encodeURIComponent(chosen)}/pack`, { path, service });
      const clean = path.replace(/\/+$/, "");
      return { ...p, label: `${chosen}:${clean}`, stem: clean.split("/").pop() ?? "" };
    });

  return (
    <div className="grid gap-3">
      <Segmented
        value={how}
        onChange={(h) => {
          setHow(h);
          setError(null);
        }}
        options={[
          ["zip", "上传 zip"],
          ["dir", "服务器上的目录"],
        ]}
      />
      {how === "zip" ? (
        <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-dashed px-4 py-5 text-sm text-muted-foreground hover:bg-accent/40">
          <FileArchiveIcon className="size-5" />
          <span className="flex-1">选一个 zip（GitHub 下载的源码包也行）。在浏览器里转成代码包再上传，最大 512 MiB。</span>
          <input
            type="file"
            accept=".zip,application/zip"
            className="hidden"
            disabled={busy}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) fromZip(f);
              e.target.value = "";
            }}
          />
        </label>
      ) : (
        <div className="grid gap-3">
          <div className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-2">
            <Picker value={chosen} options={serverOptions(servers)} onChange={setServer} />
            <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/opt/app" className="font-mono text-sm" />
          </div>
          {hostOk ? (
            <DirBrowser server={chosen} path={path} onPath={setPath} />
          ) : (
            <Notice kind="warn">这台服务器没有开启宿主机访问。到"服务器详情 → 设置"打开"允许从页面打开宿主机终端"。</Notice>
          )}
          <Button variant="outline" className="w-fit" disabled={busy || !hostOk || !path.startsWith("/")} onClick={fromDir}>
            <ArrowUpIcon />
            打包这个目录
          </Button>
          <span className="text-xs text-muted-foreground">按 .gitignore、.dockerignore 排除文件，不打包 .git，规则和 wharf deploy 一样。</span>
        </div>
      )}
      {busy && (
        <span className="flex items-center gap-2 text-sm text-muted-foreground">
          <LoaderIcon className="size-4 animate-spin" />
          打包上传中…
        </span>
      )}
      {value && !busy && (
        <span className="flex items-center gap-2 text-sm">
          <PackageCheckIcon className="size-4 text-success" />
          {value.label} · {value.files} 个文件 · {kib(value.size)}
          <span className="font-mono text-xs text-muted-foreground">{value.sha256.slice(0, 12)}</span>
        </span>
      )}
      <ErrorNote error={error} />
    </div>
  );
}

function DirBrowser({ server, path, onPath }: { server: string; path: string; onPath: (p: string) => void }) {
  const [entries, setEntries] = useState<string[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const dir = path.endsWith("/") ? path : path.slice(0, path.lastIndexOf("/") + 1) || "/";

  useEffect(() => {
    let stop = false;
    setEntries(null);
    setError(null);
    const t = setTimeout(async () => {
      try {
        const list = await api.get<string[]>(`/api/servers/${encodeURIComponent(server)}/dirs?path=${encodeURIComponent(dir)}`);
        if (!stop) setEntries(list);
      } catch (e) {
        if (!stop) setError(e);
      }
    }, 300);
    return () => {
      stop = true;
      clearTimeout(t);
    };
  }, [server, dir]);

  const up = dir === "/" ? null : dir.replace(/[^/]+\/$/, "");
  return (
    <Field>
      <div className="max-h-56 overflow-y-auto rounded-lg border bg-card text-sm">
        {up !== null && (
          <button type="button" className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-muted-foreground hover:bg-accent" onClick={() => onPath(up)}>
            ..
          </button>
        )}
        {error ? (
          <div className="p-3">
            <ErrorNote error={error} />
          </div>
        ) : !entries ? (
          <div className="px-3 py-2 text-muted-foreground">读取 {dir}…</div>
        ) : (
          entries
            .filter((e) => e.endsWith("/"))
            .map((e) => (
              <button key={e} type="button" className="flex w-full items-center gap-2 px-3 py-1.5 text-left font-mono hover:bg-accent" onClick={() => onPath(dir + e)}>
                <FolderIcon className="size-3.5 text-muted-foreground" />
                {e}
              </button>
            ))
        )}
      </div>
    </Field>
  );
}
