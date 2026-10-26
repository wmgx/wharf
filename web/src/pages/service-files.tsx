import { ChevronRightIcon, DownloadIcon, EyeIcon, FileIcon, FolderIcon, LinkIcon, UploadIcon } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { api, usePoll } from "@/api";
import { CodeBlock, Empty, ErrorNote, ago } from "@/components/common";
import { bytes } from "@/components/metrics";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { FileEntry } from "@/types";

/** 超过这个大小不在页面上预览，只能下载。 */
const PREVIEW_MAX = 1 << 20;

const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);

/** 服务数据目录 `/srv/<服务>/` 的文件：浏览、预览、下载、上传。 */
export function Files({ name }: { name: string }) {
  const [dir, setDir] = useState("");
  const base = `/api/services/${encodeURIComponent(name)}/files`;
  const { data, error, refresh } = usePoll<FileEntry[]>(`${base}?path=${encodeURIComponent(dir)}`, 30000);
  const [preview, setPreview] = useState<{ path: string; text: string } | null>(null);
  const [pending, setPending] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const parts = dir ? dir.split("/") : [];
  const download = (path: string) => `${base}/download?path=${encodeURIComponent(path)}`;

  const open = async (f: FileEntry) => {
    const path = join(dir, f.name);
    try {
      const resp = await fetch(download(path));
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.includes(0)) {
        toast.info(`${f.name} 不是文本，只能下载`);
        return;
      }
      setPreview({ path, text: new TextDecoder().decode(buf) });
    } catch (e) {
      toast.error(`读不了 ${f.name}`, { description: (e as Error).message });
    }
  };

  const upload = async (file: File) => {
    setPending(null);
    setUploading(true);
    try {
      await api.upload(`${base}?path=${encodeURIComponent(join(dir, file.name))}`, file);
      toast.success(`已上传 ${file.name}`);
      refresh();
    } catch (e) {
      toast.error(`上传 ${file.name} 失败`, { description: (e as Error).message });
    } finally {
      setUploading(false);
    }
  };

  const pick = (file?: File) => {
    if (!file) return;
    if (data?.some((f) => f.name === file.name)) setPending(file);
    else upload(file);
  };

  return (
    <>
      <div className="mb-3 flex items-center justify-between gap-2">
        <nav className="flex min-w-0 flex-wrap items-center gap-0.5 font-mono text-xs">
          <button type="button" className="rounded px-1 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground" onClick={() => setDir("")}>
            /srv/{name}
          </button>
          {parts.map((p, i) => (
            <span key={i} className="flex items-center gap-0.5">
              <ChevronRightIcon className="size-3 text-muted-foreground" />
              <button type="button" className="rounded px-1 py-0.5 hover:bg-accent" onClick={() => setDir(parts.slice(0, i + 1).join("/"))}>
                {p}
              </button>
            </span>
          ))}
        </nav>
        <Button variant="outline" size="sm" disabled={uploading} onClick={() => input.current?.click()}>
          <UploadIcon />
          {uploading ? "上传中…" : "上传"}
        </Button>
        <input
          ref={input}
          type="file"
          className="hidden"
          onChange={(e) => {
            pick(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </div>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>空目录</Empty>
      ) : (
        data && (
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead className="text-right">大小</TableHead>
                  <TableHead>修改</TableHead>
                  <TableHead className="w-0" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((f) => (
                  <TableRow key={f.name}>
                    <TableCell className="font-mono text-xs">
                      {f.dir ? (
                        <button type="button" className="flex items-center gap-2 hover:underline" onClick={() => setDir(join(dir, f.name))}>
                          <FolderIcon className="size-4 text-primary" />
                          {f.name}
                        </button>
                      ) : (
                        <span className="flex items-center gap-2">
                          {f.link ? <LinkIcon className="size-4 text-muted-foreground" /> : <FileIcon className="size-4 text-muted-foreground" />}
                          {f.name}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs text-muted-foreground">{f.dir ? "" : bytes(f.size)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ago(new Date(f.modified).toISOString())}</TableCell>
                    <TableCell>
                      {!f.dir && !f.link && (
                        <div className="flex">
                          <Button variant="ghost" size="xs" title="预览" disabled={f.size > PREVIEW_MAX} onClick={() => open(f)}>
                            <EyeIcon />
                          </Button>
                          <Button variant="ghost" size="xs" title="下载" asChild>
                            <a href={download(join(dir, f.name))} download={f.name}>
                              <DownloadIcon />
                            </a>
                          </Button>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )
      )}
      <Dialog open={!!preview} onOpenChange={(o) => !o && setPreview(null)}>
        <DialogContent className="sm:max-w-3xl" aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle className="font-mono text-sm">{preview?.path}</DialogTitle>
          </DialogHeader>
          <CodeBlock className="max-h-[60vh] overflow-auto whitespace-pre">{preview?.text}</CodeBlock>
        </DialogContent>
      </Dialog>
      <Dialog open={!!pending} onOpenChange={(o) => !o && setPending(null)}>
        <DialogContent aria-describedby={undefined}>
          <DialogHeader>
            <DialogTitle>覆盖 {pending?.name}？</DialogTitle>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPending(null)}>
              取消
            </Button>
            <Button variant="destructive" onClick={() => pending && upload(pending)}>
              覆盖
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
