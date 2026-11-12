import { useEffect, useState } from "react";
import { api } from "@/api";
import { useActions } from "@/components/actions";
import { Notice } from "@/components/common";
import { CodePackageField, type CodePackage } from "@/components/code-package";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import type { ServiceView } from "@/types";

export function Repack({ svc, onClose }: { svc: ServiceView; onClose: () => void }) {
  const actions = useActions();
  // undefined：还在读；null：没有记录（之前是上传的 zip 或 CLI 部署的）。
  const [origin, setOrigin] = useState<
    { server: string; path: string } | null | undefined
  >(undefined);
  useEffect(() => {
    api
      .get<{ server: string; path: string } | null>(
        `/api/services/${encodeURIComponent(svc.name)}/origin`,
      )
      .then(setOrigin)
      .catch(() => setOrigin(null));
  }, [svc.name]);
  const [pkg, setPkg] = useState<CodePackage | null>(null);
  const loaded = origin !== undefined;
  const submit = () => {
    if (!pkg || !("build" in svc.spec.source)) return;
    onClose();
    actions.plan({
      title: `更新 ${svc.name} 的代码`,
      changes: [
        {
          op: "upsert_service",
          name: svc.name,
          spec: {
            ...svc.spec,
            source: { build: { ...svc.spec.source.build, upload: pkg.sha256 } },
          },
        },
      ],
    });
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent aria-describedby={undefined} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>更新 {svc.name} 的代码包</DialogTitle>
        </DialogHeader>
        {loaded ? (
          <CodePackageField
            value={pkg}
            onChange={setPkg}
            service={svc.name}
            initial={origin}
          />
        ) : (
          <Skeleton className="h-32 rounded-lg" />
        )}
        {pkg &&
          "build" in svc.spec.source &&
          pkg.sha256 === svc.spec.source.build.upload && (
            <Notice>代码没有变化。</Notice>
          )}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button
            disabled={
              !pkg ||
              ("build" in svc.spec.source &&
                pkg.sha256 === svc.spec.source.build.upload)
            }
            onClick={submit}
          >
            预览改动
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
