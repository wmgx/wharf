import { Field, Picker, Segmented } from "@/components/fields";
import { Input } from "@/components/ui/input";
import type { ServiceView } from "@/types";

/** 域名或路径指向哪里：Wharf 的服务，或不归 Wharf 管的地址。 */
export type Target = { kind: "service"; service: string; port?: string } | { kind: "upstream"; upstream: string };

const httpPorts = (services: ServiceView[], name: string) => (services.find((s) => s.name === name)?.spec.ports ?? []).filter((p) => !p.udp);

export function targetError(t: Target, services: ServiceView[]): string | null {
  if (t.kind === "service") {
    if (!t.service) return "选一个服务";
    if (httpPorts(services, t.service).length > 1 && !t.port) return "选一个端口";
    return null;
  }
  const m = /^[^\s/:]+:(\d{1,5})$/.exec(t.upstream.trim());
  return m && Number(m[1]) >= 1 && Number(m[1]) <= 65535 ? null : "写成 主机:端口";
}

export function targetText(t: Target): string {
  return t.kind === "service" ? (t.port ? `${t.service}:${t.port}` : t.service) : t.upstream;
}

export function sameTarget(a: Target, b: Target): boolean {
  return targetText(a) === targetText(b) && a.kind === b.kind;
}

/** 选服务（多个端口时再选端口）或填地址。`fixedService` 给了就只选端口。 */
export function TargetFields({ value, onChange, services, idPrefix, fixedService, touched }: {
  value: Target;
  onChange: (t: Target) => void;
  services: ServiceView[];
  idPrefix: string;
  fixedService?: string;
  touched?: boolean;
}) {
  const service = fixedService ?? (value.kind === "service" ? value.service : "");
  const ports = httpPorts(services, service);
  const pickService = (name: string) => {
    const list = httpPorts(services, name);
    onChange({ kind: "service", service: name, port: list.length > 1 ? list[0].name : undefined });
  };
  const error = touched ? targetError(value, services) : null;
  return (
    <div className="grid gap-4">
      {!fixedService && (
        <Segmented<Target["kind"]>
          value={value.kind}
          options={[["service", "服务"], ["upstream", "地址"]]}
          onChange={(k) => (k === "service" ? onChange({ kind: "service", service: "" }) : onChange({ kind: "upstream", upstream: "" }))}
        />
      )}
      {value.kind === "service" ? (
        <>
          {!fixedService && (
            <Field label="服务" htmlFor={`${idPrefix}-service`}>
              <Picker
                id={`${idPrefix}-service`}
                value={value.service}
                placeholder="选一个服务"
                options={services.map((s) => ({ value: s.name, label: s.name, hint: s.spec.server }))}
                onChange={pickService}
              />
            </Field>
          )}
          {ports.length > 1 && (
            <Field label="端口" htmlFor={`${idPrefix}-port`}>
              <Picker
                id={`${idPrefix}-port`}
                value={value.port ?? ""}
                placeholder="选一个端口"
                options={ports.map((p) => ({ value: p.name, label: p.name }))}
                onChange={(port) => onChange({ kind: "service", service, port })}
              />
            </Field>
          )}
        </>
      ) : (
        <Field label="地址" htmlFor={`${idPrefix}-upstream`}>
          <Input
            id={`${idPrefix}-upstream`}
            className="font-mono"
            placeholder="127.0.0.1:7700"
            value={value.upstream}
            onChange={(e) => onChange({ kind: "upstream", upstream: e.target.value })}
          />
        </Field>
      )}
      {error && <p className="-mt-2 text-xs text-destructive">{error}</p>}
    </div>
  );
}
