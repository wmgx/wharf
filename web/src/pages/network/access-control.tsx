import type { ReactNode } from "react";
import { usePoll } from "@/api";
import { CodeBlock, ErrorNote, Notice, SectionTitle } from "@/components/common";
import type { AclView } from "@/types";

export function AccessControl({ children }: { children: ReactNode }) {
  const { data: acl, error } = usePoll<AclView>("/api/network/acl", 60000);
  return <>
    <SectionTitle>访问控制</SectionTitle>
    <ErrorNote error={error} />
    {acl && (acl.raw != null
      ? <>
        {acl.status !== "正常" && <Notice kind="warn">{acl.status}</Notice>}
        <CodeBlock>{acl.raw}</CodeBlock>
      </>
      : <Notice kind="warn">{acl.status}{acl.hint && <div>{acl.hint}</div>}</Notice>)}
    {children}
  </>;
}
