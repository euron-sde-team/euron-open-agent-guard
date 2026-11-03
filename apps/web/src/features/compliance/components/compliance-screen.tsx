"use client";

import { CheckCircle2Icon, ClipboardCheckIcon, FileDownIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { ErrorState } from "@/components/error-state";
import { KeyValues, Mono, shortHash } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { Stat } from "@/components/stat";
import { Surface } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Skeleton } from "@/components/ui/skeleton";
import { download } from "@/lib/api/client";
import { errorMessage } from "@/lib/api/errors";
import { cn } from "@/lib/cn";
import { formatDateTime } from "@/lib/format";
import { arr, bool, num, obj, str } from "@/lib/read";

import { useComplianceReport } from "../api";

const STATUS = {
  met: { label: "Met", tone: "success" as const },
  partial: { label: "Partial", tone: "warning" as const },
  gap: { label: "Gap", tone: "danger" as const },
};

function statusOf(s: string | null) {
  return STATUS[(s ?? "gap") as keyof typeof STATUS] ?? STATUS.gap;
}

export function ComplianceScreen() {
  const q = useComplianceReport();
  const exp = (format: "md" | "json") => download(`/api/v1/compliance/export?format=${format}`, `agentguard-compliance.${format}`).catch((e) => toast.error(errorMessage(e)));
  return (
    <>
      <PageHeader
        title="Compliance"
        description="Your controls mapped to the OWASP Top 10 for Agentic Applications, with live evidence from this organisation. The report is signed, with the audit chain head it was built from."
        actions={
          <>
            <Button variant="outline" onClick={() => void exp("md")}>
              <FileDownIcon />
              Markdown
            </Button>
            <Button variant="outline" onClick={() => void exp("json")}>
              <FileDownIcon />
              JSON
            </Button>
          </>
        }
      />
      {q.isPending ? (
        <div className="grid gap-4 md:grid-cols-2" aria-busy>
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-[14px]" />
          ))}
        </div>
      ) : q.isError ? (
        <Surface>
          <ErrorState error={q.error} title="Could not build the compliance report" onRetry={() => void q.refetch()} />
        </Surface>
      ) : (
        (() => {
          const r = q.data;
          const summary = obj(r.summary);
          const controls = arr(r.controls).map(obj);
          const head = obj(r.audit_head);
          const sig = obj(r.signature);
          return (
            <>
              <div className="mb-4 grid gap-4 sm:grid-cols-3">
                <Stat label="Met" value={num(summary.met) ?? 0} tone="good" icon={CheckCircle2Icon} />
                <Stat label="Partial" value={num(summary.partial) ?? 0} tone={(num(summary.partial) ?? 0) > 0 ? "warn" : "default"} />
                <Stat label="Gaps" value={num(summary.gap) ?? 0} tone={(num(summary.gap) ?? 0) > 0 ? "warn" : "default"} icon={XCircleIcon} />
              </div>
              <div className="grid gap-4 lg:grid-cols-2">
                {controls.map((c) => {
                  const st = statusOf(str(c.status));
                  return (
                    <Surface key={str(c.id)} className="flex flex-col">
                      <div className="flex items-start gap-3 px-5 pt-4 pb-2">
                        <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[11.5px] font-semibold text-muted-foreground">{str(c.id)}</span>
                        <div className="min-w-0 flex-1">
                          <h2 className="text-[14px] font-semibold">{str(c.title)}</h2>
                          <p className="text-[12px] text-muted-foreground">{str(c.risk)}</p>
                        </div>
                        <Chip tone={st.tone}>{st.label}</Chip>
                      </div>
                      <ul className="space-y-1.5 px-5 pb-4">
                        {arr(c.checks)
                          .map(obj)
                          .map((k, i) => {
                            const passed = bool(k.passed);
                            return (
                              <li key={i} className={cn("rounded-lg px-3 py-2 text-[12.5px]", passed ? "bg-muted/50" : "bg-danger-soft/50")}>
                                <div className="flex items-start gap-2">
                                  {passed ? <CheckCircle2Icon className="mt-0.5 size-3.5 shrink-0 text-primary" aria-label="Pass" /> : <XCircleIcon className="mt-0.5 size-3.5 shrink-0 text-danger" aria-label="Fail" />}
                                  <div className="min-w-0">
                                    <div className="font-medium">{str(k.name)}</div>
                                    <div className="text-muted-foreground">{str(k.detail)}</div>
                                    {!passed && str(k.action) && <div className="mt-0.5 font-medium text-danger">To do: {str(k.action)}</div>}
                                  </div>
                                </div>
                              </li>
                            );
                          })}
                      </ul>
                    </Surface>
                  );
                })}
              </div>
              <Surface className="mt-4 p-5">
                <div className="mb-3 flex items-center gap-2 text-[13.5px] font-semibold">
                  <ClipboardCheckIcon className="size-4 text-primary" />
                  Signature
                </div>
                <KeyValues
                  columns={2}
                  items={[
                    { label: "Framework", value: str(r.framework) ?? "OWASP" },
                    { label: "Generated", value: formatDateTime(str(r.generated_at)) },
                    { label: "Audit chain head", value: <span>#{num(head.seq) ?? 0} <Mono title={str(head.hash) ?? ""}>{shortHash(str(head.hash), 16, 8) || "none"}</Mono></span> },
                    { label: "Report digest (SHA-256)", value: <Mono title={str(sig.sha256) ?? ""}>{shortHash(str(sig.sha256), 16, 8)}</Mono> },
                    { label: "Signing key", value: <Mono>{str(sig.kid) ?? ""}</Mono> },
                    { label: "Ed25519 signature", value: <Mono title={str(sig.ed25519) ?? ""}>{shortHash(str(sig.ed25519), 20, 10)}</Mono> },
                  ]}
                />
              </Surface>
            </>
          );
        })()
      )}
    </>
  );
}
