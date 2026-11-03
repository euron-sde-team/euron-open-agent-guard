"use client";

import { DecisionChip, SeverityChip } from "@/components/badges";
import { ErrorState } from "@/components/error-state";
import { Hint } from "@/components/hint";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono } from "@/components/kv";
import { Chip } from "@/components/ui/chip";
import { Sheet, SheetBody, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime, formatMs } from "@/lib/format";
import { humanize, reasonLabel } from "@/lib/labels";
import { arr, num, obj, str } from "@/lib/read";

import { useDecision } from "../api";

/** Everything about one decision: the input, the rules that matched and the risk factors. */
export function DecisionSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const q = useDecision(id);
  const d = q.data;
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full max-w-xl">
        <SheetHeader>
          <SheetTitle>Decision</SheetTitle>
        </SheetHeader>
        <SheetBody className="space-y-5">
          {q.isPending ? (
            <div className="space-y-3" aria-busy>
              <Skeleton className="h-6 w-48" />
              <Skeleton className="h-32" />
            </div>
          ) : q.isError ? (
            <ErrorState compact error={q.error} title="Could not load the decision" onRetry={() => void q.refetch()} />
          ) : d ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <DecisionChip decision={d.decision} />
                {d.would_be !== d.decision && (
                  <span className="text-[12px] text-muted-foreground">
                    would be <DecisionChip decision={d.would_be} tip={false} /> (audit mode)
                  </span>
                )}
                <SeverityChip level={d.risk_level} prefix={`Risk ${d.risk_score}`} />
              </div>
              <div className="rounded-xl bg-muted/70 p-3">
                <div className="font-mono text-[13px] font-medium">
                  {d.agent ?? "unknown agent"} &rarr; {d.tool}.{d.action}
                </div>
                {d.resource && <div className="mt-0.5 font-mono text-[12px] text-muted-foreground">on {d.resource}</div>}
                <p className="mt-2 text-[13px]">{reasonLabel(d.reason_code)}</p>
                {arr(d.reasons).length > 0 && (
                  <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[12.5px] text-muted-foreground">
                    {arr(d.reasons).map((r, i) => (
                      <li key={i}>{String(r)}</li>
                    ))}
                  </ul>
                )}
              </div>
              <KeyValues
                columns={2}
                items={[
                  { label: "When", value: formatDateTime(d.at) },
                  { label: "Latency", value: formatMs(d.latency_ms) },
                  { label: "Policy", value: d.policy_name ? `${d.policy_name} v${d.policy_version ?? "?"}` : "No policy matched" },
                  { label: "Source", value: humanize(d.source) },
                  { label: "Execution", value: humanize(d.execution) || "Not executed" },
                  { label: "On behalf of", value: d.on_behalf_of ?? "Nobody", hidden: !d.on_behalf_of },
                  {
                    label: (
                      <span className="inline-flex items-center gap-1">
                        Action hash <Hint term="actionHash" />
                      </span>
                    ),
                    value: <Mono>{d.action_hash}</Mono>,
                  },
                  { label: "Data classes", value: d.data_classes.length ? d.data_classes.map((c) => <Chip key={c} className="mr-1">{c}</Chip>) : "None found" },
                ]}
              />
              {arr(d.matched).length > 0 && (
                <section>
                  <h3 className="mb-2 text-[13px] font-semibold">Matched rules</h3>
                  <ul className="space-y-1.5">
                    {arr(d.matched).map((m, i) => {
                      const r = obj(m);
                      return (
                        <li key={i} className="flex flex-wrap items-center gap-2 rounded-lg bg-muted/60 px-3 py-2 text-[12.5px]">
                          <DecisionChip decision={str(r.decision) ?? ""} tip={false} />
                          <span className="font-medium">{str(r.policy) ?? str(r.name) ?? "rule"}</span>
                          {num(r.version) != null && <span className="text-subtle">v{num(r.version)}</span>}{num(r.rule) != null && <span className="text-subtle">rule {num(r.rule)}</span>}
                          {str(r.reason) && <span className="text-muted-foreground">{str(r.reason)}</span>}
                        </li>
                      );
                    })}
                  </ul>
                </section>
              )}
              {arr(d.risk_factors).length > 0 && (
                <section>
                  <h3 className="mb-2 flex items-center gap-1 text-[13px] font-semibold">
                    Risk factors <Hint term="riskScore" />
                  </h3>
                  <RiskFactors factors={arr(d.risk_factors)} />
                </section>
              )}
              {Object.keys(obj(d.obligations)).length > 0 && (
                <section>
                  <h3 className="mb-2 text-[13px] font-semibold">Obligations</h3>
                  <JsonView value={d.obligations} label="Obligations" />
                </section>
              )}
              <section>
                <h3 className="mb-2 text-[13px] font-semibold">Parameters</h3>
                <JsonView value={d.params} label="Parameters" />
              </section>
            </>
          ) : null}
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}

/** Factor list with points, most points first. */
export function RiskFactors({ factors }: { factors: unknown[] }) {
  const items = factors
    .map((f) => {
      const o = obj(f);
      return { label: str(o.factor) ?? str(o.name) ?? (typeof f === "string" ? f : JSON.stringify(f)), points: num(o.points) ?? 0 };
    })
    .sort((a, b) => b.points - a.points);
  return (
    <ul className="space-y-1">
      {items.map((f, i) => (
        <li key={i} className="flex items-center justify-between gap-3 rounded-md bg-muted/50 px-3 py-1.5 text-[12.5px]">
          <span className="min-w-0">{f.label}</span>
          <span className="tabular shrink-0 font-semibold text-warning">+{f.points}</span>
        </li>
      ))}
    </ul>
  );
}
