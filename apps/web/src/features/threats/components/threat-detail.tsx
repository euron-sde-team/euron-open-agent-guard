"use client";

import { ArrowLeftIcon, CheckIcon, EyeIcon, SirenIcon, XIcon } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { Surface, SurfaceHeader } from "@/components/surface";
import { buttonVariants } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/api/errors";
import { formatDateTime } from "@/lib/format";
import { detectorLabel, threatKindLabel } from "@/lib/labels";

import { useThreat, useUpdateThreat } from "../api";
import { responseLabel } from "./threats-screen";

export function ThreatDetailScreen({ id }: { id: string }) {
  const q = useThreat(id);
  const update = useUpdateThreat(id);
  if (q.isPending)
    return (
      <div className="space-y-4" aria-busy>
        <Skeleton className="h-10 w-full max-w-96" />
        <Skeleton className="h-64" />
      </div>
    );
  if (q.isError)
    return (
      <Surface>
        <ErrorState error={q.error} title="Could not load this threat" onRetry={() => void q.refetch()} />
      </Surface>
    );
  const t = q.data;
  const set = (status: string, done: string) => update.mutate(status, { onSuccess: () => toast.success(done), onError: (e) => toast.error(errorMessage(e)) });
  return (
    <>
      <Link href="/threats" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Threats
      </Link>
      <PageHeader
        eyebrow={
          <div className="flex flex-wrap gap-1.5">
            <SeverityChip level={t.severity} />
            <StatusChip kind="threat" status={t.status} />
            <Chip>{threatKindLabel(t.kind)}</Chip>
          </div>
        }
        title={t.summary}
        actions={
          <>
            {t.status === "open" && (
              <GatedButton need="write" size="sm" variant="outline" disabled={update.isPending} onClick={() => set("acknowledged", "Acknowledged: you are looking into it.")}>
                <EyeIcon />
                Acknowledge
              </GatedButton>
            )}
            {t.status !== "resolved" && (
              <GatedButton need="write" size="sm" disabled={update.isPending} onClick={() => set("resolved", "Threat resolved.")}>
                <CheckIcon />
                Resolve
              </GatedButton>
            )}
            {t.status !== "false_positive" && (
              <GatedButton need="write" size="sm" variant="ghost" disabled={update.isPending} onClick={() => set("false_positive", "Marked as a false positive.")}>
                <XIcon />
                False positive
              </GatedButton>
            )}
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <Surface>
          <SurfaceHeader title="Details" description="What the detector saw. Payloads are redacted before they are stored." />
          <div className="px-5 pb-5">
            <JsonView value={t.details} label="Details" />
          </div>
        </Surface>
        <div className="space-y-4">
          <Surface className="p-5">
            <KeyValues
              items={[
                { label: "Agent", value: t.agent && t.agent_id ? <Link className="text-primary hover:underline" href={`/agents/${t.agent_id}`}>{t.agent}</Link> : "No agent" },
                { label: "Detector", value: `${detectorLabel(t.detector)}: ${t.rule}` },
                { label: "First seen", value: formatDateTime(t.at) },
                { label: "Last seen", value: `${formatDateTime(t.last_seen_at)}${t.occurrences > 1 ? ` (${t.occurrences} occurrences)` : ""}` },
                { label: "Run", value: t.run_id ? <Mono>{t.run_id}</Mono> : "None", hidden: !t.run_id },
                { label: "Decision", value: t.decision_id ? <Mono>{t.decision_id}</Mono> : "None", hidden: !t.decision_id },
              ]}
            />
          </Surface>
          <Surface>
            <SurfaceHeader title="Automatic responses" description="Taken by the threat response playbook for this severity (Settings, Threat responses)." />
            <div className="flex flex-wrap gap-1.5 px-5 pb-5">
              {t.responses.length ? t.responses.map((r, i) => <Chip key={i} tone="violet">{responseLabel(r)}</Chip>) : <span className="text-[13px] text-muted-foreground">None were configured for this severity.</span>}
            </div>
            {t.incident_id && (
              <div className="px-5 pb-5">
                <Link href={`/incidents/${t.incident_id}`} className={buttonVariants({ variant: "outline", size: "sm" })}>
                  <SirenIcon />
                  Open the incident
                </Link>
              </div>
            )}
          </Surface>
        </div>
      </div>
    </>
  );
}
