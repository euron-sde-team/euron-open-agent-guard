"use client";

import { ArrowLeftIcon, BanIcon, CheckCircle2Icon, FileDownIcon, KeyRoundIcon, OctagonXIcon, PaperclipIcon, PauseIcon, ShieldOffIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono, shortHash } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { ReasonDialog } from "@/components/reason-dialog";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useAgents } from "@/features/agents/api";
import { usePermissions } from "@/features/auth/api";
import { useSecrets } from "@/features/secrets/api";
import { useNow } from "@/hooks/use-now";
import { download } from "@/lib/api/client";
import { errorMessage } from "@/lib/api/errors";
import type { IncidentDetail } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";

import { useIncident, useIncidentAction } from "../api";

type ContainKind = "suspend_agent" | "quarantine_agent" | "revoke_credentials" | "revoke_secret" | "kill_switch";

const CONTAIN: Record<ContainKind, { label: string; icon: typeof PauseIcon; title: string; body: string; target: "agent" | "secret" | null }> = {
  suspend_agent: { label: "Suspend agent", icon: PauseIcon, title: "Suspend the agent?", body: "Every action it tries is denied until someone reactivates it.", target: "agent" },
  quarantine_agent: { label: "Quarantine agent", icon: ShieldOffIcon, title: "Quarantine the agent?", body: "Every action is denied and the agent is flagged as compromised.", target: "agent" },
  revoke_credentials: { label: "Revoke credentials", icon: BanIcon, title: "Revoke all of the agent's credentials?", body: "Its tokens stop working immediately. Issue a new credential once it is safe.", target: "agent" },
  revoke_secret: { label: "Revoke a secret", icon: KeyRoundIcon, title: "Revoke the secret?", body: "Every tool that injects it stops working until you create or rotate a replacement.", target: "secret" },
  kill_switch: { label: "Kill switch", icon: OctagonXIcon, title: "Turn on the kill switch?", body: "Every action of every agent in the organisation is denied within a second, until someone turns it off in Settings.", target: null },
};

function Containment({ inc }: { inc: IncidentDetail }) {
  const actions = useIncidentAction(inc.id);
  const agents = useAgents();
  const secrets = useSecrets();
  const [kind, setKind] = React.useState<ContainKind | null>(null);
  const [target, setTarget] = React.useState("");
  const spec = kind ? CONTAIN[kind] : null;
  React.useEffect(() => {
    if (!kind) return;
    if (CONTAIN[kind].target === "agent") setTarget(inc.agent_ids[0] ?? "");
    else setTarget("");
  }, [kind, inc.agent_ids]);
  const resolved = inc.status === "resolved";
  return (
    <Surface>
      <SurfaceHeader title="Containment" description="Each action runs now and lands on the timeline." />
      <div className="grid gap-2 px-5 pb-5 sm:grid-cols-2">
        {(Object.keys(CONTAIN) as ContainKind[]).map((k) => {
          const c = CONTAIN[k];
          return (
            <GatedButton
              key={k}
              need="write"
              variant={k === "kill_switch" ? "destructive-soft" : "outline"}
              size="sm"
              className="justify-start"
              reason={resolved ? "The incident is resolved." : null}
              onClick={() => setKind(k)}
            >
              <c.icon />
              {c.label}
            </GatedButton>
          );
        })}
      </div>
      <ReasonDialog
        open={!!kind}
        onOpenChange={(o) => !o && setKind(null)}
        title={spec?.title ?? ""}
        description={spec?.body ?? ""}
        confirmLabel={spec?.label ?? "Confirm"}
        pending={actions.contain.isPending}
        onConfirm={(reason) => {
          if (!kind) return;
          if (spec?.target && !target) return toast.error(spec.target === "agent" ? "Pick the agent first." : "Pick the secret first.");
          actions.contain.mutate(
            { action: kind, target: target || null, reason },
            {
              onSuccess: () => {
                toast.success(`${CONTAIN[kind].label}: done. It is on the timeline.`);
                setKind(null);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          );
        }}
      >
        {spec?.target === "agent" && (
          <Field label="Agent" htmlFor="contain-agent">
            <SimpleSelect
              id="contain-agent"
              value={target}
              onValueChange={setTarget}
              placeholder="Pick an agent"
              options={(agents.data ?? []).map((a) => ({ value: a.id, label: `${a.slug}${inc.agent_ids.includes(a.id) ? " (involved)" : ""}` }))}
            />
          </Field>
        )}
        {spec?.target === "secret" && (
          <Field label="Secret" htmlFor="contain-secret">
            <SimpleSelect
              id="contain-secret"
              value={target}
              onValueChange={setTarget}
              placeholder="Pick a secret"
              options={(secrets.data ?? []).filter((s) => !s.revoked_at).map((s) => ({ value: s.id, label: s.name }))}
            />
          </Field>
        )}
      </ReasonDialog>
    </Surface>
  );
}

function EvidenceSection({ inc }: { inc: IncidentDetail }) {
  const actions = useIncidentAction(inc.id);
  const [open, setOpen] = React.useState(false);
  const [kind, setKind] = React.useState("decision");
  const [ref, setRef] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [show, setShow] = React.useState<string | null>(null);
  return (
    <Surface>
      <SurfaceHeader
        title="Evidence"
        description="Frozen snapshots of decisions, threats and audit records, each with its SHA-256."
        action={
          <GatedButton
            need="write"
            size="sm"
            variant="outline"
            onClick={() => {
              setRef("");
              setError(null);
              setOpen(true);
            }}
          >
            <PaperclipIcon />
            Add evidence
          </GatedButton>
        }
      />
      {!inc.evidence.length ? (
        <EmptyState compact icon={PaperclipIcon} title="No evidence attached" description="Attach the decision, threat or audit record by id. Its content is frozen, so later changes cannot alter the record." />
      ) : (
        <ul className="divide-y divide-hairline">
          {inc.evidence.map((e) => (
            <li key={e.id} className="px-5 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <Chip tone="info">{humanize(e.kind)}</Chip>
                <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{e.title}</span>
                <Button size="xs" variant="ghost" onClick={() => setShow(show === e.id ? null : e.id)}>
                  {show === e.id ? "Hide" : "Show"} snapshot
                </Button>
              </div>
              <div className="mt-1 text-[11.5px] text-subtle">
                sha256 <Mono title={e.sha256}>{shortHash(e.sha256, 16, 8)}</Mono> · {e.added_by} · {formatDateTime(e.added_at)}
              </div>
              {show === e.id && <JsonView className="mt-2" value={e.snapshot} label="Snapshot" maxHeight={300} />}
            </li>
          ))}
        </ul>
      )}
      <div className="h-2" />
      <Dialog open={open} onOpenChange={(o) => !actions.evidence.isPending && setOpen(o)}>
        <DialogContent className="max-w-md">
          <form
            className="flex min-h-0 flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              if (!ref.trim()) return setError("Paste the id of the decision, threat or audit record.");
              actions.evidence.mutate(
                { kind, ref_id: ref.trim() },
                {
                  onSuccess: () => {
                    toast.success("Evidence attached and hashed.");
                    setOpen(false);
                  },
                  onError: (err) => setError(errorMessage(err)),
                },
              );
            }}
          >
            <DialogHeader>
              <DialogTitle>Add evidence</DialogTitle>
              <DialogDescription>Ids are on decision sheets, threat pages and audit rows.</DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <Field label="Kind" htmlFor="ev-kind">
                <SimpleSelect
                  id="ev-kind"
                  value={kind}
                  onValueChange={setKind}
                  options={[
                    { value: "decision", label: "Decision" },
                    { value: "threat", label: "Threat" },
                    { value: "audit", label: "Audit record" },
                  ]}
                />
              </Field>
              <Field label="Id" htmlFor="ev-ref">
                <Input id="ev-ref" className="font-mono text-[13px]" value={ref} onChange={(e) => setRef(e.target.value)} />
              </Field>
              {error && <FieldError>{error}</FieldError>}
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={actions.evidence.isPending}>
                Attach
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Surface>
  );
}

function Timeline({ inc }: { inc: IncidentDetail }) {
  const actions = useIncidentAction(inc.id);
  const { can } = usePermissions();
  const now = useNow(60_000);
  const [note, setNote] = React.useState("");
  const items = [...inc.timeline].sort((a, b) => a.at.localeCompare(b.at));
  return (
    <Surface>
      <SurfaceHeader title="Timeline" description="Linked events, containment and notes, in order." />
      <div className="px-5 pb-5">
        <ol className="relative space-y-4 pl-5 before:absolute before:top-1.5 before:bottom-1.5 before:left-[5px] before:w-px before:bg-hairline">
          {items.map((e, i) => (
            <li key={i} className="relative">
              <span className="absolute top-1.5 -left-5 size-2.5 rounded-full bg-primary ring-4 ring-card" aria-hidden />
              <div className="flex flex-wrap items-center gap-2 text-[12px] text-subtle">
                <Chip>{humanize(e.kind)}</Chip>
                <span>{e.actor}</span>
                <span title={formatDateTime(e.at)}>{formatRelative(e.at, now)}</span>
              </div>
              <p className="mt-1 text-[13px]">{e.text}</p>
            </li>
          ))}
        </ol>
        {can("write") && inc.status !== "resolved" && (
          <form
            className="mt-5 flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (!note.trim()) return;
              actions.note.mutate(note.trim(), { onSuccess: () => setNote(""), onError: (err) => toast.error(errorMessage(err)) });
            }}
          >
            <Input aria-label="Add a note" placeholder="Add a note to the timeline" value={note} onChange={(e) => setNote(e.target.value)} />
            <Button type="submit" variant="outline" disabled={!note.trim() || actions.note.isPending}>
              Add note
            </Button>
          </form>
        )}
      </div>
    </Surface>
  );
}

function ResolveDialog({ inc, open, onOpenChange }: { inc: IncidentDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const actions = useIncidentAction(inc.id);
  const [rootCause, setRootCause] = React.useState("");
  const [resolution, setResolution] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  return (
    <Dialog open={open} onOpenChange={(o) => !actions.resolve.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!rootCause.trim() || !resolution.trim()) return setError("Write the root cause and the resolution: they are what the next person reads.");
            actions.resolve.mutate(
              { root_cause: rootCause.trim(), resolution: resolution.trim() },
              {
                onSuccess: () => {
                  toast.success(`INC-${inc.number} resolved.`);
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Resolve INC-{inc.number}</DialogTitle>
            <DialogDescription>Containment stays in place: reactivate agents and rotate secrets separately once it is safe.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="Root cause" htmlFor="res-cause">
              <Textarea id="res-cause" value={rootCause} onChange={(e) => setRootCause(e.target.value)} />
            </Field>
            <Field label="Resolution" htmlFor="res-res">
              <Textarea id="res-res" value={resolution} onChange={(e) => setResolution(e.target.value)} />
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={actions.resolve.isPending}>
              {actions.resolve.isPending ? "Resolving..." : "Resolve incident"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function IncidentDetailScreen({ id }: { id: string }) {
  const q = useIncident(id);
  const agents = useAgents();
  const [resolveOpen, setResolveOpen] = React.useState(false);
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
        <ErrorState error={q.error} title="Could not load this incident" onRetry={() => void q.refetch()} />
      </Surface>
    );
  const inc = q.data;
  const names = new Map((agents.data ?? []).map((a) => [a.id, a.slug]));
  const exp = (format: "md" | "json") =>
    download(`/api/v1/incidents/${inc.id}/export?format=${format}`, `incident-${inc.number}.${format}`).catch((e) => toast.error(errorMessage(e)));
  return (
    <>
      <Link href="/incidents" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Incidents
      </Link>
      <PageHeader
        eyebrow={
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[12px] text-subtle">INC-{inc.number}</span>
            <SeverityChip level={inc.severity} />
            <StatusChip kind="incident" status={inc.status} />
          </div>
        }
        title={inc.title}
        description={inc.summary}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void exp("md")}>
              <FileDownIcon />
              Markdown
            </Button>
            <Button variant="outline" size="sm" onClick={() => void exp("json")}>
              <FileDownIcon />
              JSON
            </Button>
            {inc.status !== "resolved" && (
              <GatedButton need="write" size="sm" onClick={() => setResolveOpen(true)}>
                <CheckCircle2Icon />
                Resolve
              </GatedButton>
            )}
          </>
        }
      />
      {inc.status === "resolved" && (
        <Surface className="mb-4 p-5">
          <KeyValues
            columns={2}
            items={[
              { label: "Root cause", value: inc.root_cause || "Not recorded" },
              { label: "Resolution", value: inc.resolution || "Not recorded" },
            ]}
          />
        </Surface>
      )}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Timeline inc={inc} />
          <EvidenceSection inc={inc} />
        </div>
        <div className="min-w-0 space-y-4">
          <Surface className="p-5">
            <KeyValues
              items={[
                {
                  label: "Agents",
                  value: inc.agent_ids.length ? (
                    <span className="flex flex-wrap gap-1.5">
                      {inc.agent_ids.map((a) => (
                        <Link key={a} href={`/agents/${a}`} className="text-primary hover:underline">
                          {names.get(a) ?? a.slice(0, 8)}
                        </Link>
                      ))}
                    </span>
                  ) : (
                    "None"
                  ),
                },
                { label: "Opened by", value: inc.opened_by === "threat-response" ? "Automatic threat response" : inc.opened_by },
                { label: "Opened", value: formatDateTime(inc.created_at) },
                { label: "Contained", value: inc.contained_at ? formatDateTime(inc.contained_at) : "Not yet" },
                { label: "Resolved", value: inc.resolved_at ? formatDateTime(inc.resolved_at) : "Not yet" },
              ]}
            />
          </Surface>
          <Containment inc={inc} />
        </div>
      </div>
      <ResolveDialog inc={inc} open={resolveOpen} onOpenChange={setResolveOpen} />
    </>
  );
}
