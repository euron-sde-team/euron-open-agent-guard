"use client";

import { PlusIcon, SirenIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAgents } from "@/features/agents/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import { formatRelative } from "@/lib/format";
import { SEVERITIES, severitySpec } from "@/lib/labels";

import { useIncidents, useOpenIncident } from "../api";

function OpenIncidentDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const create = useOpenIncident();
  const agents = useAgents();
  const router = useRouter();
  const [title, setTitle] = React.useState("");
  const [severity, setSeverity] = React.useState("high");
  const [summary, setSummary] = React.useState("");
  const [agent, setAgent] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (open) {
      setTitle("");
      setSeverity("high");
      setSummary("");
      setAgent("");
      setError(null);
    }
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!title.trim()) return setError("Give the incident a title that says what happened.");
            create.mutate(
              { title: title.trim(), severity, summary: summary.trim(), agent_ids: agent ? [agent] : [] },
              {
                onSuccess: (inc) => {
                  toast.success(`Incident INC-${inc.number} opened.`);
                  onOpenChange(false);
                  router.push(`/incidents/${inc.id}`);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Open an incident</DialogTitle>
            <DialogDescription>Collect evidence, contain the agent and record what happened. Threat responses open incidents automatically too.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="Title" htmlFor="inc-title">
              <Input id="inc-title" autoFocus value={title} placeholder="Support agent exported more customer data than expected" onChange={(e) => setTitle(e.target.value)} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Severity" htmlFor="inc-sev">
                <SimpleSelect id="inc-sev" value={severity} onValueChange={setSeverity} options={SEVERITIES.map((s) => ({ value: s, label: severitySpec(s).label }))} />
              </Field>
              <Field label="Agent involved" htmlFor="inc-agent">
                <SimpleSelect id="inc-agent" value={agent} onValueChange={setAgent} options={[{ value: "", label: "None yet" }, ...(agents.data ?? []).map((a) => ({ value: a.id, label: a.slug }))]} />
              </Field>
            </div>
            <Field label="Summary" htmlFor="inc-summary">
              <Textarea id="inc-summary" value={summary} placeholder="What was seen, when, and by whom" onChange={(e) => setSummary(e.target.value)} />
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Opening..." : "Open incident"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function IncidentsScreen() {
  const [status, setStatus] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const q = useIncidents(status);
  const router = useRouter();
  const now = useNow(60_000);
  return (
    <>
      <PageHeader
        title="Incidents"
        description="An incident collects the timeline, frozen evidence (with hashes), containment actions and the resolution. Export it as Markdown or JSON for your records."
        actions={
          <GatedButton need="write" onClick={() => setOpen(true)}>
            <PlusIcon />
            Open incident
          </GatedButton>
        }
      />
      <Tabs value={status} onValueChange={(v) => setStatus(String(v))} className="mb-4">
        <TabsList>
          <TabsTrigger value="">All</TabsTrigger>
          <TabsTrigger value="open">Open</TabsTrigger>
          <TabsTrigger value="contained">Contained</TabsTrigger>
          <TabsTrigger value="resolved">Resolved</TabsTrigger>
        </TabsList>
      </Tabs>
      <Surface>
        <QueryState
          query={q}
          errorTitle="Could not load incidents"
          empty={(d) => d.length === 0}
          emptyState={
            <EmptyState
              icon={SirenIcon}
              title={status ? "No incidents in this state" : "No incidents"}
              description="When a threat response or a person opens an incident, it appears here with its timeline and evidence."
              action={
                <GatedButton need="write" size="sm" variant="outline" onClick={() => setOpen(true)}>
                  Open an incident
                </GatedButton>
              }
            />
          }
        >
          {(items) => (
            <ul className="divide-y divide-hairline">
              {items.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    onClick={() => router.push(`/incidents/${i.id}`)}
                    className="flex w-full flex-col gap-2 px-5 py-4 text-left hover:bg-muted/50 focus-visible:bg-muted focus-visible:outline-none sm:flex-row sm:items-center sm:gap-4"
                  >
                    <span className="tabular w-16 shrink-0 font-mono text-[12.5px] text-subtle">INC-{i.number}</span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13.5px] font-medium">{i.title}</div>
                      <div className="truncate text-[12px] text-muted-foreground">{i.summary || "No summary yet."}</div>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      <SeverityChip level={i.severity} />
                      <StatusChip kind="incident" status={i.status} />
                      <span className="text-[12px] text-subtle">
                        {i.opened_by === "threat-response" ? "auto" : i.opened_by} · {formatRelative(i.created_at, now)}
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      </Surface>
      <OpenIncidentDialog open={open} onOpenChange={setOpen} />
    </>
  );
}
