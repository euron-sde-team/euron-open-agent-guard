"use client";

import { ArrowLeftIcon, BanIcon, BotIcon, KeyRoundIcon, PauseIcon, PlayIcon, PlusIcon, RotateCwIcon, ShieldOffIcon, XIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";

import { StatusChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { KeyValues, Mono } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { ReasonDialog } from "@/components/reason-dialog";
import { Stat } from "@/components/stat";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePermissions } from "@/features/auth/api";
import { useNetworkPolicies } from "@/features/network/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { AgentDetail, Credential, Issued } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatDate, formatDateTime, formatNumber, formatRelative } from "@/lib/format";
import { formatLabels, joinList, parseLabels, splitList } from "@/lib/forms";
import { frameworkLabel } from "@/lib/labels";

import { useAgent, useAgentAction, useIssueCredential, useRevokeCredential, useRotateCredential, useUpdateAgent, type AgentAction } from "../api";
import { CredentialDialog } from "./credential-dialog";
import { DecisionsTable } from "./decisions-table";

const ACTION_COPY: Record<AgentAction, { title: string; body: string; confirm: string; done: string }> = {
  suspend: {
    title: "Suspend this agent?",
    body: "Every action it tries is denied until someone reactivates it. Its credentials stay valid.",
    confirm: "Suspend agent",
    done: "Agent suspended. Its actions are now denied.",
  },
  quarantine: {
    title: "Quarantine this agent?",
    body: "Use this when it behaves suspiciously: every action is denied and the event is flagged for investigation.",
    confirm: "Quarantine agent",
    done: "Agent quarantined.",
  },
  reactivate: {
    title: "Reactivate this agent?",
    body: "It can authenticate and receive decisions again. Make sure whatever caused the suspension is fixed.",
    confirm: "Reactivate",
    done: "Agent reactivated.",
  },
  revoke: {
    title: "Revoke this agent for good?",
    body: "Its credentials stop working immediately and it cannot be reactivated. Register a new agent to replace it.",
    confirm: "Revoke agent",
    done: "Agent revoked.",
  },
};

function StatusActions({ agent }: { agent: AgentDetail }) {
  const act = useAgentAction(agent.id);
  const [pending, setPending] = React.useState<AgentAction | null>(null);
  const actions: { action: AgentAction; label: string; icon: typeof PauseIcon; variant: "outline" | "destructive-soft" | "default" }[] = [];
  if (agent.status === "active") {
    actions.push({ action: "suspend", label: "Suspend", icon: PauseIcon, variant: "outline" });
    actions.push({ action: "quarantine", label: "Quarantine", icon: ShieldOffIcon, variant: "outline" });
  }
  if (agent.status === "suspended" || agent.status === "quarantined") actions.push({ action: "reactivate", label: "Reactivate", icon: PlayIcon, variant: "default" });
  if (agent.status !== "revoked") actions.push({ action: "revoke", label: "Revoke", icon: BanIcon, variant: "destructive-soft" });
  const copy = pending ? ACTION_COPY[pending] : null;
  return (
    <>
      {actions.map((a) => (
        <GatedButton key={a.action} need="write" variant={a.variant} size="sm" onClick={() => setPending(a.action)}>
          <a.icon />
          {a.label}
        </GatedButton>
      ))}
      <ReasonDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        title={copy?.title ?? ""}
        description={copy?.body ?? ""}
        confirmLabel={copy?.confirm ?? "Confirm"}
        destructive={pending !== "reactivate"}
        pending={act.isPending}
        onConfirm={(reason) =>
          pending &&
          act.mutate(
            { action: pending, reason },
            {
              onSuccess: () => {
                toast.success(ACTION_COPY[pending].done);
                setPending(null);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </>
  );
}

function credentialState(c: Credential, now: Date): { label: string; tone: "success" | "warning" | "danger" | "neutral" } {
  if (c.revoked_at) return { label: "Revoked", tone: "neutral" };
  if (c.expires_at && new Date(c.expires_at) < now) return { label: "Expired", tone: "danger" };
  if (c.grace_until && new Date(c.grace_until) > now) return { label: "Rotating out", tone: "warning" };
  return { label: "Active", tone: "success" };
}

function Credentials({ agent }: { agent: AgentDetail }) {
  const issue = useIssueCredential(agent.id);
  const rotate = useRotateCredential(agent.id);
  const revoke = useRevokeCredential(agent.id);
  const now = useNow(60_000);
  const [issued, setIssued] = React.useState<Issued | null>(null);
  const [newOpen, setNewOpen] = React.useState(false);
  const [label, setLabel] = React.useState("default");
  const [days, setDays] = React.useState("90");
  const [cidrs, setCidrs] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);
  const [confirm, setConfirm] = React.useState<{ kind: "rotate" | "revoke"; cred: Credential } | null>(null);
  const disabled = agent.status === "revoked";

  return (
    <Surface>
      <SurfaceHeader
        title="Credentials"
        description="Client id and secret pairs the SDK exchanges at /oauth/token for short-lived signed tokens. Rotation keeps the old one valid for a grace period."
        action={
          <GatedButton
            need="write"
            size="sm"
            reason={disabled ? "A revoked agent cannot get new credentials." : null}
            onClick={() => {
              setLabel(agent.credentials.length ? `key-${agent.credentials.length + 1}` : "default");
              setDays("90");
              setCidrs("");
              setErr(null);
              setNewOpen(true);
            }}
          >
            <PlusIcon />
            Issue credential
          </GatedButton>
        }
      />
      {!agent.credentials.length ? (
        <EmptyState
          compact
          icon={KeyRoundIcon}
          title="No credentials"
          description="Without a credential the agent cannot authenticate, so every request it makes is refused. Issue one to connect the SDK."
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Label</TableHead>
              <TableHead>Client id</TableHead>
              <TableHead>State</TableHead>
              <TableHead className="hidden md:table-cell">Expires</TableHead>
              <TableHead className="hidden md:table-cell">Last used</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {agent.credentials.map((c) => {
              const st = credentialState(c, now);
              const live = !c.revoked_at;
              return (
                <TableRow key={c.id}>
                  <TableCell className="font-medium">
                    {c.label}
                    {c.allowed_cidrs.length > 0 && <div className="font-mono text-[11px] text-subtle">from {c.allowed_cidrs.join(", ")}</div>}
                  </TableCell>
                  <TableCell>
                    <Mono>{c.client_id}</Mono>
                  </TableCell>
                  <TableCell>
                    <Chip tone={st.tone} dot>
                      {st.label}
                    </Chip>
                    {c.grace_until && live && new Date(c.grace_until) > now && <div className="mt-0.5 text-[11px] text-subtle">until {formatDateTime(c.grace_until)}</div>}
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{c.expires_at ? formatDate(c.expires_at) : "Never"}</TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{c.last_used_at ? formatRelative(c.last_used_at, now) : "Never"}</TableCell>
                  <TableCell className="text-right">
                    {live && (
                      <div className="flex justify-end gap-1">
                        <GatedButton need="write" size="xs" variant="ghost" onClick={() => setConfirm({ kind: "rotate", cred: c })}>
                          <RotateCwIcon />
                          Rotate
                        </GatedButton>
                        <GatedButton need="write" size="xs" variant="ghost" className="text-danger" onClick={() => setConfirm({ kind: "revoke", cred: c })}>
                          <XIcon />
                          Revoke
                        </GatedButton>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
      <div className="h-2" />
      <Dialog open={newOpen} onOpenChange={(o) => !issue.isPending && setNewOpen(o)}>
        <DialogContent className="max-w-md">
          <form
            className="flex min-h-0 flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              const d = days.trim() ? Number(days) : null;
              if (d != null && (!Number.isInteger(d) || d < 1 || d > 3650)) return setErr("Expiry is a whole number of days between 1 and 3650, or empty for none.");
              issue.mutate(
                { label: label.trim() || "default", expires_in_days: d, allowed_cidrs: splitList(cidrs) },
                {
                  onSuccess: (r) => {
                    setNewOpen(false);
                    setIssued(r);
                  },
                  onError: (e2) => setErr(errorMessage(e2)),
                },
              );
            }}
          >
            <DialogHeader>
              <DialogTitle>Issue a credential</DialogTitle>
              <DialogDescription>The secrets are shown once, on the next screen.</DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <Field label="Label" htmlFor="cred-label">
                <Input id="cred-label" value={label} onChange={(e) => setLabel(e.target.value)} />
              </Field>
              <Field label="Expires after (days)" htmlFor="cred-days" hint="Leave empty for no expiry. Shorter is safer.">
                <Input id="cred-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
              </Field>
              <Field label="Allowed source networks" htmlFor="cred-cidrs" hint="Optional CIDRs, comma separated. Token exchanges from anywhere else are refused.">
                <Input id="cred-cidrs" className="font-mono text-[13px]" placeholder="10.20.0.0/16" value={cidrs} onChange={(e) => setCidrs(e.target.value)} />
              </Field>
              {err && <FieldError>{err}</FieldError>}
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setNewOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={issue.isPending}>
                {issue.isPending ? "Issuing..." : "Issue credential"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm?.kind === "rotate" ? `Rotate ${confirm?.cred.label}?` : `Revoke ${confirm?.cred.label}?`}
        description={
          confirm?.kind === "rotate"
            ? "A new secret is issued and shown once. The current one keeps working for a grace period, so you can roll it out without downtime."
            : "Tokens from this credential stop working immediately. Agents still using it will be refused."
        }
        confirmLabel={confirm?.kind === "rotate" ? "Rotate" : "Revoke"}
        destructive={confirm?.kind === "revoke"}
        pending={rotate.isPending || revoke.isPending}
        onConfirm={() => {
          if (!confirm) return;
          if (confirm.kind === "rotate")
            rotate.mutate(confirm.cred.id, {
              onSuccess: (r) => {
                setConfirm(null);
                setIssued(r);
              },
              onError: (e) => toast.error(errorMessage(e)),
            });
          else
            revoke.mutate(confirm.cred.id, {
              onSuccess: () => {
                setConfirm(null);
                toast.success("Credential revoked.");
              },
              onError: (e) => toast.error(errorMessage(e)),
            });
        }}
      />
      <CredentialDialog issued={issued} signed={agent.require_signed_requests} onClose={() => setIssued(null)} />
    </Surface>
  );
}

function Configuration({ agent }: { agent: AgentDetail }) {
  const update = useUpdateAgent(agent.id);
  const networks = useNetworkPolicies();
  const { can } = usePermissions();
  const editable = can("write") && agent.status !== "revoked";
  const [roles, setRoles] = React.useState(joinList(agent.roles));
  const [labels, setLabels] = React.useState(formatLabels(agent.labels));
  const [network, setNetwork] = React.useState(agent.network_policy_id ?? "");
  const [signed, setSigned] = React.useState(agent.require_signed_requests);
  React.useEffect(() => {
    setRoles(joinList(agent.roles));
    setLabels(formatLabels(agent.labels));
    setNetwork(agent.network_policy_id ?? "");
    setSigned(agent.require_signed_requests);
  }, [agent]);
  const dirty =
    roles !== joinList(agent.roles) || labels !== formatLabels(agent.labels) || network !== (agent.network_policy_id ?? "") || signed !== agent.require_signed_requests;
  function save() {
    update.mutate(
      {
        roles: splitList(roles),
        labels: parseLabels(labels),
        network_policy_id: network || null,
        clear_network_policy: !network,
        require_signed_requests: signed,
      },
      { onSuccess: () => toast.success("Agent updated. The next decision uses the new settings."), onError: (e) => toast.error(errorMessage(e)) },
    );
  }
  return (
    <Surface>
      <SurfaceHeader title="Identity and access" description="Roles grant permissions; labels and the network policy feed policy conditions and the egress guard." />
      <div className="grid gap-4 px-5 pb-5 md:grid-cols-2">
        <Field label="Roles" htmlFor="cfg-roles" hint="Comma separated role names from Access control.">
          <Input id="cfg-roles" disabled={!editable} value={roles} onChange={(e) => setRoles(e.target.value)} />
        </Field>
        <Field label="Labels" htmlFor="cfg-labels" hint="key=value pairs, comma separated.">
          <Input id="cfg-labels" disabled={!editable} className="font-mono text-[13px]" value={labels} onChange={(e) => setLabels(e.target.value)} />
        </Field>
        <Field label="Network policy" htmlFor="cfg-net" hint="Where its HTTP tools, MCP upstreams and sandbox may connect.">
          <SimpleSelect
            id="cfg-net"
            disabled={!editable}
            value={network}
            onValueChange={setNetwork}
            options={[{ value: "", label: "Organisation default" }, ...(networks.data ?? []).map((n) => ({ value: n.id, label: n.name }))]}
          />
        </Field>
        <label className={cn("flex items-start gap-3 self-end rounded-lg bg-muted/70 p-3", !editable && "opacity-60")}>
          <Switch checked={signed} disabled={!editable} onCheckedChange={setSigned} aria-label="Require signed requests" />
          <span className="text-[13px]">
            <span className="font-medium">Require signed requests</span>
            <span className="block text-[12px] text-muted-foreground">HMAC signature and nonce on every call; replays are refused.</span>
          </span>
        </label>
      </div>
      {editable && (
        <div className="flex justify-end gap-2 bg-muted/40 px-5 py-3">
          <Button size="sm" disabled={!dirty || update.isPending} onClick={save}>
            {update.isPending ? "Saving..." : "Save changes"}
          </Button>
        </div>
      )}
    </Surface>
  );
}

export function AgentDetailScreen({ id }: { id: string }) {
  const q = useAgent(id);
  const now = useNow(60_000);
  if (q.isPending)
    return (
      <div className="space-y-4" aria-busy>
        <Skeleton className="h-10 w-full max-w-80" />
        <Skeleton className="h-28" />
        <Skeleton className="h-64" />
      </div>
    );
  if (q.isError)
    return (
      <Surface>
        <ErrorState error={q.error} title="Could not load this agent" onRetry={() => void q.refetch()} />
      </Surface>
    );
  const a = q.data;
  return (
    <>
      <Link href="/agents" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Agents
      </Link>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2.5">
            <span className="flex size-9 items-center justify-center rounded-xl bg-primary-soft text-primary">
              <BotIcon className="size-5" aria-hidden />
            </span>
            {a.name}
            <StatusChip kind="agent" status={a.status} />
          </span>
        }
        description={a.description || "No description."}
        actions={<StatusActions agent={a} />}
      />
      {a.status !== "active" && (
        <div role="status" className={cn("mb-4 rounded-xl px-4 py-3 text-[13px]", a.status === "quarantined" ? "bg-violet-soft text-violet" : a.status === "revoked" ? "bg-danger-soft text-danger" : "bg-warning-soft text-warning")}>
          <span className="font-semibold">Every action of this agent is denied.</span> {a.status_reason ? `Reason: ${a.status_reason}.` : ""}{" "}
          {a.status_changed_at ? `Since ${formatRelative(a.status_changed_at, now)}.` : ""}
        </div>
      )}
      <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Decisions, 24 hours" value={formatNumber(a.decisions_24h ?? 0)} />
        <Stat label="Denied, 24 hours" value={formatNumber(a.denied_24h ?? 0)} tone={a.denied_24h ? "warn" : "default"} />
        <Stat label="Open threats" value={formatNumber(a.open_threats ?? 0)} tone={a.open_threats ? "warn" : "default"} detail={a.open_threats ? <Link className="text-primary hover:underline" href={`/threats?agent=${a.id}`}>Review threats</Link> : undefined} />
        <Stat label="Approvals pending" value={formatNumber(a.pending_approvals ?? 0)} detail={a.pending_approvals ? <Link className="text-primary hover:underline" href="/approvals">Open the queue</Link> : undefined} />
      </div>
      <Tabs defaultValue="activity">
        <TabsList>
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="credentials">Credentials ({a.credentials.filter((c) => !c.revoked_at).length})</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>
        <TabsContent value="activity">
          <Surface>
            <SurfaceHeader title="Recent decisions" description="Everything this agent asked to do, newest first. Open a row for the input, matched rules and risk factors." />
            <DecisionsTable filters={{ agent_id: a.id, hours: 24 * 30 }} showAgent={false} emptyText="This agent has not asked to do anything yet. Connect the SDK with one of its credentials." />
          </Surface>
        </TabsContent>
        <TabsContent value="credentials">
          <Credentials agent={a} />
        </TabsContent>
        <TabsContent value="config" className="space-y-4">
          <Configuration agent={a} />
          <Surface className="p-5">
            <KeyValues
              columns={3}
              items={[
                { label: "Short name", value: <Mono>{a.slug}</Mono> },
                { label: "Framework", value: frameworkLabel(a.framework) },
                { label: "Project", value: a.project || "Default" },
                { label: "Registered", value: formatDateTime(a.created_at) },
                { label: "Last seen", value: a.last_seen_at ? formatRelative(a.last_seen_at, now) : "Never" },
                { label: "Agent id", value: <Mono>{a.id}</Mono> },
              ]}
            />
          </Surface>
        </TabsContent>
      </Tabs>
    </>
  );
}
