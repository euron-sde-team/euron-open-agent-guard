"use client";

import { ArrowLeftIcon, BanIcon, KeyRoundIcon, PlusIcon, RotateCwIcon, Trash2Icon, XIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { KeyValues, Mono } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { ReasonDialog } from "@/components/reason-dialog";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAgents } from "@/features/agents/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { SecretDetail } from "@/lib/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";
import { obj, str } from "@/lib/read";

import { useDeleteSecret, useEndLease, useGrantLease, useRevokeSecret, useRotateSecret, useSecret } from "../api";
import { SecretStatus, storeLabel } from "./secrets-screen";

function RotateDialog({ secret, open, onOpenChange }: { secret: SecretDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const rotate = useRotateSecret(secret.id);
  const [value, setValue] = React.useState("");
  const [grace, setGrace] = React.useState("3600");
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (open) {
      setValue("");
      setGrace("3600");
      setError(null);
    }
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={(o) => !rotate.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-md">
        <form
          className="flex min-h-0 flex-col"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            if (!value) return setError("Enter the new value.");
            rotate.mutate(
              { value, grace_s: Number(grace) },
              {
                onSuccess: (s) => {
                  setValue("");
                  toast.success(`Rotated to v${s.current_version}. The previous version works until the grace period ends.`);
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Rotate {secret.name}</DialogTitle>
            <DialogDescription>The new value is used from the next execution. Running jobs keep the old one during the grace period.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="New value" htmlFor="rot-value">
              <Input id="rot-value" type="password" autoComplete="new-password" autoFocus className="font-mono text-[13px]" value={value} onChange={(e) => setValue(e.target.value)} />
            </Field>
            <Field label="Grace period" htmlFor="rot-grace" labelExtra={<Hint term="grace" />}>
              <SimpleSelect
                id="rot-grace"
                value={grace}
                onValueChange={setGrace}
                options={[
                  { value: "0", label: "None: the old value stops now" },
                  { value: "900", label: "15 minutes" },
                  { value: "3600", label: "1 hour" },
                  { value: "86400", label: "1 day" },
                  { value: "604800", label: "7 days" },
                ]}
              />
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={rotate.isPending}>
              {rotate.isPending ? "Rotating..." : "Rotate"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Leases({ secret }: { secret: SecretDetail }) {
  const agents = useAgents();
  const grant = useGrantLease(secret.id);
  const end = useEndLease(secret.id);
  const now = useNow(30_000);
  const [open, setOpen] = React.useState(false);
  const [agent, setAgent] = React.useState("");
  const [minutes, setMinutes] = React.useState("60");
  const [uses, setUses] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const live = secret.leases.filter((l) => !l.revoked_at && new Date(l.expires_at) > now);
  return (
    <Surface>
      <SurfaceHeader
        title="Leases"
        titleExtra={<Hint term="lease" />}
        description={secret.requires_lease ? "This secret is only injected for agents holding a live lease." : "Optional here: the secret does not require a lease."}
        action={
          <GatedButton
            need="write"
            size="sm"
            variant="outline"
            reason={secret.revoked_at ? "A revoked secret cannot be leased." : null}
            onClick={() => {
              setAgent("");
              setMinutes("60");
              setUses("");
              setReason("");
              setError(null);
              setOpen(true);
            }}
          >
            <PlusIcon />
            Grant lease
          </GatedButton>
        }
      />
      {!secret.leases.length ? (
        <EmptyState compact icon={KeyRoundIcon} title="No leases" description="Grant an agent time-boxed use of this secret, optionally capped to a number of uses." />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Agent</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead className="hidden sm:table-cell">Uses</TableHead>
              <TableHead className="hidden md:table-cell">Reason</TableHead>
              <TableHead className="text-right">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {secret.leases.map((l) => {
              const active = live.includes(l);
              return (
                <TableRow key={l.id} className={active ? undefined : "opacity-60"}>
                  <TableCell className="font-medium">{l.agent || l.agent_id.slice(0, 8)}</TableCell>
                  <TableCell>{l.revoked_at ? <Chip>Ended</Chip> : active ? formatRelative(l.expires_at, now) : <Chip>Expired</Chip>}</TableCell>
                  <TableCell className="tabular hidden sm:table-cell">
                    {l.uses}
                    {l.max_uses != null ? ` of ${l.max_uses}` : ""}
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{l.reason || "None"}</TableCell>
                  <TableCell className="text-right">
                    {active && (
                      <GatedButton need="write" size="xs" variant="ghost" onClick={() => end.mutate(l.id, { onSuccess: () => toast.success("Lease ended."), onError: (e) => toast.error(errorMessage(e)) })}>
                        <XIcon />
                        End
                      </GatedButton>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
      <div className="h-2" />
      <Dialog open={open} onOpenChange={(o) => !grant.isPending && setOpen(o)}>
        <DialogContent className="max-w-md">
          <form
            className="flex min-h-0 flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              if (!agent) return setError("Pick the agent.");
              const m = Number(minutes);
              const u = uses.trim() ? Number(uses) : null;
              if (u != null && (!Number.isInteger(u) || u < 1)) return setError("Max uses is a whole number, or empty for unlimited.");
              grant.mutate(
                { agent_id: agent, minutes: m, max_uses: u, reason: reason.trim() },
                {
                  onSuccess: () => {
                    toast.success("Lease granted.");
                    setOpen(false);
                  },
                  onError: (err) => setError(errorMessage(err)),
                },
              );
            }}
          >
            <DialogHeader>
              <DialogTitle>Grant a lease on {secret.name}</DialogTitle>
              <DialogDescription>The agent&apos;s executions may use the secret until the lease ends. The agent never receives the value.</DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <Field label="Agent" htmlFor="lease-agent">
                <SimpleSelect id="lease-agent" value={agent} onValueChange={setAgent} placeholder="Pick an agent" options={(agents.data ?? []).map((a) => ({ value: a.id, label: a.slug }))} />
              </Field>
              <div className="grid grid-cols-2 gap-4">
                <Field label="Duration" htmlFor="lease-min">
                  <SimpleSelect
                    id="lease-min"
                    value={minutes}
                    onValueChange={setMinutes}
                    options={[
                      { value: "15", label: "15 minutes" },
                      { value: "60", label: "1 hour" },
                      { value: "240", label: "4 hours" },
                      { value: "1440", label: "1 day" },
                    ]}
                  />
                </Field>
                <Field label="Max uses" htmlFor="lease-uses">
                  <Input id="lease-uses" inputMode="numeric" placeholder="Unlimited" value={uses} onChange={(e) => setUses(e.target.value)} />
                </Field>
              </div>
              <Field label="Reason" htmlFor="lease-reason">
                <Input id="lease-reason" value={reason} placeholder="Nightly reconciliation" onChange={(e) => setReason(e.target.value)} />
              </Field>
              {error && <FieldError>{error}</FieldError>}
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={grant.isPending}>
                Grant lease
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Surface>
  );
}

export function SecretDetailScreen({ id }: { id: string }) {
  const q = useSecret(id);
  const agents = useAgents();
  const router = useRouter();
  const revoke = useRevokeSecret(id);
  const del = useDeleteSecret();
  const now = useNow(60_000);
  const [rotating, setRotating] = React.useState(false);
  const [revoking, setRevoking] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  if (q.isPending)
    return (
      <div className="space-y-4" aria-busy>
        <Skeleton className="h-10 w-full max-w-80" />
        <Skeleton className="h-64" />
      </div>
    );
  if (q.isError)
    return (
      <Surface>
        <ErrorState error={q.error} title="Could not load this secret" onRetry={() => void q.refetch()} />
      </Surface>
    );
  const s = q.data;
  const names = new Map((agents.data ?? []).map((a) => [a.id, a.slug]));
  return (
    <>
      <Link href="/secrets" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Secrets
      </Link>
      <PageHeader
        eyebrow={<SecretStatus s={s} />}
        title={<span className="font-mono">{s.name}</span>}
        description={s.description || "No description."}
        actions={
          !s.revoked_at ? (
            <>
              {s.store === "database" && (
                <GatedButton need="write" size="sm" onClick={() => setRotating(true)}>
                  <RotateCwIcon />
                  Rotate
                </GatedButton>
              )}
              <GatedButton need="write" size="sm" variant="destructive-soft" onClick={() => setRevoking(true)}>
                <BanIcon />
                Revoke
              </GatedButton>
            </>
          ) : (
            <GatedButton need="write" size="sm" variant="ghost" onClick={() => setDeleting(true)}>
              <Trash2Icon />
              Delete
            </GatedButton>
          )
        }
      />
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
        <div className="min-w-0 space-y-4">
          <Surface className="p-5">
            <KeyValues
              columns={2}
              items={[
                { label: "Store", value: storeLabel(s.store) },
                { label: "Reference", value: s.external_ref ? <Mono>{s.external_ref}</Mono> : "Stored in AgentGuard", hidden: s.store === "database" },
                { label: "Hint", value: <Mono>{s.hint}</Mono> },
                { label: "Current version", value: `v${s.current_version}` },
                { label: "Previous valid until", value: s.previous_valid_until ? formatDateTime(s.previous_valid_until) : "Not in a grace period" },
                { label: "Expires", value: s.expires_at ? formatDateTime(s.expires_at) : "Never" },
                { label: "Rotation", value: s.rotation_days ? `Every ${s.rotation_days} days${s.rotated_at ? `, last ${formatRelative(s.rotated_at, now)}` : ""}` : "Not scheduled" },
                { label: "Allowed hosts", value: s.allowed_hosts.length ? s.allowed_hosts.join(", ") : "Any host the tool calls" },
                { label: "Uses, 24 hours", value: String(s.uses_24h ?? 0) },
                { label: "Revoked", value: s.revoked_at ? formatDateTime(s.revoked_at) : "No", hidden: !s.revoked_at },
              ]}
            />
          </Surface>
          <Surface>
            <SurfaceHeader title="Versions" description="Values are never shown, only their hints." />
            <ul className="space-y-1 px-3 pb-4">
              {[...s.versions]
                .sort((a, b) => b.version - a.version)
                .map((v) => (
                  <li key={v.version} className="flex items-center gap-3 rounded-lg px-2 py-1.5 text-[13px]">
                    <span className="font-medium">v{v.version}</span>
                    {v.version === s.current_version && <Chip tone="success">Current</Chip>}
                    <Mono className="flex-1 truncate">{v.hint}</Mono>
                    <span className="text-[12px] text-subtle">{formatDateTime(v.created_at)}</span>
                  </li>
                ))}
            </ul>
          </Surface>
          <Leases secret={s} />
        </div>
        <Surface>
          <SurfaceHeader title="Access log" description="Every write, injection and refusal, with the agent and decision behind it." />
          {!s.recent_access.length ? (
            <EmptyState compact icon={KeyRoundIcon} title="Not used yet" description="Uses appear here when a tool injects this secret." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Purpose</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead className="hidden sm:table-cell">Agent</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.recent_access.map((a, i) => {
                  const host = str(obj(a.detail).host);
                  return (
                    <TableRow key={i}>
                      <TableCell className="whitespace-nowrap text-muted-foreground" title={formatDateTime(a.at)}>
                        {formatRelative(a.at, now)}
                      </TableCell>
                      <TableCell>
                        {humanize(a.purpose)}
                        {host && <div className="font-mono text-[11.5px] text-subtle">to {host}</div>}
                      </TableCell>
                      <TableCell>
                        <Chip tone={a.outcome === "used" || a.outcome === "written" ? "success" : a.outcome === "denied" || a.outcome === "refused" ? "danger" : "neutral"}>{humanize(a.outcome)}</Chip>
                        <span className="ml-1.5 text-[11.5px] text-subtle">v{a.version}</span>
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">{a.agent_id ? (names.get(a.agent_id) ?? a.agent_id.slice(0, 8)) : <span className="text-subtle">A person</span>}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Surface>
      </div>
      <RotateDialog secret={s} open={rotating} onOpenChange={setRotating} />
      <ReasonDialog
        open={revoking}
        onOpenChange={setRevoking}
        title={`Revoke ${s.name}?`}
        description="It stops being injected immediately, so every tool that uses it fails until you store a replacement."
        confirmLabel="Revoke secret"
        pending={revoke.isPending}
        onConfirm={(reason) =>
          revoke.mutate(reason, {
            onSuccess: () => {
              toast.success("Secret revoked.");
              setRevoking(false);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${s.name}?`}
        description="Its encrypted versions are destroyed. The access log stays in the audit trail."
        confirmLabel="Delete secret"
        pending={del.isPending}
        onConfirm={() =>
          del.mutate(s.id, {
            onSuccess: () => {
              toast.success("Secret deleted.");
              router.replace("/secrets");
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </>
  );
}
