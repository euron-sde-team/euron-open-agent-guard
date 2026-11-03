"use client";

import { KeyRoundIcon, PlusIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ListInput } from "@/features/policies/components/list-input";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { Secret } from "@/lib/api/types";
import { formatDate, formatRelative } from "@/lib/format";
import { slugify } from "@/lib/forms";

import { useCreateSecret, useSecrets } from "../api";

export const STORES = [
  { value: "database", label: "AgentGuard (envelope encrypted)" },
  { value: "aws", label: "AWS Secrets Manager" },
  { value: "vault", label: "HashiCorp Vault KV v2" },
  { value: "env", label: "Environment variable" },
];

export function storeLabel(store: string): string {
  return STORES.find((s) => s.value === store)?.label ?? store;
}

/** The status chips a secret shows: its state, plus rotation due when it is. */
export function SecretStatus({ s }: { s: Pick<Secret, "status" | "rotation_due"> }) {
  return (
    <span className="flex flex-wrap gap-1">
      <StatusChip kind="secret" status={s.status ?? "active"} />
      {s.rotation_due && s.status !== "rotation_due" && <StatusChip kind="secret" status="rotation_due" />}
    </span>
  );
}

function CreateSecretDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const create = useCreateSecret();
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [store, setStore] = React.useState("database");
  const [value, setValue] = React.useState("");
  const [ref, setRef] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [hosts, setHosts] = React.useState<string[]>([]);
  const [rotation, setRotation] = React.useState("90");
  const [lease, setLease] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (open) {
      setName("");
      setStore("database");
      setValue("");
      setRef("");
      setDescription("");
      setHosts([]);
      setRotation("90");
      setLease(false);
      setError(null);
    }
  }, [open]);
  const external = store !== "database";
  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            const n = slugify(name);
            if (!n) return setError("Name the secret, like crm-api-key. Tools reference it as {secret:crm-api-key}.");
            if (!external && !value) return setError("Enter the value. It is encrypted and never shown again.");
            if (external && !ref.trim()) return setError("Give the reference in the external store (path, ARN or variable name).");
            const r = rotation.trim() ? Number(rotation) : null;
            if (r != null && (!Number.isInteger(r) || r < 1)) return setError("Rotation is a whole number of days, or empty.");
            create.mutate(
              { name: n, store, value: external ? null : value, external_ref: external ? ref.trim() : null, description: description.trim(), allowed_hosts: hosts, rotation_days: r, requires_lease: lease },
              {
                onSuccess: (s) => {
                  setValue("");
                  toast.success(`${s.name} stored. Its value will never be shown again.`);
                  onOpenChange(false);
                  router.push(`/secrets/${s.id}`);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Store a secret</DialogTitle>
            <DialogDescription>Write only: AgentGuard injects it at execution time, and no API, log or audit record ever returns it.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" htmlFor="sec-name">
                <Input id="sec-name" autoFocus className="font-mono text-[13px]" value={name} placeholder="crm-api-key" onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Store" htmlFor="sec-store">
                <SimpleSelect id="sec-store" value={store} onValueChange={setStore} options={STORES} />
              </Field>
            </div>
            {external ? (
              <Field label="Reference" htmlFor="sec-ref" hint="Where the value lives; AgentGuard reads it at execution time.">
                <Input id="sec-ref" className="font-mono text-[13px]" value={ref} placeholder={store === "aws" ? "prod/crm/api-key" : store === "vault" ? "secret/data/crm#api_key" : "CRM_API_KEY"} onChange={(e) => setRef(e.target.value)} />
              </Field>
            ) : (
              <Field label="Value" htmlFor="sec-value" hint="Encrypted with a per-secret data key. Only a hint (first and last characters) is kept in clear.">
                <Input id="sec-value" type="password" autoComplete="new-password" className="font-mono text-[13px]" value={value} onChange={(e) => setValue(e.target.value)} />
              </Field>
            )}
            <Field label="Description" htmlFor="sec-desc">
              <Input id="sec-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Allowed hosts" htmlFor="sec-hosts" hint="Only sent to these hosts. Empty: any host the tool calls.">
                <ListInput id="sec-hosts" value={hosts} onChange={setHosts} placeholder="api.crm.example" />
              </Field>
              <Field label="Rotate every (days)" htmlFor="sec-rot">
                <Input id="sec-rot" inputMode="numeric" value={rotation} onChange={(e) => setRotation(e.target.value)} />
              </Field>
            </div>
            <label className="flex items-start gap-3 rounded-lg bg-muted/70 p-3">
              <Switch checked={lease} onCheckedChange={setLease} aria-label="Require a lease" />
              <span className="text-[13px]">
                <span className="font-medium">Require a lease</span>
                <span className="block text-[12px] text-muted-foreground">Only agents holding a time-boxed lease get it injected.</span>
              </span>
            </label>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Storing..." : "Store secret"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function SecretsScreen() {
  const q = useSecrets();
  const router = useRouter();
  const now = useNow(60_000);
  const [creating, setCreating] = React.useState(false);
  return (
    <>
      <PageHeader
        title="Secrets"
        description="Credentials stay inside AgentGuard and are injected into HTTP tools, MCP servers and sandbox runs at execution time. Agents never see them. Only metadata is shown here."
        actions={
          <GatedButton need="write" onClick={() => setCreating(true)}>
            <PlusIcon />
            Store secret
          </GatedButton>
        }
      />
      <Surface>
        <QueryState
          query={q}
          errorTitle="Could not load secrets"
          empty={(d) => d.length === 0}
          emptyState={
            <EmptyState
              icon={KeyRoundIcon}
              title="No secrets yet"
              description="Store an API key here instead of giving it to an agent. Tools reference it as {secret:name} and AgentGuard injects it when the call runs."
              action={
                <GatedButton need="write" size="sm" onClick={() => setCreating(true)}>
                  Store your first secret
                </GatedButton>
              }
            />
          }
        >
          {(items) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Secret</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden md:table-cell">Store</TableHead>
                  <TableHead className="hidden lg:table-cell">Hint</TableHead>
                  <TableHead className="hidden sm:table-cell">Expires</TableHead>
                  <TableHead className="text-right">Uses 24h</TableHead>
                  <TableHead className="hidden text-right xl:table-cell">Last used</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((s) => (
                  <TableRow key={s.id} className="cursor-pointer" onClick={() => router.push(`/secrets/${s.id}`)}>
                    <TableCell>
                      <Link href={`/secrets/${s.id}`} className="font-mono text-[13px] font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={(e) => e.stopPropagation()}>
                        {s.name}
                      </Link>
                      <div className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
                        {s.description || "No description"}
                        {s.requires_lease && <Chip tone="info">Lease</Chip>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <SecretStatus s={s} />
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{storeLabel(s.store)}</TableCell>
                    <TableCell className="hidden font-mono text-[12px] text-muted-foreground lg:table-cell">{s.hint}</TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{s.expires_at ? formatDate(s.expires_at) : "Never"}</TableCell>
                    <TableCell className="tabular text-right">{s.uses_24h ?? 0}</TableCell>
                    <TableCell className="hidden text-right text-muted-foreground xl:table-cell">{s.last_used_at ? formatRelative(s.last_used_at, now) : "Never"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryState>
      </Surface>
      <CreateSecretDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}
