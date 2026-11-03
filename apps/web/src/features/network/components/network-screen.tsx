"use client";

import { ArrowDownIcon, ArrowUpIcon, GlobeLockIcon, PencilIcon, PlusIcon, SearchCheckIcon, Trash2Icon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { StatusChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAgents } from "@/features/agents/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { NetworkPolicy } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatBytes, formatNumber, formatRelative } from "@/lib/format";
import { parsePorts, splitList } from "@/lib/forms";
import { humanize, reasonLabel } from "@/lib/labels";
import { num, obj, str, strs } from "@/lib/read";

import { useDeleteNetworkPolicy, useEgress, useNetworkPolicies, useSaveNetworkPolicy, useTestDestination } from "../api";

interface RuleRow {
  action: "allow" | "deny";
  host: string;
  cidr: string;
  ports: string;
  methods: string;
  note: string;
}

export function toRuleRows(rules: unknown[]): RuleRow[] {
  return rules.map((r) => {
    const o = obj(r);
    return {
      action: str(o.action) === "deny" ? "deny" : "allow",
      host: str(o.host) ?? "",
      cidr: str(o.cidr) ?? "",
      ports: (Array.isArray(o.ports) ? o.ports : []).join(", "),
      methods: strs(o.methods).join(", "),
      note: str(o.note) ?? "",
    };
  });
}

export function fromRuleRows(rows: RuleRow[]): Record<string, unknown>[] {
  return rows.map((r) => {
    const out: Record<string, unknown> = { action: r.action };
    if (r.host.trim()) out.host = r.host.trim().toLowerCase();
    if (r.cidr.trim()) out.cidr = r.cidr.trim();
    const ports = parsePorts(r.ports);
    if (ports.length) out.ports = ports;
    const methods = splitList(r.methods).map((m) => m.toUpperCase());
    if (methods.length) out.methods = methods;
    if (r.note.trim()) out.note = r.note.trim();
    return out;
  });
}

function ruleText(r: Record<string, unknown>): string {
  const parts = [str(r.host) || str(r.cidr) || "any destination"];
  const ports = Array.isArray(r.ports) ? r.ports : [];
  if (ports.length) parts.push(`port ${ports.join(", ")}`);
  const methods = strs(r.methods);
  if (methods.length) parts.push(methods.join(", "));
  return parts.join(" · ");
}

function PolicyDialog({ policy, open, onOpenChange }: { policy: NetworkPolicy | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const save = useSaveNetworkPolicy();
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [rows, setRows] = React.useState<RuleRow[]>([]);
  const [defaultAction, setDefaultAction] = React.useState("deny");
  const [isDefault, setIsDefault] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open) return;
    setName(policy?.name ?? "");
    setDescription(policy?.description ?? "");
    setRows(toRuleRows(policy?.rules ?? []));
    setDefaultAction(policy?.default_action ?? "deny");
    setIsDefault(policy?.is_default ?? false);
    setError(null);
  }, [open, policy]);
  const set = (i: number, patch: Partial<RuleRow>) => setRows((r) => r.map((x, n) => (n === i ? { ...x, ...patch } : x)));
  const move = (i: number, d: -1 | 1) =>
    setRows((r) => {
      const next = [...r];
      const j = i + d;
      if (j < 0 || j >= next.length) return r;
      [next[i], next[j]] = [next[j] as RuleRow, next[i] as RuleRow];
      return next;
    });
  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-3xl">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim()) return setError("Name the policy.");
            for (const [i, r] of rows.entries()) if (!r.host.trim() && !r.cidr.trim()) return setError(`Rule ${i + 1}: give a host pattern or a CIDR.`);
            save.mutate(
              { id: policy?.id, body: { name: name.trim(), description: description.trim(), rules: fromRuleRows(rows), default_action: defaultAction, is_default: isDefault } },
              {
                onSuccess: () => {
                  toast.success("Network policy saved. It applies to the next connection.");
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>{policy ? `Edit ${policy.name}` : "Create a network policy"}</DialogTitle>
            <DialogDescription>Rules are checked in order and the first match decides. Cloud metadata addresses are always refused.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" htmlFor="np-name">
                <Input id="np-name" value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Description" htmlFor="np-desc">
                <Input id="np-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
              </Field>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[13px] font-medium">Rules, in order</span>
                <Button type="button" size="xs" variant="outline" onClick={() => setRows([...rows, { action: "allow", host: "", cidr: "", ports: "443", methods: "", note: "" }])}>
                  <PlusIcon />
                  Add rule
                </Button>
              </div>
              {!rows.length && <p className="rounded-lg bg-muted/60 p-3 text-[12.5px] text-muted-foreground">No rules: every destination gets the default action.</p>}
              <ol className="space-y-2">
                {rows.map((r, i) => (
                  <li key={i} className="grid gap-2 rounded-xl bg-muted/60 p-3 sm:grid-cols-[110px_1.4fr_1fr_0.8fr_0.9fr_auto]">
                    <SimpleSelect
                      aria-label={`Action of rule ${i + 1}`}
                      value={r.action}
                      onValueChange={(v) => set(i, { action: v === "deny" ? "deny" : "allow" })}
                      options={[
                        { value: "allow", label: "Allow" },
                        { value: "deny", label: "Deny" },
                      ]}
                    />
                    <Input aria-label={`Host pattern ${i + 1}`} className="font-mono text-[12.5px]" placeholder="*.stripe.com" value={r.host} onChange={(e) => set(i, { host: e.target.value })} />
                    <Input aria-label={`CIDR ${i + 1}`} className="font-mono text-[12.5px]" placeholder="10.0.0.0/8" value={r.cidr} onChange={(e) => set(i, { cidr: e.target.value })} />
                    <Input aria-label={`Ports ${i + 1}`} className="font-mono text-[12.5px]" placeholder="443" value={r.ports} onChange={(e) => set(i, { ports: e.target.value })} />
                    <Input aria-label={`Methods ${i + 1}`} className="font-mono text-[12.5px]" placeholder="GET, POST" value={r.methods} onChange={(e) => set(i, { methods: e.target.value })} />
                    <div className="flex">
                      <Button type="button" size="icon-sm" variant="ghost" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)}>
                        <ArrowUpIcon />
                      </Button>
                      <Button type="button" size="icon-sm" variant="ghost" aria-label="Move down" disabled={i === rows.length - 1} onClick={() => move(i, 1)}>
                        <ArrowDownIcon />
                      </Button>
                      <Button type="button" size="icon-sm" variant="ghost" aria-label={`Remove rule ${i + 1}`} onClick={() => setRows(rows.filter((_, n) => n !== i))}>
                        <Trash2Icon />
                      </Button>
                    </div>
                  </li>
                ))}
              </ol>
              <p className="text-[12px] text-muted-foreground">An allow by host name never opens private addresses; only a CIDR rule can.</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="When no rule matches" htmlFor="np-default" labelExtra={<Hint term="networkDefault" />}>
                <SimpleSelect
                  id="np-default"
                  value={defaultAction}
                  onValueChange={setDefaultAction}
                  options={[
                    { value: "deny", label: "Deny (allowlist)" },
                    { value: "allow", label: "Allow public addresses" },
                  ]}
                />
              </Field>
              <label className="flex items-center gap-2 self-end pb-2 text-[13px]">
                <Switch checked={isDefault} onCheckedChange={setIsDefault} aria-label="Organisation default" />
                Organisation default (agents without their own policy)
              </label>
            </div>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : "Save policy"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Tester() {
  const test = useTestDestination();
  const policies = useNetworkPolicies();
  const agents = useAgents();
  const [host, setHost] = React.useState("");
  const [port, setPort] = React.useState("443");
  const [method, setMethod] = React.useState("");
  const [policy, setPolicy] = React.useState("");
  const [agent, setAgent] = React.useState("");
  const r = test.data;
  return (
    <Surface>
      <SurfaceHeader title="Destination tester" description="Would this connection be allowed? Resolves the host and checks every address, like the egress guard does." />
      <form
        className="space-y-3 px-5 pb-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (!host.trim()) return;
          test.mutate(
            { host: host.trim(), port: Number(port) || 443, method: method || null, policy_id: policy || null, agent_id: agent || null },
            { onError: (err) => toast.error(errorMessage(err)) },
          );
        }}
      >
        <div className="grid gap-3 sm:grid-cols-[1fr_90px_110px]">
          <Input aria-label="Host" className="font-mono text-[13px]" placeholder="api.stripe.com" value={host} onChange={(e) => setHost(e.target.value)} />
          <Input aria-label="Port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
          <SimpleSelect aria-label="Method" value={method} onValueChange={setMethod} options={[{ value: "", label: "Any" }, ...["GET", "POST", "PUT", "DELETE"].map((m) => ({ value: m, label: m }))]} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <SimpleSelect aria-label="Policy" value={policy} onValueChange={setPolicy} options={[{ value: "", label: "Policy of the agent (or default)" }, ...(policies.data ?? []).map((p) => ({ value: p.id, label: p.name }))]} />
          <SimpleSelect aria-label="Agent" value={agent} onValueChange={setAgent} options={[{ value: "", label: "No agent" }, ...(agents.data ?? []).map((a) => ({ value: a.id, label: a.slug }))]} />
        </div>
        <Button type="submit" variant="outline" disabled={!host.trim() || test.isPending}>
          <SearchCheckIcon />
          {test.isPending ? "Checking..." : "Test destination"}
        </Button>
        {r && (
          <div className={cn("rounded-xl p-3 text-[13px]", r.allowed ? "bg-primary-soft" : "bg-danger-soft")} aria-live="polite">
            <div className={cn("font-semibold", r.allowed ? "text-primary" : "text-danger")}>{r.allowed ? "Allowed" : "Blocked"}</div>
            <div className="mt-0.5 text-muted-foreground">
              {reasonLabel(r.reason)}
              {r.policy ? ` by ${r.policy}` : ""}
              {r.rule != null ? `, rule ${r.rule + 1}` : ""}.
            </div>
            {r.addresses.length > 0 && <div className="mt-1 font-mono text-[12px] text-subtle">{r.addresses.join(", ")}</div>}
          </div>
        )}
      </form>
    </Surface>
  );
}

function Policies() {
  const q = useNetworkPolicies();
  const del = useDeleteNetworkPolicy();
  const [edit, setEdit] = React.useState<{ policy: NetworkPolicy | null } | null>(null);
  const [remove, setRemove] = React.useState<NetworkPolicy | null>(null);
  return (
    <>
      <div className="mb-3 flex justify-end">
        <GatedButton need="write" onClick={() => setEdit({ policy: null })}>
          <PlusIcon />
          New policy
        </GatedButton>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <QueryState
          query={q}
          errorTitle="Could not load network policies"
          empty={(d) => d.length === 0}
          emptyState={
            <Surface>
              <EmptyState
                icon={GlobeLockIcon}
                title="No network policies"
                description="Without one, agents may reach public addresses only. Write an allowlist for agents that only need a few APIs."
                action={
                  <GatedButton need="write" size="sm" onClick={() => setEdit({ policy: null })}>
                    Create a policy
                  </GatedButton>
                }
              />
            </Surface>
          }
        >
          {(items) => (
            <div className="space-y-4">
              {items.map((p) => (
                <Surface key={p.id}>
                  <SurfaceHeader
                    title={p.name}
                    titleExtra={p.is_default ? <Chip tone="primary">Default</Chip> : undefined}
                    description={p.description || "No description."}
                    action={
                      <div className="flex gap-0.5">
                        <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Edit ${p.name}`} onClick={() => setEdit({ policy: p })}>
                          <PencilIcon />
                        </GatedButton>
                        <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Delete ${p.name}`} onClick={() => setRemove(p)}>
                          <Trash2Icon />
                        </GatedButton>
                      </div>
                    }
                  />
                  <ol className="space-y-1 px-5">
                    {p.rules.map((r, i) => {
                      const o = obj(r);
                      return (
                        <li key={i} className="flex items-center gap-2 rounded-lg bg-muted/60 px-3 py-1.5 text-[12.5px]">
                          <span className="tabular w-4 text-subtle">{i + 1}</span>
                          <Chip tone={str(o.action) === "deny" ? "danger" : "success"}>{humanize(str(o.action))}</Chip>
                          <span className="font-mono">{ruleText(o)}</span>
                          {str(o.note) && <span className="truncate text-subtle">{str(o.note)}</span>}
                        </li>
                      );
                    })}
                    <li className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-[12.5px] text-muted-foreground">
                      <span className="w-4" />
                      Otherwise <Chip tone={p.default_action === "deny" ? "danger" : "success"}>{humanize(p.default_action)}</Chip>
                      {p.default_action === "allow" && <span className="text-subtle">(public addresses only)</span>}
                    </li>
                  </ol>
                  <div className="flex gap-4 px-5 pt-2 pb-4 text-[12px] text-muted-foreground">
                    <span>
                      <span className="tabular font-semibold text-foreground">{p.agents ?? 0}</span> agents
                    </span>
                    <span>
                      <span className="tabular font-semibold text-foreground">{p.blocked_24h ?? 0}</span> blocked in 24 hours
                    </span>
                  </div>
                </Surface>
              ))}
            </div>
          )}
        </QueryState>
        <div>
          <Tester />
        </div>
      </div>
      <PolicyDialog open={!!edit} policy={edit?.policy ?? null} onOpenChange={(o) => !o && setEdit(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Delete ${remove?.name}?`}
        description="Agents using it fall back to the organisation default."
        confirmLabel="Delete policy"
        pending={del.isPending}
        onConfirm={() =>
          remove &&
          del.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Network policy deleted.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </>
  );
}

function Connections() {
  const [decision, setDecision] = React.useState("deny");
  const q = useEgress({ decision });
  const now = useNow(60_000);
  return (
    <Surface>
      <div className="flex px-5 pt-4 pb-3">
        <SimpleSelect
          aria-label="Filter connections"
          className="sm:w-48"
          value={decision}
          onValueChange={setDecision}
          options={[
            { value: "deny", label: "Blocked" },
            { value: "allow", label: "Allowed" },
            { value: "", label: "All connections" },
          ]}
        />
      </div>
      <QueryState
        query={q}
        errorTitle="Could not load connections"
        empty={(d) => d.length === 0}
        emptyState={<EmptyState compact icon={GlobeLockIcon} title={decision === "deny" ? "Nothing blocked" : "No connections"} description="Outbound connections from HTTP tools, MCP upstreams, webhooks, the sandbox and the egress proxy are recorded here." />}
      >
        {(items) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Result</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead className="hidden md:table-cell">Agent</TableHead>
                <TableHead className="hidden lg:table-cell">Why</TableHead>
                <TableHead className="hidden sm:table-cell text-right">Transfer</TableHead>
                <TableHead className="text-right">When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((e) => (
                <TableRow key={e.id}>
                  <TableCell>
                    <StatusChip kind="egress" status={e.decision} />
                  </TableCell>
                  <TableCell>
                    <div className="font-mono text-[12.5px]">
                      {e.method ? `${e.method} ` : ""}
                      {e.host}:{e.port}
                    </div>
                    <div className="text-[11.5px] text-subtle">
                      {humanize(e.source)}
                      {e.ip ? ` · ${e.ip}` : ""}
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{e.agent ?? <span className="text-subtle">None</span>}</TableCell>
                  <TableCell className="hidden text-muted-foreground lg:table-cell">
                    {humanize(e.reason)}
                    {e.policy_name && <div className="text-[11.5px] text-subtle">{e.policy_name}</div>}
                  </TableCell>
                  <TableCell className="tabular hidden text-right text-muted-foreground sm:table-cell">{formatBytes(e.bytes_up + e.bytes_down)}</TableCell>
                  <TableCell className="text-right whitespace-nowrap text-muted-foreground">{formatRelative(e.at, now)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
    </Surface>
  );
}

export function NetworkScreen() {
  const q = useNetworkPolicies();
  const blocked = (q.data ?? []).reduce((s, p) => s + (num(p.blocked_24h) ?? 0), 0);
  return (
    <>
      <PageHeader
        title="Network guard"
        description="Every outbound path AgentGuard owns (HTTP tools, MCP upstreams, webhooks, the sandbox and the egress proxy) is checked against the agent's network policy. The connected peer is checked too, so DNS rebinding cannot reach private ranges."
      />
      <Tabs defaultValue="policies">
        <TabsList>
          <TabsTrigger value="policies">Policies</TabsTrigger>
          <TabsTrigger value="connections">
            Connections
            {blocked > 0 && <span className="tabular rounded-full bg-danger-soft px-1.5 text-[11px] font-semibold text-danger">{formatNumber(blocked)}</span>}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="policies">
          <Policies />
        </TabsContent>
        <TabsContent value="connections">
          <Connections />
        </TabsContent>
      </Tabs>
    </>
  );
}
