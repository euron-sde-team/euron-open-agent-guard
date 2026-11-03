"use client";

import { PencilIcon, PlusIcon, Trash2Icon, UserPlusIcon, XIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { CopyButton } from "@/components/copy-button";
import { GatedButton } from "@/components/gated";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { QueryState } from "@/components/query-state";
import { usePermissions } from "@/features/auth/api";
import { SecretOnceDialog } from "@/features/integrations/components/secret-once-dialog";
import { ListInput } from "@/features/policies/components/list-input";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { Limit, Project } from "@/lib/api/types";
import { formatBytes, formatDate, formatNumber, formatRelative } from "@/lib/format";
import { slugify } from "@/lib/forms";
import { humanize } from "@/lib/labels";
import { ROLES, roleDescription, roleLabel, type Role } from "@/lib/roles";

import { useCreateProject, useDeleteLimit, useInvitations, useInvite, useLimits, useOidc, useProjects, useRevokeInvitation, useSaveLimit, useSaveOidc, useUpdateProject, useUpdateUser, useUsers } from "../api";
import { useDraft } from "./settings-sections";

const ROLE_OPTIONS = ROLES.map((r) => ({ value: r, label: roleLabel(r) }));

export function PeopleSection() {
  const users = useUsers();
  const { can, user: me } = usePermissions();
  const admin = can("admin");
  const invitations = useInvitations(admin);
  const update = useUpdateUser();
  const invite = useInvite();
  const revoke = useRevokeInvitation();
  const now = useNow(60_000);
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<Role>("reviewer");
  const [link, setLink] = React.useState<string | null>(null);
  const pending = (invitations.data ?? []).filter((i) => !i.accepted_at && new Date(i.expires_at) > now);
  return (
    <Surface id="people" className="scroll-mt-20">
      <SurfaceHeader title="Users and roles" description="Auditor < reviewer < security officer < org admin. The role decides what each person may see and change." />
      {admin && (
        <form
          className="flex flex-col gap-2 px-5 pb-4 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) return toast.error("Enter a valid email address.");
            invite.mutate(
              { email: email.trim(), role },
              {
                onSuccess: (inv) => {
                  setEmail("");
                  setLink(inv.invite_url);
                },
                onError: (err) => toast.error(errorMessage(err)),
              },
            );
          }}
        >
          <Input aria-label="Email to invite" type="email" placeholder="colleague@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <SimpleSelect aria-label="Role" className="sm:w-48" value={role} onValueChange={(v) => setRole(v as Role)} options={ROLE_OPTIONS} />
          <Button type="submit" disabled={invite.isPending}>
            <UserPlusIcon />
            Invite
          </Button>
        </form>
      )}
      <QueryState query={users} errorTitle="Could not load people">
        {(list) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Person</TableHead>
                <TableHead>Role</TableHead>
                <TableHead className="hidden md:table-cell">Last sign-in</TableHead>
                <TableHead className="text-right">Access</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((u) => {
                const self = u.id === me?.id;
                return (
                  <TableRow key={u.id} className={u.disabled ? "opacity-60" : undefined}>
                    <TableCell>
                      <div className="font-medium">
                        {u.name} {self && <span className="text-[12px] font-normal text-subtle">(you)</span>}
                      </div>
                      <div className="text-[12px] text-muted-foreground">
                        {u.email}
                        {u.sso && <Chip className="ml-1.5">SSO</Chip>}
                      </div>
                    </TableCell>
                    <TableCell>
                      {admin && !self ? (
                        <SimpleSelect
                          size="sm"
                          aria-label={`Role of ${u.name}`}
                          className="w-44"
                          value={u.role}
                          onValueChange={(v) => update.mutate({ id: u.id, role: v as Role }, { onSuccess: () => toast.success(`${u.name} is now ${roleLabel(v).toLowerCase()}.`), onError: (e) => toast.error(errorMessage(e)) })}
                          options={ROLE_OPTIONS}
                        />
                      ) : (
                        <Chip tone="primary" title={roleDescription(u.role)}>
                          {roleLabel(u.role)}
                        </Chip>
                      )}
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{u.last_login_at ? formatRelative(u.last_login_at, now) : "Never"}</TableCell>
                    <TableCell className="text-right">
                      {admin && !self ? (
                        <Switch
                          checked={!u.disabled}
                          aria-label={u.disabled ? `Enable ${u.name}` : `Disable ${u.name}`}
                          onCheckedChange={(c) => update.mutate({ id: u.id, disabled: !c }, { onSuccess: () => toast.success(c ? `${u.name} can sign in again.` : `${u.name} is disabled and signed out.`), onError: (e) => toast.error(errorMessage(e)) })}
                        />
                      ) : (
                        <span className="text-[12px] text-subtle">{u.disabled ? "Disabled" : "Active"}</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </QueryState>
      {admin && pending.length > 0 && (
        <div className="px-5 pt-2 pb-5">
          <div className="mb-2 text-[12.5px] font-semibold">Pending invitations</div>
          <ul className="space-y-1">
            {pending.map((i) => (
              <li key={i.id} className="flex items-center gap-2 rounded-lg bg-muted/60 px-3 py-2 text-[12.5px]">
                <span className="min-w-0 flex-1 truncate">{i.email}</span>
                <Chip>{roleLabel(i.role)}</Chip>
                <span className="text-subtle">until {formatDate(i.expires_at)}</span>
                <Button size="icon-xs" variant="ghost" aria-label={`Revoke the invitation of ${i.email}`} onClick={() => revoke.mutate(i.id, { onSuccess: () => toast.success("Invitation revoked."), onError: (e) => toast.error(errorMessage(e)) })}>
                  <XIcon />
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="h-2" />
      <SecretOnceDialog value={link} title="Invitation link" description="It was emailed too. Share it only with the person invited; it works once." onClose={() => setLink(null)} />
    </Surface>
  );
}

export function SsoSection() {
  const { can } = usePermissions();
  const admin = can("admin");
  const q = useOidc(admin);
  const save = useSaveOidc();
  const data = q.data;
  const base = React.useMemo(
    () => ({
      issuer: data?.issuer ?? "",
      client_id: data?.client_id ?? "",
      allowed_domains: data?.allowed_domains ?? [],
      role_claim: data?.role_claim ?? "groups",
      default_role: data?.default_role ?? "",
      enabled: data?.enabled ?? false,
      role_map: Object.entries(data?.role_map ?? {})
        .map(([k, v]) => `${k}=${v}`)
        .join(", "),
    }),
    [data],
  );
  const [f, setF, dirty] = useDraft(base);
  const [secret, setSecret] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  if (!admin)
    return (
      <Surface id="sso" className="scroll-mt-20 p-5">
        <h2 className="text-[14px] font-semibold">Single sign-on</h2>
        <p className="mt-1 text-[12.5px] text-muted-foreground">Only org admins configure the identity provider.</p>
      </Surface>
    );
  return (
    <Surface id="sso" className="scroll-mt-20">
      <SurfaceHeader title="Single sign-on (OIDC)" description="People sign in with your identity provider. Groups map to AgentGuard roles." titleExtra={data?.configured ? <Chip tone={data.enabled ? "success" : "neutral"}>{data.enabled ? "On" : "Off"}</Chip> : undefined} />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!/^https:\/\//.test(f.issuer.trim()) && !/^http:\/\/(localhost|127\.)/.test(f.issuer.trim())) return setError("The issuer is an https URL, like https://login.example.com.");
          if (!f.client_id.trim()) return setError("Enter the client id from your identity provider.");
          const roleMap: Record<string, string> = {};
          for (const pair of f.role_map.split(",")) {
            const [k, v] = pair.split("=").map((x) => x?.trim());
            if (k && v) roleMap[k] = v;
          }
          setError(null);
          save.mutate(
            { issuer: f.issuer.trim(), client_id: f.client_id.trim(), client_secret: secret || null, allowed_domains: f.allowed_domains, role_claim: f.role_claim.trim() || "groups", role_map: roleMap, default_role: f.default_role, enabled: f.enabled },
            {
              onSuccess: () => {
                setSecret("");
                toast.success("Single sign-on saved.");
              },
              onError: (err) => setError(errorMessage(err)),
            },
          );
        }}
      >
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4 px-5 pb-5 sm:grid-cols-2">
          {data?.redirect_uri && (
            <div className="sm:col-span-2">
              <div className="mb-1 text-[12px] font-medium text-muted-foreground">Redirect URI (register it with your provider)</div>
              <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
                <code className="min-w-0 flex-1 truncate font-mono text-[12.5px]">{data.redirect_uri}</code>
                <CopyButton value={data.redirect_uri} iconOnly label="Copy the redirect URI" variant="subtle" />
              </div>
            </div>
          )}
          <Field label="Issuer" htmlFor="oidc-issuer">
            <Input id="oidc-issuer" className="font-mono text-[12.5px]" placeholder="https://login.example.com" value={f.issuer} onChange={(e) => setF({ ...f, issuer: e.target.value })} />
          </Field>
          <Field label="Client id" htmlFor="oidc-client">
            <Input id="oidc-client" className="font-mono text-[12.5px]" value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })} />
          </Field>
          <Field label="Client secret" htmlFor="oidc-secret" hint={data?.configured ? "Stored. Leave empty to keep it." : "Write only."}>
            <Input id="oidc-secret" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
          <Field label="Allowed email domains" htmlFor="oidc-domains">
            <ListInput id="oidc-domains" className="text-[13px]" value={f.allowed_domains} onChange={(v) => setF({ ...f, allowed_domains: v })} placeholder="company.com" />
          </Field>
          <Field label="Role claim" htmlFor="oidc-claim">
            <Input id="oidc-claim" className="font-mono text-[12.5px]" value={f.role_claim} onChange={(e) => setF({ ...f, role_claim: e.target.value })} />
          </Field>
          <Field label="Default role" htmlFor="oidc-default" hint="For people whose groups map to no role. Empty refuses them.">
            <SimpleSelect id="oidc-default" value={f.default_role} onValueChange={(v) => setF({ ...f, default_role: v })} options={[{ value: "", label: "Refuse sign-in" }, ...ROLE_OPTIONS]} />
          </Field>
          <Field label="Group to role" htmlFor="oidc-map" className="sm:col-span-2" hint="group=role pairs, comma separated: sec-team=security_officer, platform=org_admin">
            <Input id="oidc-map" className="font-mono text-[12.5px]" value={f.role_map} onChange={(e) => setF({ ...f, role_map: e.target.value })} />
          </Field>
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={f.enabled} onCheckedChange={(c) => setF({ ...f, enabled: c })} aria-label="Enable single sign-on" />
            Enabled
          </label>
          {error && <FieldError className="sm:col-span-2">{error}</FieldError>}
        </div>
        <div className="flex justify-end bg-muted/40 px-5 py-3">
          <Button type="submit" size="sm" disabled={(!dirty && !secret) || save.isPending}>
            {save.isPending ? "Saving..." : "Save"}
          </Button>
        </div>
      </form>
    </Surface>
  );
}

export function ProjectsSection() {
  const q = useProjects();
  const create = useCreateProject();
  const update = useUpdateProject();
  const [name, setName] = React.useState("");
  const [env, setEnv] = React.useState<Project["environment"]>("production");
  return (
    <Surface id="projects" className="scroll-mt-20">
      <SurfaceHeader title="Projects" description="Agents and resources belong to a project; an agent acts on its own project's resources unless a policy says otherwise." />
      <form
        className="flex flex-col gap-2 px-5 pb-4 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return;
          create.mutate(
            { name: name.trim(), slug: slugify(name), environment: env as "development" | "staging" | "production" },
            {
              onSuccess: () => {
                setName("");
                toast.success("Project created.");
              },
              onError: (err) => toast.error(errorMessage(err)),
            },
          );
        }}
      >
        <Input aria-label="Project name" placeholder="New project name" value={name} onChange={(e) => setName(e.target.value)} />
        <SimpleSelect aria-label="Environment" className="sm:w-44" value={env} onValueChange={(v) => setEnv(v)} options={["development", "staging", "production"].map((x) => ({ value: x, label: humanize(x) }))} />
        <GatedButton need="write" type="submit" variant="outline" disabled={!name.trim() || create.isPending}>
          <PlusIcon />
          Add project
        </GatedButton>
      </form>
      <QueryState query={q} errorTitle="Could not load projects">
        {(items) => (
          <ul className="divide-y divide-hairline">
            {items.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">{p.name}</div>
                  <div className="font-mono text-[11.5px] text-subtle">{p.slug}</div>
                </div>
                <span className="text-[12px] text-muted-foreground">{formatNumber(p.agents ?? 0)} agents</span>
                <SimpleSelect
                  size="sm"
                  aria-label={`Environment of ${p.name}`}
                  className="w-36"
                  value={p.environment}
                  onValueChange={(v) => update.mutate({ id: p.id, environment: v as "development" | "staging" | "production" }, { onSuccess: () => toast.success("Environment changed."), onError: (e) => toast.error(errorMessage(e)) })}
                  options={["development", "staging", "production"].map((x) => ({ value: x, label: humanize(x) }))}
                />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
      <div className="h-2" />
    </Surface>
  );
}

const METRICS: Record<string, { label: string; unit: string; windowed: boolean }> = {
  tool_calls_per_run: { label: "Tool calls per run", unit: "calls", windowed: false },
  run_duration_s: { label: "Run duration", unit: "seconds", windowed: false },
  concurrent_runs: { label: "Concurrent runs", unit: "runs", windowed: false },
  failed_attempts: { label: "Failed attempts", unit: "denials", windowed: true },
  requests_per_window: { label: "Requests", unit: "requests", windowed: true },
  data_transfer_bytes: { label: "Data transfer", unit: "bytes", windowed: true },
  sandbox_memory_mb: { label: "Sandbox memory", unit: "MB", windowed: false },
};

function LimitDialog({ limit, open, onOpenChange }: { limit: Limit | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const save = useSaveLimit();
  const [name, setName] = React.useState("");
  const [scope, setScope] = React.useState("agent");
  const [metric, setMetric] = React.useState("requests_per_window");
  const [value, setValue] = React.useState("60");
  const [windowS, setWindowS] = React.useState("60");
  const [onExceed, setOnExceed] = React.useState("deny");
  const [enabled, setEnabled] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open) return;
    setName(limit?.name ?? "");
    setScope(limit?.scope_type ?? "agent");
    setMetric(limit?.metric ?? "requests_per_window");
    setValue(String(limit?.limit_value ?? 60));
    setWindowS(String(limit?.window_s ?? 60));
    setOnExceed(limit?.on_exceed ?? "deny");
    setEnabled(limit?.enabled ?? true);
    setError(null);
  }, [open, limit]);
  const m = METRICS[metric];
  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const v = Number(value);
            const w = Number(windowS);
            if (!name.trim()) return setError("Name the limit.");
            if (!Number.isInteger(v) || v < 1) return setError("The limit is a whole number of at least 1.");
            if (m?.windowed && (!Number.isInteger(w) || w < 1)) return setError("The window is a whole number of seconds.");
            save.mutate(
              { id: limit?.id, body: { name: name.trim(), scope_type: scope, scope_id: limit?.scope_id ?? null, metric, limit_value: v, window_s: w || 60, on_exceed: onExceed, enabled } },
              {
                onSuccess: () => {
                  toast.success("Limit saved. It applies to the next decision.");
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>{limit ? "Edit limit" : "Add a limit"}</DialogTitle>
            <DialogDescription>Counted atomically, so it holds under concurrent requests. A scope of agent applies to each agent separately.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor="lim-name" className="sm:col-span-2">
              <Input id="lim-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Metric" htmlFor="lim-metric">
              <SimpleSelect id="lim-metric" value={metric} onValueChange={setMetric} options={Object.entries(METRICS).map(([k, v]) => ({ value: k, label: v.label }))} />
            </Field>
            <Field label="Applies per" htmlFor="lim-scope">
              <SimpleSelect id="lim-scope" value={scope} onValueChange={setScope} options={["agent", "project", "user", "org"].map((x) => ({ value: x, label: x === "org" ? "Organisation" : humanize(x) }))} />
            </Field>
            <Field label={`Limit (${m?.unit ?? ""})`} htmlFor="lim-value">
              <Input id="lim-value" inputMode="numeric" value={value} onChange={(e) => setValue(e.target.value)} />
            </Field>
            {m?.windowed && (
              <Field label="Window (seconds)" htmlFor="lim-window">
                <Input id="lim-window" inputMode="numeric" value={windowS} onChange={(e) => setWindowS(e.target.value)} />
              </Field>
            )}
            <Field label="When exceeded" htmlFor="lim-exceed">
              <SimpleSelect
                id="lim-exceed"
                value={onExceed}
                onValueChange={setOnExceed}
                options={[
                  { value: "deny", label: "Deny the action" },
                  { value: "suspend", label: "Deny and suspend the agent" },
                ]}
              />
            </Field>
            <label className="flex items-center gap-2 self-end pb-2 text-[13px]">
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Enabled" />
              Enabled
            </label>
            {error && <FieldError className="sm:col-span-2">{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : "Save limit"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function LimitsSection() {
  const q = useLimits();
  const del = useDeleteLimit();
  const [edit, setEdit] = React.useState<{ limit: Limit | null } | null>(null);
  const [remove, setRemove] = React.useState<Limit | null>(null);
  return (
    <Surface id="limits" className="scroll-mt-20">
      <SurfaceHeader
        title="Limits"
        description="Usage limits per agent, user, project or organisation. Repeated violations can suspend the agent automatically."
        action={
          <GatedButton need="write" size="sm" variant="outline" onClick={() => setEdit({ limit: null })}>
            <PlusIcon />
            Add limit
          </GatedButton>
        }
      />
      <QueryState query={q} errorTitle="Could not load limits" empty={(d) => d.length === 0} emptyState={<p className="px-5 pb-5 text-[12.5px] text-muted-foreground">No limits: only policies and the kill switch stop runaway agents. Add calls per run and requests per minute at least.</p>}>
        {(items) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Limit</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="hidden sm:table-cell">Per</TableHead>
                <TableHead className="hidden md:table-cell">When exceeded</TableHead>
                <TableHead className="text-right">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((l) => {
                const m = METRICS[l.metric];
                return (
                  <TableRow key={l.id} className={l.enabled === false ? "opacity-60" : undefined}>
                    <TableCell>
                      <div className="font-medium">{l.name}</div>
                      <div className="text-[12px] text-muted-foreground">{m?.label ?? humanize(l.metric)}</div>
                    </TableCell>
                    <TableCell className="tabular">
                      {l.metric === "data_transfer_bytes" ? formatBytes(l.limit_value) : `${formatNumber(l.limit_value)} ${m?.unit ?? ""}`}
                      {m?.windowed && <span className="text-subtle"> / {l.window_s} s</span>}
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">{l.scope_type === "org" ? "Organisation" : humanize(l.scope_type)}</TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Chip tone={l.on_exceed === "suspend" ? "warning" : "neutral"}>{l.on_exceed === "suspend" ? "Deny and suspend" : "Deny"}</Chip>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-0.5">
                        <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Edit ${l.name}`} onClick={() => setEdit({ limit: l })}>
                          <PencilIcon />
                        </GatedButton>
                        <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Delete ${l.name}`} onClick={() => setRemove(l)}>
                          <Trash2Icon />
                        </GatedButton>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </QueryState>
      <div className="h-2" />
      <LimitDialog open={!!edit} limit={edit?.limit ?? null} onOpenChange={(o) => !o && setEdit(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Delete ${remove?.name}?`}
        description="Agents are no longer held to it."
        confirmLabel="Delete limit"
        pending={del.isPending}
        onConfirm={() =>
          remove &&
          del.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Limit deleted.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </Surface>
  );
}
