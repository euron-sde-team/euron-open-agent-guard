"use client";

import { DatabaseIcon, LinkIcon, PencilIcon, PlusIcon, Trash2Icon, UserCogIcon, XIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAgents } from "@/features/agents/api";
import { usePermissions } from "@/features/auth/api";
import { useProjects } from "@/features/org/api";
import { ListInput } from "@/features/policies/components/list-input";
import { errorMessage } from "@/lib/api/errors";
import type { AccessRole, Resource } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { humanize } from "@/lib/labels";

import { useBind, useDeleteResource, useDeleteRole, useResources, useRoles, useSaveResource, useUnbind } from "../api";
import { RoleDialog } from "./role-dialog";

const SENSITIVITY_TONE: Record<string, "neutral" | "info" | "warning" | "danger"> = { public: "neutral", internal: "info", confidential: "warning", restricted: "danger" };

function BindDialog({ role, onClose }: { role: AccessRole | null; onClose: () => void }) {
  const bind = useBind();
  const agents = useAgents();
  const projects = useProjects();
  const [type, setType] = React.useState("agent");
  const [subject, setSubject] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    setType("agent");
    setSubject("");
    setError(null);
  }, [role]);
  const options =
    type === "agent" ? (agents.data ?? []).map((a) => ({ value: a.id, label: a.slug })) : type === "project" ? (projects.data ?? []).map((p) => ({ value: p.id, label: p.name })) : [];
  return (
    <Dialog open={!!role} onOpenChange={(o) => !o && !bind.isPending && onClose()}>
      <DialogContent className="max-w-md">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!role) return;
            if (type !== "org" && !subject) return setError(`Pick the ${type}.`);
            bind.mutate(
              { role: role.name, subject_type: type, subject_id: type === "org" ? null : subject },
              {
                onSuccess: () => {
                  toast.success(`${role.name} bound.`);
                  onClose();
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Bind {role?.name}</DialogTitle>
            <DialogDescription>Permissions are inherited organisation to project to agent.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="Applies to" htmlFor="bind-type">
              <SimpleSelect
                id="bind-type"
                value={type}
                onValueChange={(v) => {
                  setType(v);
                  setSubject("");
                }}
                options={[
                  { value: "agent", label: "One agent" },
                  { value: "project", label: "Every agent of a project" },
                  { value: "org", label: "Every agent of the organisation" },
                ]}
              />
            </Field>
            {type !== "org" && (
              <Field label={type === "agent" ? "Agent" : "Project"} htmlFor="bind-subject">
                <SimpleSelect id="bind-subject" value={subject} onValueChange={setSubject} placeholder="Pick one" options={options} />
              </Field>
            )}
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={bind.isPending}>
              Bind role
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Roles() {
  const q = useRoles();
  const del = useDeleteRole();
  const unbind = useUnbind();
  const { can } = usePermissions();
  const [edit, setEdit] = React.useState<{ role: AccessRole | null } | null>(null);
  const [bindRole, setBindRole] = React.useState<AccessRole | null>(null);
  const [remove, setRemove] = React.useState<AccessRole | null>(null);
  return (
    <>
      <div className="mb-3 flex justify-end">
        <GatedButton need="write" onClick={() => setEdit({ role: null })}>
          <PlusIcon />
          Create role
        </GatedButton>
      </div>
      <QueryState
        query={q}
        errorTitle="Could not load roles"
        empty={(d) => d.length === 0}
        emptyState={
          <Surface>
            <EmptyState
              icon={UserCogIcon}
              title="No roles yet"
              description="Roles grant agents permissions on tools, actions and resources. Without one, an agent may call nothing (default deny)."
              action={
                <GatedButton need="write" size="sm" onClick={() => setEdit({ role: null })}>
                  Create the first role
                </GatedButton>
              }
            />
          </Surface>
        }
      >
        {(roles) => (
          <div className="grid gap-4 lg:grid-cols-2">
            {roles.map((r) => (
              <Surface key={r.id} className="flex flex-col">
                <SurfaceHeader
                  title={<span className="font-mono">{r.name}</span>}
                  description={r.description || "No description."}
                  titleExtra={r.inherits.length ? <span className="text-[12px] font-normal text-subtle">inherits {r.inherits.join(", ")}</span> : undefined}
                  action={
                    can("write") ? (
                      <div className="flex gap-0.5">
                        <Button size="icon-xs" variant="ghost" aria-label={`Edit ${r.name}`} onClick={() => setEdit({ role: r })}>
                          <PencilIcon />
                        </Button>
                        <Button size="icon-xs" variant="ghost" aria-label={`Delete ${r.name}`} onClick={() => setRemove(r)}>
                          <Trash2Icon />
                        </Button>
                      </div>
                    ) : undefined
                  }
                />
                <ul className="space-y-1 px-5">
                  {(r.permissions ?? []).map((p) => (
                    <li key={p.id} className="rounded-lg bg-muted/60 px-3 py-2 text-[12.5px]">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="font-mono font-medium">{p.tool}</span>
                        <span className="text-subtle">{(p.actions ?? []).length ? (p.actions ?? []).join(", ") : "every action"}</span>
                        {p.resource && p.resource !== "*" && <span className="font-mono text-subtle">on {p.resource}</span>}
                      </div>
                      {p.condition && <code className="mt-0.5 block font-mono text-[11.5px] text-muted-foreground">when {p.condition}</code>}
                    </li>
                  ))}
                  {!(r.permissions ?? []).length && <li className="text-[12.5px] text-muted-foreground">No permissions of its own.</li>}
                </ul>
                <div className="mt-auto flex flex-wrap items-center gap-1.5 px-5 pt-3 pb-4">
                  <span className="text-[12px] text-subtle">Bound to</span>
                  {(r.bindings ?? []).map((b) => (
                    <Chip key={b.id} tone={b.subject_type === "org" ? "primary" : b.subject_type === "project" ? "info" : "neutral"}>
                      {humanize(b.subject_type)}: {b.subject}
                      {can("write") && (
                        <button
                          type="button"
                          aria-label={`Unbind ${b.subject}`}
                          className="-mr-1 rounded-full p-0.5 hover:bg-black/10 dark:hover:bg-white/10"
                          onClick={() => unbind.mutate(b.id, { onSuccess: () => toast.success("Binding removed."), onError: (e) => toast.error(errorMessage(e)) })}
                        >
                          <XIcon className="size-3" />
                        </button>
                      )}
                    </Chip>
                  ))}
                  {!(r.bindings ?? []).length && <span className="text-[12px] text-muted-foreground">nobody yet</span>}
                  <GatedButton need="write" size="xs" variant="ghost" onClick={() => setBindRole(r)}>
                    <LinkIcon />
                    Bind
                  </GatedButton>
                </div>
              </Surface>
            ))}
          </div>
        )}
      </QueryState>
      <RoleDialog open={!!edit} role={edit?.role ?? null} onOpenChange={(o) => !o && setEdit(null)} />
      <BindDialog role={bindRole} onClose={() => setBindRole(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Delete ${remove?.name}?`}
        description="Agents that relied on it lose its permissions at their next decision."
        confirmLabel="Delete role"
        pending={del.isPending}
        onConfirm={() =>
          remove &&
          del.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Role deleted.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </>
  );
}

function ResourceDialog({ resource, open, onOpenChange }: { resource: Resource | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const save = useSaveResource();
  const projects = useProjects();
  const [key, setKey] = React.useState("");
  const [name, setName] = React.useState("");
  const [sensitivity, setSensitivity] = React.useState("internal");
  const [environment, setEnvironment] = React.useState("production");
  const [classes, setClasses] = React.useState<string[]>([]);
  const [project, setProject] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open) return;
    setKey(resource?.key ?? "");
    setName(resource?.name ?? "");
    setSensitivity(resource?.sensitivity ?? "internal");
    setEnvironment(resource?.environment ?? "production");
    setClasses(resource?.data_classes ?? []);
    setProject(resource?.project_id ?? "");
    setError(null);
  }, [open, resource]);
  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (!/^[a-z0-9_-]+:.+$/i.test(key.trim())) return setError("A resource key is type:name, like database:production or customer:*.");
            if (!name.trim()) return setError("Give the resource a readable name.");
            save.mutate(
              { id: resource?.id, body: { key: key.trim(), name: name.trim(), sensitivity, environment, data_classes: classes, project_id: project || null } },
              {
                onSuccess: () => {
                  toast.success(resource ? "Resource saved." : "Resource registered. Policies and risk rules can now use its sensitivity.");
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>{resource ? "Edit resource" : "Register a resource"}</DialogTitle>
            <DialogDescription>What agents act on. Its owner project, sensitivity and data classes feed ownership checks, risk and policy conditions.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4 sm:grid-cols-2">
            <Field label="Key" htmlFor="res-key" hint="Patterns allowed: customer:*">
              <Input id="res-key" disabled={!!resource} className="font-mono text-[13px]" value={key} placeholder="database:production" onChange={(e) => setKey(e.target.value)} />
            </Field>
            <Field label="Name" htmlFor="res-name">
              <Input id="res-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Sensitivity" htmlFor="res-sens" labelExtra={<Hint term="sensitivity" />}>
              <SimpleSelect id="res-sens" value={sensitivity} onValueChange={setSensitivity} options={["public", "internal", "confidential", "restricted"].map((s) => ({ value: s, label: humanize(s) }))} />
            </Field>
            <Field label="Environment" htmlFor="res-env">
              <SimpleSelect id="res-env" value={environment} onValueChange={setEnvironment} options={["development", "staging", "production"].map((s) => ({ value: s, label: humanize(s) }))} />
            </Field>
            <Field label="Owner project" htmlFor="res-project">
              <SimpleSelect id="res-project" value={project} onValueChange={setProject} options={[{ value: "", label: "Whole organisation" }, ...(projects.data ?? []).map((p) => ({ value: p.id, label: p.name }))]} />
            </Field>
            <Field label="Data classes" htmlFor="res-classes" hint="pii, financial, credentials, health">
              <ListInput id="res-classes" value={classes} onChange={setClasses} placeholder="pii, financial" />
            </Field>
            {error && <FieldError className="sm:col-span-2">{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : "Save resource"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Resources() {
  const q = useResources();
  const projects = useProjects();
  const del = useDeleteResource();
  const { can } = usePermissions();
  const [edit, setEdit] = React.useState<{ resource: Resource | null } | null>(null);
  const [remove, setRemove] = React.useState<Resource | null>(null);
  const projectName = new Map((projects.data ?? []).map((p) => [p.id, p.name]));
  return (
    <Surface>
      <SurfaceHeader
        title="Resources"
        description="An agent in one project cannot act on another project's resources unless a policy grants it."
        action={
          <GatedButton need="write" size="sm" onClick={() => setEdit({ resource: null })}>
            <PlusIcon />
            Register resource
          </GatedButton>
        }
      />
      <QueryState
        query={q}
        errorTitle="Could not load resources"
        empty={(d) => d.length === 0}
        emptyState={
          <EmptyState
            compact
            icon={DatabaseIcon}
            title="No registered resources"
            description="Register databases, customer records or buckets so decisions know their owner, sensitivity and data classes."
            action={
              <GatedButton need="write" size="sm" variant="outline" onClick={() => setEdit({ resource: null })}>
                Register a resource
              </GatedButton>
            }
          />
        }
      >
        {(items) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Resource</TableHead>
                <TableHead>Sensitivity</TableHead>
                <TableHead className="hidden sm:table-cell">Environment</TableHead>
                <TableHead className="hidden md:table-cell">Data classes</TableHead>
                <TableHead className="hidden lg:table-cell">Owner</TableHead>
                <TableHead className="text-right">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <div className="font-mono text-[13px] font-medium">{r.key}</div>
                    <div className="text-[12px] text-muted-foreground">{r.name}</div>
                  </TableCell>
                  <TableCell>
                    <Chip tone={SENSITIVITY_TONE[r.sensitivity] ?? "neutral"}>{humanize(r.sensitivity)}</Chip>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground sm:table-cell">{humanize(r.environment)}</TableCell>
                  <TableCell className="hidden md:table-cell">
                    <div className="flex flex-wrap gap-1">{r.data_classes.length ? r.data_classes.map((c) => <Chip key={c}>{c}</Chip>) : <span className="text-[12px] text-subtle">None</span>}</div>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground lg:table-cell">{r.project_id ? (projectName.get(r.project_id) ?? "Project") : "Organisation"}</TableCell>
                  <TableCell className="text-right">
                    {can("write") && (
                      <div className={cn("flex justify-end gap-0.5")}>
                        <Button size="icon-xs" variant="ghost" aria-label={`Edit ${r.key}`} onClick={() => setEdit({ resource: r })}>
                          <PencilIcon />
                        </Button>
                        <Button size="icon-xs" variant="ghost" aria-label={`Delete ${r.key}`} onClick={() => setRemove(r)}>
                          <Trash2Icon />
                        </Button>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
      <ResourceDialog open={!!edit} resource={edit?.resource ?? null} onOpenChange={(o) => !o && setEdit(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Delete ${remove?.key}?`}
        description="Decisions on it fall back to unregistered defaults: no owner, no sensitivity, no data classes."
        confirmLabel="Delete resource"
        pending={del.isPending}
        onConfirm={() =>
          remove &&
          del.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Resource deleted.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </Surface>
  );
}

export function AccessScreen() {
  return (
    <>
      <PageHeader
        title="Access control"
        description="Roles give agents permissions on tool, action and resource patterns, with optional conditions. Bind a role to an agent, a project or the whole organisation."
      />
      <Tabs defaultValue="roles">
        <TabsList>
          <TabsTrigger value="roles">Roles and permissions</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
        </TabsList>
        <TabsContent value="roles">
          <Roles />
        </TabsContent>
        <TabsContent value="resources">
          <Resources />
        </TabsContent>
      </Tabs>
    </>
  );
}
