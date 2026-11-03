"use client";

import * as React from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useRoles } from "@/features/access/api";
import { useNetworkPolicies } from "@/features/network/api";
import { useProjects } from "@/features/org/api";
import { errorMessage } from "@/lib/api/errors";
import type { Registered } from "@/lib/api/types";
import { parseLabels, slugify, splitList } from "@/lib/forms";
import { FRAMEWORKS } from "@/lib/labels";

import { useRegisterAgent } from "../api";

export function RegisterAgentDialog({ open, onOpenChange, onRegistered }: { open: boolean; onOpenChange: (o: boolean) => void; onRegistered: (r: Registered, signed: boolean) => void }) {
  const register = useRegisterAgent();
  const projects = useProjects();
  const roles = useRoles();
  const networks = useNetworkPolicies();
  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [slugTouched, setSlugTouched] = React.useState(false);
  const [description, setDescription] = React.useState("");
  const [project, setProject] = React.useState("");
  const [framework, setFramework] = React.useState("langgraph");
  const [roleList, setRoleList] = React.useState("");
  const [labels, setLabels] = React.useState("");
  const [network, setNetwork] = React.useState("");
  const [signed, setSigned] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) return;
    setName("");
    setSlug("");
    setSlugTouched(false);
    setDescription("");
    setProject("");
    setFramework("langgraph");
    setRoleList("");
    setLabels("");
    setNetwork("");
    setSigned(false);
    setError(null);
  }, [open]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const s = slug || slugify(name);
    if (!name.trim() || !s) return setError("Give the agent a name; the short name is derived from it.");
    setError(null);
    register.mutate(
      {
        name: name.trim(),
        slug: s,
        description: description.trim(),
        project_id: project || null,
        framework,
        roles: splitList(roleList),
        labels: parseLabels(labels),
        network_policy_id: network || null,
        require_signed_requests: signed,
      },
      {
        onSuccess: (r) => {
          toast.success(`${r.agent.name} is registered. Copy its credential now.`);
          onOpenChange(false);
          onRegistered(r, signed);
        },
        onError: (err) => setError(errorMessage(err)),
      },
    );
  }

  const roleNames = (roles.data ?? []).map((r) => r.name);
  return (
    <Dialog open={open} onOpenChange={(o) => !register.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-xl">
        <form onSubmit={submit} className="flex min-h-0 flex-col">
          <DialogHeader>
            <DialogTitle>Register an agent</DialogTitle>
            <DialogDescription>It gets its own identity and a credential. Its name or prompt never authenticates it: only the credential does.</DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor="ag-name" className="sm:col-span-2">
              <Input id="ag-name" autoFocus value={name} placeholder="Billing assistant" onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Short name" htmlFor="ag-slug" hint="Used in policies (scope.agents) and logs.">
              <Input
                id="ag-slug"
                value={slugTouched ? slug : slugify(name)}
                placeholder="billing-assistant"
                className="font-mono text-[13px]"
                onChange={(e) => {
                  setSlugTouched(true);
                  setSlug(slugify(e.target.value));
                }}
              />
            </Field>
            <Field label="Framework" htmlFor="ag-fw">
              <SimpleSelect id="ag-fw" value={framework} onValueChange={setFramework} options={FRAMEWORKS.map((f) => ({ value: f.value, label: f.label }))} />
            </Field>
            <Field label="Project" htmlFor="ag-project" hint="Resources of other projects are off limits by default.">
              <SimpleSelect
                id="ag-project"
                value={project}
                onValueChange={setProject}
                placeholder="Default project"
                options={[{ value: "", label: "Default project" }, ...(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.name} (${p.environment})` }))]}
              />
            </Field>
            <Field label="Network policy" htmlFor="ag-net">
              <SimpleSelect
                id="ag-net"
                value={network}
                onValueChange={setNetwork}
                options={[{ value: "", label: "Organisation default" }, ...(networks.data ?? []).map((n) => ({ value: n.id, label: n.name }))]}
              />
            </Field>
            <Field
              label="Roles"
              htmlFor="ag-roles"
              className="sm:col-span-2"
              hint={roleNames.length ? `Comma separated. Existing roles: ${roleNames.join(", ")}.` : "Comma separated. Create roles in Access control."}
            >
              <Input id="ag-roles" value={roleList} placeholder="support, reader" onChange={(e) => setRoleList(e.target.value)} />
            </Field>
            <Field label="Labels" htmlFor="ag-labels" className="sm:col-span-2" hint="key=value pairs, comma separated. Policies can match on them (scope.labels, agent.labels).">
              <Input id="ag-labels" value={labels} placeholder="team=finance, pii_cleared=true" className="font-mono text-[13px]" onChange={(e) => setLabels(e.target.value)} />
            </Field>
            <Field label="Description" htmlFor="ag-desc" className="sm:col-span-2">
              <Textarea id="ag-desc" value={description} placeholder="What it does and who owns it" onChange={(e) => setDescription(e.target.value)} />
            </Field>
            <label className="flex items-start gap-3 rounded-lg bg-muted/70 p-3 sm:col-span-2">
              <Switch checked={signed} onCheckedChange={setSigned} aria-label="Require signed requests" />
              <span className="text-[13px]">
                <span className="font-medium">Require signed requests</span>
                <span className="block text-[12px] text-muted-foreground">Each authorize call carries an HMAC signature and a nonce, so a stolen token alone cannot replay it.</span>
              </span>
            </label>
            {error && <FieldError className="sm:col-span-2">{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={register.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={register.isPending}>
              {register.isPending ? "Registering..." : "Register and issue credential"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
