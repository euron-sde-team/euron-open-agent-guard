"use client";

import { PlusIcon, Trash2Icon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { useTools } from "@/features/tools/api";
import { ListInput } from "@/features/policies/components/list-input";
import { errorMessage } from "@/lib/api/errors";
import type { AccessRole, Permission } from "@/lib/api/types";
import { conditionIssue } from "@/lib/conditions";
import { slugify } from "@/lib/forms";

import { useRoles, useSaveRole } from "../api";

type Row = { tool: string; actions: string[]; resource: string; condition: string };

export function RoleDialog({ role, open, onOpenChange }: { role: AccessRole | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const save = useSaveRole();
  const roles = useRoles();
  const tools = useTools();
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [inherits, setInherits] = React.useState<string[]>([]);
  const [rows, setRows] = React.useState<Row[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open) return;
    setName(role?.name ?? "");
    setDescription(role?.description ?? "");
    setInherits(role?.inherits ?? []);
    setRows((role?.permissions ?? []).map((p) => ({ tool: p.tool, actions: p.actions ?? [], resource: p.resource ?? "*", condition: p.condition ?? "" })));
    setError(null);
  }, [open, role]);
  const setRow = (i: number, patch: Partial<Row>) => setRows((r) => r.map((x, n) => (n === i ? { ...x, ...patch } : x)));
  const others = (roles.data ?? []).filter((r) => r.name !== role?.name).map((r) => r.name);

  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-3xl">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const n = role?.name ?? slugify(name).replace(/-/g, "_");
            if (!n) return setError("Name the role, like support or finance_lead.");
            for (const [i, r] of rows.entries()) {
              if (!r.tool.trim()) return setError(`Permission ${i + 1}: name a tool or a pattern like crm.*`);
              const issue = conditionIssue(r.condition);
              if (issue) return setError(`Permission ${i + 1}: ${issue}`);
            }
            setError(null);
            const permissions: Permission[] = rows.map((r) => ({ tool: r.tool.trim(), actions: r.actions, resource: r.resource.trim() || "*", condition: r.condition.trim() }));
            save.mutate(
              { id: role?.id, body: { name: n, description: description.trim(), inherits, permissions } },
              {
                onSuccess: () => {
                  toast.success(role ? "Role saved. The next decision uses it." : "Role created. Bind it to agents, projects or the organisation.");
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>{role ? `Edit ${role.name}` : "Create a role"}</DialogTitle>
            <DialogDescription>A permission names a tool pattern, the actions it allows, a resource pattern and an optional condition.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" htmlFor="role-name">
                <Input id="role-name" autoFocus={!role} disabled={!!role} className="font-mono text-[13px]" value={name} placeholder="support" onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Description" htmlFor="role-desc">
                <Input id="role-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
              </Field>
            </div>
            <fieldset>
              <legend className="mb-1.5 text-[13px] font-medium">Inherits from</legend>
              {others.length ? (
                <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {others.map((o) => (
                    <label key={o} className="flex items-center gap-1.5 text-[13px]">
                      <input type="checkbox" className="size-3.5 accent-[var(--primary)]" checked={inherits.includes(o)} onChange={(e) => setInherits(e.target.checked ? [...inherits, o] : inherits.filter((x) => x !== o))} />
                      {o}
                    </label>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-muted-foreground">No other roles yet.</p>
              )}
            </fieldset>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[13px] font-medium">Permissions</span>
                <Button type="button" size="xs" variant="outline" onClick={() => setRows([...rows, { tool: "", actions: [], resource: "*", condition: "" }])}>
                  <PlusIcon />
                  Add permission
                </Button>
              </div>
              <datalist id="role-tools">
                {(tools.data ?? []).map((t) => (
                  <option key={t.id} value={t.name} />
                ))}
              </datalist>
              {!rows.length && <p className="rounded-lg bg-muted/60 p-3 text-[12.5px] text-muted-foreground">No permissions: agents with only this role may not call anything.</p>}
              <ul className="space-y-2">
                {rows.map((r, i) => (
                  <li key={i} className="grid gap-2 rounded-xl bg-muted/60 p-3 sm:grid-cols-[1.2fr_1fr_1fr_auto]">
                    <Input aria-label={`Tool pattern ${i + 1}`} list="role-tools" className="font-mono text-[12.5px]" placeholder="crm.*" value={r.tool} onChange={(e) => setRow(i, { tool: e.target.value })} />
                    <ListInput aria-label={`Actions ${i + 1}`} value={r.actions} onChange={(v) => setRow(i, { actions: v })} placeholder="Every action" />
                    <Input aria-label={`Resource pattern ${i + 1}`} className="font-mono text-[12.5px]" value={r.resource} onChange={(e) => setRow(i, { resource: e.target.value })} />
                    <Button type="button" size="icon-sm" variant="ghost" aria-label={`Remove permission ${i + 1}`} onClick={() => setRows(rows.filter((_, n) => n !== i))}>
                      <Trash2Icon />
                    </Button>
                    <Input aria-label={`Condition ${i + 1}`} className="font-mono text-[12.5px] sm:col-span-3" placeholder="Condition (optional): params.amount <= 200" value={r.condition} onChange={(e) => setRow(i, { condition: e.target.value })} />
                  </li>
                ))}
              </ul>
            </div>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : role ? "Save role" : "Create role"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
