"use client";

import { BanIcon, PlayIcon, ShieldPlusIcon, Trash2Icon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { GatedButton } from "@/components/gated";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono } from "@/components/kv";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Sheet, SheetBody, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useRoles } from "@/features/access/api";
import { usePermissions } from "@/features/auth/api";
import { errorMessage } from "@/lib/api/errors";
import type { Tool } from "@/lib/api/types";
import { conditionIssue } from "@/lib/conditions";
import { formatDateTime } from "@/lib/format";
import { splitList } from "@/lib/forms";
import { toolKindLabel } from "@/lib/labels";

import { useDeleteTool, useGrantTool, useUpdateTool } from "../api";

function GrantForm({ tool }: { tool: Tool }) {
  const roles = useRoles();
  const grant = useGrantTool();
  const [role, setRole] = React.useState("");
  const [actions, setActions] = React.useState(tool.actions.join(", "));
  const [resource, setResource] = React.useState("*");
  const [condition, setCondition] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  return (
    <form
      className="space-y-3 rounded-xl bg-muted/60 p-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!role) return setError("Pick the role that may call this tool.");
        const issue = conditionIssue(condition);
        if (issue) return setError(issue);
        setError(null);
        grant.mutate(
          { id: tool.id, body: { role, actions: splitList(actions), resource: resource.trim() || "*", condition: condition.trim() } },
          { onSuccess: () => toast.success(`Agents with the ${role} role may now call ${tool.name}.`), onError: (err) => setError(errorMessage(err)) },
        );
      }}
    >
      <div className="text-[12.5px] font-semibold">Grant to a role</div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Role" htmlFor="grant-role">
          <SimpleSelect id="grant-role" value={role} onValueChange={setRole} placeholder="Pick a role" options={(roles.data ?? []).map((r) => ({ value: r.name, label: r.name }))} />
        </Field>
        <Field label="Actions" htmlFor="grant-actions">
          <Input id="grant-actions" className="font-mono text-[12.5px]" value={actions} onChange={(e) => setActions(e.target.value)} />
        </Field>
        <Field label="Resource pattern" htmlFor="grant-res">
          <Input id="grant-res" className="font-mono text-[12.5px]" value={resource} onChange={(e) => setResource(e.target.value)} />
        </Field>
        <Field label="Condition (optional)" htmlFor="grant-cond">
          <Input id="grant-cond" className="font-mono text-[12.5px]" placeholder="params.amount <= 200" value={condition} onChange={(e) => setCondition(e.target.value)} />
        </Field>
      </div>
      {error && <FieldError>{error}</FieldError>}
      <Button type="submit" size="sm" variant="outline" disabled={grant.isPending}>
        <ShieldPlusIcon />
        {grant.isPending ? "Granting..." : "Grant permission"}
      </Button>
    </form>
  );
}

/** One tool: its definition, configuration, permissions and lifecycle actions. */
export function ToolSheet({ tool, onClose }: { tool: Tool | null; onClose: () => void }) {
  const update = useUpdateTool();
  const del = useDeleteTool();
  const { can } = usePermissions();
  const [confirm, setConfirm] = React.useState(false);
  return (
    <Sheet open={!!tool} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full max-w-xl">
        {tool && (
          <>
            <SheetHeader>
              <SheetTitle className="font-mono">{tool.name}</SheetTitle>
              <SheetDescription>{tool.description || "No description."}</SheetDescription>
              <div className="flex flex-wrap gap-1.5 pt-1">
                <StatusChip kind="tool" status={tool.status} />
                <Chip>{toolKindLabel(tool.kind)}</Chip>
                <SeverityChip level={tool.risk} prefix="Risk" />
                {tool.sensitive && <Chip tone="orange">Sensitive</Chip>}
                {tool.external && <Chip tone="info">External</Chip>}
              </div>
            </SheetHeader>
            <SheetBody className="space-y-5">
              <div className="flex flex-wrap gap-2">
                {tool.status === "disabled" ? (
                  <GatedButton need="write" size="sm" variant="outline" disabled={update.isPending} onClick={() => update.mutate({ id: tool.id, body: { status: "active" } }, { onSuccess: () => toast.success("Tool enabled."), onError: (e) => toast.error(errorMessage(e)) })}>
                    <PlayIcon />
                    Enable
                  </GatedButton>
                ) : tool.status === "active" ? (
                  <GatedButton need="write" size="sm" variant="outline" disabled={update.isPending} onClick={() => update.mutate({ id: tool.id, body: { status: "disabled" } }, { onSuccess: () => toast.success("Tool disabled. Every call is denied."), onError: (e) => toast.error(errorMessage(e)) })}>
                    <BanIcon />
                    Disable
                  </GatedButton>
                ) : null}
                {!tool.mcp_server_id && (
                  <GatedButton need="write" size="sm" variant="destructive-soft" onClick={() => setConfirm(true)}>
                    <Trash2Icon />
                    Delete
                  </GatedButton>
                )}
              </div>
              <KeyValues
                columns={2}
                items={[
                  { label: "Actions", value: tool.actions.length ? tool.actions.join(", ") : "call" },
                  { label: "Resource template", value: tool.resource_template ? <Mono>{tool.resource_template}</Mono> : "None" },
                  { label: "Calls, 24 hours", value: `${tool.calls_24h ?? 0} (${tool.denied_24h ?? 0} denied)` },
                  { label: "Granted to", value: (tool.granted_roles ?? []).length ? (tool.granted_roles ?? []).join(", ") : "No role yet" },
                  { label: "Registered", value: formatDateTime(tool.created_at) },
                  { label: "Updated", value: formatDateTime(tool.updated_at) },
                ]}
              />
              {can("write") && tool.status !== "pending_review" && <GrantForm tool={tool} />}
              <section>
                <h3 className="mb-2 text-[13px] font-semibold">Input schema</h3>
                <JsonView value={tool.input_schema} label="Input schema" maxHeight={280} />
              </section>
              <section>
                <h3 className="mb-2 text-[13px] font-semibold">Constraints</h3>
                {Object.keys(tool.constraints).length ? <JsonView value={tool.constraints} label="Constraints" maxHeight={200} /> : <p className="text-[12.5px] text-muted-foreground">None. The schema alone validates parameters.</p>}
              </section>
              <section>
                <h3 className="mb-2 text-[13px] font-semibold">Configuration</h3>
                <p className="mb-2 text-[12px] text-muted-foreground">Secret references only ({"{secret:name}"}); values are injected at execution time.</p>
                <JsonView value={tool.config} label="Configuration" maxHeight={200} />
              </section>
            </SheetBody>
            <ConfirmDialog
              open={confirm}
              onOpenChange={setConfirm}
              title={`Delete ${tool.name}?`}
              description="Agents can no longer call it, and policies naming it stop matching. Past decisions keep the tool name."
              confirmLabel="Delete tool"
              pending={del.isPending}
              onConfirm={() =>
                del.mutate(tool.id, {
                  onSuccess: () => {
                    toast.success("Tool deleted.");
                    setConfirm(false);
                    onClose();
                  },
                  onError: (e) => toast.error(errorMessage(e)),
                })
              }
            />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
