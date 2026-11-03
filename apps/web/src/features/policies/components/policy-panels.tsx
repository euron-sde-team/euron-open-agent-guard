"use client";

import { FlaskConicalIcon, HistoryIcon, PlayIcon, RotateCcwIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { DecisionChip, SeverityChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { JsonView } from "@/components/json-view";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { RiskFactors } from "@/features/agents/components/decision-sheet";
import { useAgents } from "@/features/agents/api";
import { useUsers } from "@/features/org/api";
import { useTools } from "@/features/tools/api";
import { errorMessage } from "@/lib/api/errors";
import type { PolicyDetail } from "@/lib/api/types";
import { formatDateTime, formatNumber } from "@/lib/format";
import { exampleParams, parseJsonObject } from "@/lib/forms";
import { decisionSpec, reasonLabel } from "@/lib/labels";
import { arr, num, obj, str } from "@/lib/read";

import { useEvaluatePolicy, usePolicyAction, useSimulatePolicy } from "../api";

/** Run one hypothetical request through every active policy plus this draft. */
export function TestPanel({ source, defaults }: { source: string; defaults?: { tool?: string; action?: string } }) {
  const agents = useAgents();
  const tools = useTools();
  const evaluate = useEvaluatePolicy();
  const [agent, setAgent] = React.useState("");
  const [tool, setTool] = React.useState("");
  const [action, setAction] = React.useState("call");
  const [resource, setResource] = React.useState("");
  const [params, setParams] = React.useState('{\n  "amount": 750\n}');
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!agent && agents.data?.[0]) setAgent(agents.data[0].slug);
  }, [agent, agents.data]);
  const seeded = React.useRef(false);
  React.useEffect(() => {
    if (seeded.current || !defaults?.tool) return;
    seeded.current = true;
    setTool(defaults.tool);
    if (defaults.action) setAction(defaults.action);
  }, [defaults?.tool, defaults?.action]);
  const toolDef = tools.data?.find((t) => t.name === tool);
  const toolActions = toolDef?.actions ?? [];
  // Prefill parameters from the tool's schema when the tool changes, so the first run passes validation.
  const filledFor = React.useRef<string | null>(null);
  React.useEffect(() => {
    if (!toolDef || filledFor.current === toolDef.name) return;
    filledFor.current = toolDef.name;
    setParams(JSON.stringify(exampleParams(toolDef.input_schema), null, 2));
    if (toolDef.actions.length && !toolDef.actions.includes(action)) setAction(toolDef.actions[0] ?? "call");
  }, [toolDef, action]);
  const r = evaluate.data;
  return (
    <Surface>
      <SurfaceHeader title="Test" description="One request, decided by the active policies plus this draft. Nothing is recorded or run." />
      <form
        className="space-y-3 px-5 pb-5"
        onSubmit={(e) => {
          e.preventDefault();
          const p = parseJsonObject(params);
          if ("error" in p) return setError(p.error);
          if (!agent || !tool.trim()) return setError("Pick an agent and a tool.");
          setError(null);
          evaluate.mutate(
            { agent, draft: source, request: { tool: tool.trim(), action: action.trim() || "call", resource: resource.trim() || null, parameters: p.value } },
            { onError: (err) => setError(errorMessage(err)) },
          );
        }}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Agent" htmlFor="t-agent">
            <SimpleSelect id="t-agent" value={agent} onValueChange={setAgent} placeholder="Pick an agent" options={(agents.data ?? []).map((a) => ({ value: a.slug, label: a.slug }))} />
          </Field>
          <Field label="Tool" htmlFor="t-tool">
            <Input id="t-tool" list="t-tools" className="font-mono text-[12.5px]" value={tool} placeholder="payments.refund" onChange={(e) => setTool(e.target.value)} />
            <datalist id="t-tools">
              {(tools.data ?? []).map((t) => (
                <option key={t.id} value={t.name} />
              ))}
            </datalist>
          </Field>
          <Field label="Action" htmlFor="t-action">
            <Input id="t-action" list="t-actions" className="font-mono text-[12.5px]" value={action} onChange={(e) => setAction(e.target.value)} />
            <datalist id="t-actions">
              {toolActions.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
          </Field>
          <Field label="Resource" htmlFor="t-res">
            <Input id="t-res" className="font-mono text-[12.5px]" value={resource} placeholder="customer:2048" onChange={(e) => setResource(e.target.value)} />
          </Field>
        </div>
        <Field label="Parameters (JSON)" htmlFor="t-params">
          <Textarea id="t-params" className="min-h-24 font-mono text-[12px]" value={params} onChange={(e) => setParams(e.target.value)} />
        </Field>
        {error && <FieldError>{error}</FieldError>}
        <Button type="submit" variant="outline" disabled={evaluate.isPending}>
          <PlayIcon />
          {evaluate.isPending ? "Deciding..." : "Run test"}
        </Button>
        {r && (
          <div className="space-y-3 rounded-xl bg-muted/60 p-3" aria-live="polite">
            <div className="flex flex-wrap items-center gap-2">
              <DecisionChip decision={r.decision} />
              <SeverityChip level={str(obj(r.risk).level) ?? "low"} prefix={`Risk ${num(obj(r.risk).score) ?? 0}`} />
            </div>
            <p className="text-[13px]">{r.reason || reasonLabel(r.reason_code)}</p>
            {r.matched.length > 0 && (
              <ul className="space-y-1">
                {r.matched.map((m, i) => {
                  const o = obj(m);
                  const draft = str(o.policy_id) === "draft";
                  return (
                    <li key={i} className="flex flex-wrap items-center gap-1.5 text-[12px]">
                      <DecisionChip decision={str(o.decision) ?? ""} tip={false} />
                      <span className="font-medium">{str(o.policy)}</span>
                      {draft && <Chip tone="primary">this draft</Chip>}
                      <span className="text-subtle">rule {num(o.rule)}</span>
                    </li>
                  );
                })}
              </ul>
            )}
            {Object.keys(r.obligations).length > 0 && <JsonView value={r.obligations} label="Obligations" maxHeight={160} />}
            {arr(obj(r.risk).factors).length > 0 && (
              <details>
                <summary className="cursor-pointer text-[12px] font-medium text-muted-foreground">Risk factors</summary>
                <div className="mt-2">
                  <RiskFactors factors={arr(obj(r.risk).factors)} />
                </div>
              </details>
            )}
          </div>
        )}
      </form>
    </Surface>
  );
}

/** Replay recorded decisions against the draft and list what changes. */
export function SimulatePanel({ source, policyId }: { source: string; policyId?: string }) {
  const simulate = useSimulatePolicy();
  const [days, setDays] = React.useState("7");
  const r = simulate.data;
  const summary = Object.entries(r?.summary ?? {}).map(([k, v]) => {
    const [before, after] = k.split("->");
    return { before: before ?? "", after: after ?? "", count: v.count ?? 0 };
  });
  return (
    <Surface>
      <SurfaceHeader title="Simulate" titleExtra={<Hint term="simulation" />} description="What would have changed if this draft had been active." />
      <div className="space-y-3 px-5 pb-5">
        <div className="flex gap-2">
          <SimpleSelect
            aria-label="History window"
            className="w-36"
            value={days}
            onValueChange={setDays}
            options={[
              { value: "1", label: "Last day" },
              { value: "7", label: "Last 7 days" },
              { value: "30", label: "Last 30 days" },
            ]}
          />
          <Button
            variant="outline"
            disabled={simulate.isPending}
            onClick={() => simulate.mutate({ source, policy_id: policyId ?? null, days: Number(days) }, { onError: (e) => toast.error(errorMessage(e)) })}
          >
            <FlaskConicalIcon />
            {simulate.isPending ? "Simulating..." : "Simulate"}
          </Button>
        </div>
        {r && (
          <div className="space-y-3" aria-live="polite">
            <p className="text-[13px]">
              <span className="font-semibold">{formatNumber(summary.reduce((s, x) => s + x.count, 0))}</span> of {formatNumber(r.evaluated)} recorded decisions would change.
            </p>
            {summary.length > 0 && (
              <ul className="space-y-1.5">
                {summary.map((s) => (
                  <li key={`${s.before}-${s.after}`} className="flex items-center gap-2 text-[12.5px]">
                    <DecisionChip decision={s.before} tip={false} />
                    <span className="text-subtle" aria-label="to">
                      &rarr;
                    </span>
                    <DecisionChip decision={s.after} tip={false} />
                    <span className="tabular ml-auto font-semibold">{formatNumber(s.count)}</span>
                  </li>
                ))}
              </ul>
            )}
            {r.changed.length > 0 && (
              <details>
                <summary className="cursor-pointer text-[12px] font-medium text-muted-foreground">The changed decisions ({r.changed.length})</summary>
                <ul className="mt-2 max-h-72 space-y-1 overflow-y-auto">
                  {r.changed.map((c, i) => {
                    const o = obj(c);
                    return (
                      <li key={i} className="rounded-md bg-muted/60 px-2.5 py-1.5 text-[12px]">
                        <div className="font-mono">
                          {str(o.agent) ?? "?"} &rarr; {str(o.tool)}.{str(o.action)}
                        </div>
                        <div className="text-muted-foreground">
                          {decisionSpec(str(o.before)).label} to {decisionSpec(str(o.after)).label} · {formatDateTime(str(o.at))}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </details>
            )}
          </div>
        )}
      </div>
    </Surface>
  );
}

/** Versions with activate (any version) and rollback (to the previous one). */
export function VersionsPanel({ policy, onLoad }: { policy: PolicyDetail; onLoad: (source: string, version: number) => void }) {
  const act = usePolicyAction();
  const users = useUsers();
  const who = (id: string | null) => (id ? (users.data?.find((u) => u.id === id)?.name ?? "a person") : "AgentGuard");
  const [confirm, setConfirm] = React.useState<{ kind: "activate" | "rollback"; version?: number } | null>(null);
  const versions = [...policy.versions].sort((a, b) => b.version - a.version);
  return (
    <Surface>
      <SurfaceHeader
        title="Versions"
        description="Activating and rolling back are audited. Every decision records the version that decided it."
        action={
          policy.active_version && policy.active_version > 1 ? (
            <GatedButton need="write" size="xs" variant="ghost" onClick={() => setConfirm({ kind: "rollback" })}>
              <RotateCcwIcon />
              Roll back
            </GatedButton>
          ) : undefined
        }
      />
      <ul className="space-y-1 px-3 pb-4">
        {versions.map((v) => {
          const active = v.version === policy.active_version;
          return (
            <li key={v.version} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted/50">
              <HistoryIcon className="size-4 shrink-0 text-subtle" aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-[13px] font-medium">
                  v{v.version}
                  {active && <Chip tone="success">Active</Chip>}
                </div>
                <div className="truncate text-[11.5px] text-subtle">
                  {v.comment || "No comment"} · {who(v.created_by)} · {formatDateTime(v.created_at)}
                </div>
              </div>
              <Button size="xs" variant="ghost" onClick={() => onLoad(v.source, v.version)}>
                View
              </Button>
              {!active && (
                <GatedButton need="write" size="xs" variant="outline" onClick={() => setConfirm({ kind: "activate", version: v.version })}>
                  Activate
                </GatedButton>
              )}
            </li>
          );
        })}
      </ul>
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm?.kind === "rollback" ? "Roll back to the previous version?" : `Activate v${confirm?.version}?`}
        description="The next decision uses it. Simulate first if you are not sure what changes."
        confirmLabel={confirm?.kind === "rollback" ? "Roll back" : "Activate"}
        destructive={false}
        pending={act.isPending}
        onConfirm={() =>
          confirm &&
          act.mutate(
            { id: policy.id, action: confirm.kind, version: confirm.version },
            {
              onSuccess: () => {
                toast.success(confirm.kind === "rollback" ? "Rolled back." : `v${confirm.version} is active.`);
                setConfirm(null);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </Surface>
  );
}
