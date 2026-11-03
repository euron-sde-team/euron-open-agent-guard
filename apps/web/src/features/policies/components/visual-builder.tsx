"use client";

import { ArrowDownIcon, ArrowUpIcon, PlusIcon, Trash2Icon } from "lucide-react";
import * as React from "react";

import { Hint } from "@/components/hint";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field, FieldHint } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/cn";
import { conditionIssue, CONDITION_EXAMPLES } from "@/lib/conditions";
import { formatLabels, parseLabels } from "@/lib/forms";
import { DECISIONS, decisionSpec, type DecisionCode } from "@/lib/labels";
import { emptyRule, withDecision, APPROVER_ROLES, type PolicyApproval, type PolicyModel, type PolicyObligations, type PolicyRule } from "@/lib/policy-model";
import { roleLabel } from "@/lib/roles";

import { ListInput } from "./list-input";

const DECISION_BAR: Record<DecisionCode, string> = {
  allow: "bg-savings",
  restrict: "bg-info",
  require_approval: "bg-warning",
  deny: "bg-danger",
  quarantine: "bg-violet",
};

function ConditionInput({ value, onChange, id, disabled }: { value: string; onChange: (v: string) => void; id: string; disabled?: boolean }) {
  const issue = conditionIssue(value);
  const listId = `${id}-examples`;
  return (
    <div className="space-y-1">
      <Input
        id={id}
        list={listId}
        disabled={disabled}
        className={cn("font-mono text-[12.5px]", issue && "ring-danger/60")}
        placeholder='params.amount > 500 and risk.level >= "high"'
        value={value}
        aria-invalid={!!issue || undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      <datalist id={listId}>
        {CONDITION_EXAMPLES.map((e) => (
          <option key={e} value={e} />
        ))}
      </datalist>
      {issue ? <p className="text-[11.5px] text-danger">{issue}</p> : null}
    </div>
  );
}

function NumberField({ value, onChange, id, placeholder, disabled }: { value: number | null; onChange: (v: number | null) => void; id: string; placeholder?: string; disabled?: boolean }) {
  const [text, setText] = React.useState(value == null ? "" : String(value));
  const focused = React.useRef(false);
  React.useEffect(() => {
    if (!focused.current) setText(value == null ? "" : String(value));
  }, [value]);
  return (
    <Input
      id={id}
      inputMode="decimal"
      onFocus={() => (focused.current = true)}
      onBlur={() => (focused.current = false)}
      disabled={disabled}
      placeholder={placeholder}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        const t = e.target.value.trim();
        if (!t) return onChange(null);
        const n = Number(t);
        if (Number.isFinite(n)) onChange(n);
      }}
    />
  );
}

function ObligationsEditor({ value, onChange, idp, disabled }: { value: PolicyObligations; onChange: (v: PolicyObligations) => void; idp: string; disabled?: boolean }) {
  const set = <K extends keyof PolicyObligations>(k: K, v: PolicyObligations[K]) => onChange({ ...value, [k]: v });
  const toggles: { key: "redact_output" | "wrap_untrusted" | "no_network"; label: string }[] = [
    { key: "redact_output", label: "Redact personal data and credentials in the output" },
    { key: "wrap_untrusted", label: "Wrap the output as untrusted data" },
    { key: "no_network", label: "No network (sandbox runs)" },
  ];
  return (
    <div className="space-y-3 rounded-xl bg-info-soft/50 p-3">
      <div className="flex items-center gap-1 text-[12px] font-semibold text-info">
        Obligations <Hint term="obligations" />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Max rows" htmlFor={`${idp}-rows`}>
          <NumberField id={`${idp}-rows`} disabled={disabled} value={value.max_rows} onChange={(v) => set("max_rows", v)} placeholder="100" />
        </Field>
        <Field label="Redact fields" htmlFor={`${idp}-redact`}>
          <ListInput id={`${idp}-redact`} disabled={disabled} value={value.redact_fields} onChange={(v) => set("redact_fields", v)} placeholder="email, phone" />
        </Field>
        <Field label="Only these parameters" htmlFor={`${idp}-allow`}>
          <ListInput id={`${idp}-allow`} disabled={disabled} value={value.allow_params} onChange={(v) => set("allow_params", v)} placeholder="Leave empty to keep all" />
        </Field>
        <Field label="Timeout (seconds)" htmlFor={`${idp}-timeout`}>
          <NumberField id={`${idp}-timeout`} disabled={disabled} value={value.timeout_s} onChange={(v) => set("timeout_s", v)} placeholder="30" />
        </Field>
      </div>
      <div className="flex flex-col gap-2">
        {toggles.map((t) => (
          <label key={t.key} className="flex items-center gap-2 text-[12.5px]">
            <Switch checked={value[t.key]} disabled={disabled} onCheckedChange={(c) => set(t.key, c)} aria-label={t.label} />
            {t.label}
          </label>
        ))}
      </div>
    </div>
  );
}

function ApprovalEditor({ value, onChange, idp, disabled }: { value: PolicyApproval; onChange: (v: PolicyApproval) => void; idp: string; disabled?: boolean }) {
  const setStage = (i: number, patch: Partial<PolicyApproval["stages"][number]>) =>
    onChange({ ...value, stages: value.stages.map((s, n) => (n === i ? { ...s, ...patch } : s)) });
  return (
    <div className="space-y-3 rounded-xl bg-warning-soft/50 p-3">
      <div className="text-[12px] font-semibold text-warning">Approval</div>
      <ol className="space-y-2">
        {value.stages.map((s, i) => (
          <li key={i} className="rounded-lg bg-card/70 p-2.5 dark:bg-card/40">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="text-[12px] font-medium">Stage {i + 1}</span>
              {value.stages.length > 1 && (
                <Button type="button" size="icon-xs" variant="ghost" disabled={disabled} aria-label={`Remove stage ${i + 1}`} onClick={() => onChange({ ...value, stages: value.stages.filter((_, n) => n !== i) })}>
                  <Trash2Icon />
                </Button>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <fieldset className="flex flex-wrap gap-x-3 gap-y-1">
                <legend className="sr-only">Roles that may approve</legend>
                {APPROVER_ROLES.map((r) => (
                  <label key={r} className="flex items-center gap-1.5 text-[12.5px]">
                    <input
                      type="checkbox"
                      disabled={disabled}
                      className="size-3.5 accent-[var(--primary)]"
                      checked={s.roles.includes(r)}
                      onChange={(e) => setStage(i, { roles: e.target.checked ? [...s.roles, r] : s.roles.filter((x) => x !== r) })}
                    />
                    {roleLabel(r)}
                  </label>
                ))}
              </fieldset>
              <label className="flex items-center gap-1.5 text-[12.5px]">
                Approvals needed
                <Input
                  type="number"
                  min={1}
                  max={10}
                  disabled={disabled}
                  className="h-7 w-16"
                  value={s.count}
                  onChange={(e) => setStage(i, { count: Math.max(1, Math.min(10, Number(e.target.value) || 1)) })}
                />
              </label>
            </div>
            <div className="mt-2">
              <ListInput aria-label={`Named reviewers for stage ${i + 1}`} disabled={disabled} value={s.users} onChange={(v) => setStage(i, { users: v })} placeholder="Or named people: priya@corp.example" />
            </div>
          </li>
        ))}
      </ol>
      <Button type="button" size="xs" variant="ghost" disabled={disabled || value.stages.length >= 5} onClick={() => onChange({ ...value, stages: [...value.stages, { roles: ["security_officer"], users: [], count: 1 }] })}>
        <PlusIcon />
        Add a stage
      </Button>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Expires after" htmlFor={`${idp}-exp`} hint="30m, 4h, 2d">
          <Input id={`${idp}-exp`} disabled={disabled} value={value.expires_in} onChange={(e) => onChange({ ...value, expires_in: e.target.value })} />
        </Field>
        <Field label="Once approved, runs by" htmlFor={`${idp}-exec`}>
          <SimpleSelect
            id={`${idp}-exec`}
            disabled={disabled}
            value={value.execute}
            onValueChange={(v) => onChange({ ...value, execute: v as PolicyApproval["execute"] })}
            options={[
              { value: "auto", label: "Automatic (by tool kind)" },
              { value: "agentguard", label: "AgentGuard (trusted path)" },
              { value: "agent", label: "The agent, with the approval" },
            ]}
          />
        </Field>
      </div>
      <label className="flex items-center gap-2 text-[12.5px]">
        <Switch checked={value.forbid_requester} disabled={disabled} onCheckedChange={(c) => onChange({ ...value, forbid_requester: c })} aria-label="Forbid self approval" />
        The person the run acts for may not approve it
      </label>
    </div>
  );
}

function RuleCard({
  rule,
  index,
  count,
  onChange,
  onMove,
  onRemove,
  disabled,
}: {
  rule: PolicyRule;
  index: number;
  count: number;
  onChange: (r: PolicyRule) => void;
  onMove: (dir: -1 | 1) => void;
  onRemove: () => void;
  disabled?: boolean;
}) {
  const idp = `rule-${index}`;
  return (
    <li className="relative overflow-hidden rounded-xl bg-muted/50 p-4 pl-5">
      <span className={cn("absolute inset-y-0 left-0 w-1", DECISION_BAR[rule.decision])} aria-hidden />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="text-[12px] font-semibold text-subtle">Rule {index + 1}</span>
        <SimpleSelect
          size="sm"
          aria-label={`Decision of rule ${index + 1}`}
          className="w-48"
          disabled={disabled}
          value={rule.decision}
          onValueChange={(v) => onChange(withDecision(rule, v as DecisionCode))}
          options={DECISIONS.map((d) => ({ value: d, label: decisionSpec(d).label }))}
        />
        <div className="ml-auto flex gap-0.5">
          <Button type="button" size="icon-xs" variant="ghost" disabled={disabled || index === 0} aria-label="Move rule up" onClick={() => onMove(-1)}>
            <ArrowUpIcon />
          </Button>
          <Button type="button" size="icon-xs" variant="ghost" disabled={disabled || index === count - 1} aria-label="Move rule down" onClick={() => onMove(1)}>
            <ArrowDownIcon />
          </Button>
          <Button type="button" size="icon-xs" variant="ghost" disabled={disabled || count === 1} aria-label={`Delete rule ${index + 1}`} onClick={onRemove}>
            <Trash2Icon />
          </Button>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label="Actions" htmlFor={`${idp}-actions`} hint="Empty means every action.">
          <ListInput id={`${idp}-actions`} disabled={disabled} value={rule.actions} onChange={(v) => onChange({ ...rule, actions: v })} placeholder="read, write" />
        </Field>
        <Field label="Tools" htmlFor={`${idp}-tools`} hint="Patterns: crm.*">
          <ListInput id={`${idp}-tools`} disabled={disabled} value={rule.tools} onChange={(v) => onChange({ ...rule, tools: v })} placeholder="Every tool" />
        </Field>
        <Field label="Resources" htmlFor={`${idp}-res`} hint="Patterns: database:*">
          <ListInput id={`${idp}-res`} disabled={disabled} value={rule.resources} onChange={(v) => onChange({ ...rule, resources: v })} placeholder="Every resource" />
        </Field>
        <Field label="When" htmlFor={`${idp}-when`} className="md:col-span-2">
          <ConditionInput id={`${idp}-when`} disabled={disabled} value={rule.when} onChange={(v) => onChange({ ...rule, when: v })} />
        </Field>
        <Field label="Reason" htmlFor={`${idp}-reason`} hint="Returned to the agent and shown to reviewers.">
          <Input id={`${idp}-reason`} disabled={disabled} value={rule.reason} onChange={(e) => onChange({ ...rule, reason: e.target.value })} />
        </Field>
      </div>
      {rule.decision === "restrict" && rule.obligations && (
        <div className="mt-3">
          <ObligationsEditor idp={idp} disabled={disabled} value={rule.obligations} onChange={(o) => onChange({ ...rule, obligations: o })} />
        </div>
      )}
      {rule.decision === "require_approval" && rule.approval && (
        <div className="mt-3">
          <ApprovalEditor idp={idp} disabled={disabled} value={rule.approval} onChange={(a) => onChange({ ...rule, approval: a })} />
        </div>
      )}
    </li>
  );
}

function LabelsInput({ value, onChange, disabled }: { value: Record<string, string | number | boolean>; onChange: (v: Record<string, string | number | boolean>) => void; disabled?: boolean }) {
  const [text, setText] = React.useState(formatLabels(value));
  const focused = React.useRef(false);
  React.useEffect(() => {
    if (!focused.current) setText(formatLabels(value));
  }, [value]);
  return (
    <Input
      id="scope-labels"
      disabled={disabled}
      className="font-mono text-[12.5px]"
      placeholder="team=finance"
      value={text}
      onFocus={() => (focused.current = true)}
      onBlur={() => (focused.current = false)}
      onChange={(e) => {
        setText(e.target.value);
        onChange(parseLabels(e.target.value));
      }}
    />
  );
}

/** The visual mode: every field of the policy as a form. Changes go straight to YAML. */
export function VisualBuilder({ model, onChange, disabled, nameLocked }: { model: PolicyModel; onChange: (m: PolicyModel) => void; disabled?: boolean; nameLocked?: boolean }) {
  const setScope = (patch: Partial<PolicyModel["scope"]>) => onChange({ ...model, scope: { ...model.scope, ...patch } });
  const setRule = (i: number, r: PolicyRule) => onChange({ ...model, rules: model.rules.map((x, n) => (n === i ? r : x)) });
  const move = (i: number, dir: -1 | 1) => {
    const rules = [...model.rules];
    const j = i + dir;
    if (j < 0 || j >= rules.length) return;
    [rules[i], rules[j]] = [rules[j] as PolicyRule, rules[i] as PolicyRule];
    onChange({ ...model, rules });
  };
  return (
    <div className="space-y-4">
      <Surface>
        <SurfaceHeader title="Policy" description="Lower case letters, digits, dots and dashes in the name." />
        <div className="grid gap-4 px-5 pb-5 md:grid-cols-2">
          <Field label="Name" htmlFor="pol-name" hint={nameLocked ? "The name identifies the policy across versions." : undefined}>
            <Input id="pol-name" className="font-mono text-[13px]" disabled={disabled || nameLocked} value={model.name} onChange={(e) => onChange({ ...model, name: e.target.value })} />
          </Field>
          <Field label="Description" htmlFor="pol-desc">
            <Input id="pol-desc" disabled={disabled} value={model.description} onChange={(e) => onChange({ ...model, description: e.target.value })} />
          </Field>
        </div>
      </Surface>
      <Surface>
        <SurfaceHeader title="Applies to" description="Leave a field empty to match everything. The policy only decides actions inside its scope." />
        <div className="grid gap-4 px-5 pb-5 md:grid-cols-3">
          <Field label="Agents" htmlFor="scope-agents">
            <ListInput id="scope-agents" disabled={disabled} value={model.scope.agents} onChange={(v) => setScope({ agents: v })} placeholder="billing-agent" />
          </Field>
          <Field label="Projects" htmlFor="scope-projects">
            <ListInput id="scope-projects" disabled={disabled} value={model.scope.projects} onChange={(v) => setScope({ projects: v })} placeholder="finance" />
          </Field>
          <Field label="Agent roles" htmlFor="scope-roles">
            <ListInput id="scope-roles" disabled={disabled} value={model.scope.roles} onChange={(v) => setScope({ roles: v })} placeholder="support" />
          </Field>
          <Field label="Environments" htmlFor="scope-env">
            <ListInput id="scope-env" disabled={disabled} value={model.scope.environments} onChange={(v) => setScope({ environments: v })} placeholder="production" />
          </Field>
          <Field label="Frameworks" htmlFor="scope-fw">
            <ListInput id="scope-fw" disabled={disabled} value={model.scope.frameworks} onChange={(v) => setScope({ frameworks: v })} placeholder="langgraph" />
          </Field>
          <Field label="Labels" htmlFor="scope-labels">
            <LabelsInput disabled={disabled} value={model.scope.labels} onChange={(v) => setScope({ labels: v })} />
          </Field>
          <Field label="Tools" htmlFor="pol-tools">
            <ListInput id="pol-tools" disabled={disabled} value={model.tools} onChange={(v) => onChange({ ...model, tools: v })} placeholder="payments.*" />
          </Field>
          <Field label="Resources" htmlFor="pol-res">
            <ListInput id="pol-res" disabled={disabled} value={model.resources} onChange={(v) => onChange({ ...model, resources: v })} placeholder="database:production" />
          </Field>
          <Field label="Actions" htmlFor="pol-actions" hint="Rules may only use these.">
            <ListInput id="pol-actions" disabled={disabled} value={model.actions} onChange={(v) => onChange({ ...model, actions: v })} placeholder="read, write, delete" />
          </Field>
          <Field label="Only when" htmlFor="pol-when" className="md:col-span-3">
            <ConditionInput id="pol-when" disabled={disabled} value={model.when} onChange={(v) => onChange({ ...model, when: v })} />
          </Field>
        </div>
      </Surface>
      <Surface>
        <SurfaceHeader
          title="Rules"
          description="Every matching rule counts, and the most cautious wins: deny, quarantine, approval, restrict, then allow. Order is for reading."
          action={
            <Button type="button" size="sm" variant="outline" disabled={disabled || model.rules.length >= 200} onClick={() => onChange({ ...model, rules: [...model.rules, emptyRule()] })}>
              <PlusIcon />
              Add rule
            </Button>
          }
        />
        <ol className="space-y-3 px-5 pb-5">
          {model.rules.map((r, i) => (
            <RuleCard
              key={i}
              rule={r}
              index={i}
              count={model.rules.length}
              disabled={disabled}
              onChange={(nr) => setRule(i, nr)}
              onMove={(d) => move(i, d)}
              onRemove={() => onChange({ ...model, rules: model.rules.filter((_, n) => n !== i) })}
            />
          ))}
          {!model.rules.length && <FieldHint>A policy needs at least one rule.</FieldHint>}
        </ol>
      </Surface>
    </div>
  );
}
