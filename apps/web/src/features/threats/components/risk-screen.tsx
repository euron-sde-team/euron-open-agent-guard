"use client";

import { ChevronDownIcon, GaugeIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { DecisionChip, SeverityChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { RiskFactors } from "@/features/agents/components/decision-sheet";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { RiskRule } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { conditionIssue, CONDITION_EXAMPLES } from "@/lib/conditions";
import { formatRelative, plural } from "@/lib/format";
import { SEVERITIES, severitySpec } from "@/lib/labels";

import { useDeleteRiskRule, useRiskAssessments, useRiskRules, useSaveRiskRule } from "../api";

function Assessments() {
  const [level, setLevel] = React.useState("");
  const [days, setDays] = React.useState("7");
  const q = useRiskAssessments({ level, hours: Number(days) * 24 });
  const [open, setOpen] = React.useState<string | null>(null);
  const [shown, setShown] = React.useState(12);
  const now = useNow(60_000);
  React.useEffect(() => setShown(12), [level, days]);
  return (
    <Surface>
      <SurfaceHeader
        title="Highest-risk actions"
        titleExtra={<Hint term="riskScore" />}
        description="Scored actions, riskiest first, with the factors behind each score."
        action={
          <div className="flex gap-2">
            <SimpleSelect
              size="sm"
              aria-label="Level"
              className="w-36"
              value={level}
              onValueChange={setLevel}
              options={[{ value: "", label: "Every level" }, ...[...SEVERITIES].reverse().map((s) => ({ value: s, label: severitySpec(s).label }))]}
            />
            <SimpleSelect
              size="sm"
              aria-label="Period"
              className="w-32"
              value={days}
              onValueChange={setDays}
              options={[
                { value: "1", label: "24 hours" },
                { value: "7", label: "7 days" },
                { value: "30", label: "30 days" },
              ]}
            />
          </div>
        }
      />
      <QueryState
        query={q}
        errorTitle="Could not load risk assessments"
        empty={(d) => d.length === 0}
        emptyState={<EmptyState compact icon={GaugeIcon} title="No scored actions in this period" description="Every decision gets a risk score from your rules. Widen the period or the level to see more." />}
      >
        {(all) => {
          const items = all.slice(0, shown);
          return (
          <>
          <ul className="divide-y divide-hairline">
            {items.map((a) => {
              const isOpen = open === a.decision_id;
              return (
                <li key={a.decision_id}>
                  <button
                    type="button"
                    aria-expanded={isOpen}
                    onClick={() => setOpen(isOpen ? null : a.decision_id)}
                    className="flex w-full flex-col gap-2 px-5 py-3 text-left hover:bg-muted/50 focus-visible:bg-muted focus-visible:outline-none sm:flex-row sm:items-center sm:gap-4"
                  >
                    <div className="flex items-center gap-2">
                      <span className="tabular w-9 text-right text-[18px] font-semibold">{a.risk_score}</span>
                      <SeverityChip level={a.risk_level} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-[13px]">
                        {a.agent ?? "unknown"} &rarr; {a.tool}.{a.action}
                      </div>
                      <div className="text-[12px] text-muted-foreground">
                        {plural(a.factors.length, "factor")}{a.resource ? ` · ${a.resource}` : ""} · {formatRelative(a.at, now)}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <DecisionChip decision={a.decision} tip={false} />
                      <ChevronDownIcon className={cn("size-4 text-subtle transition-transform", isOpen && "rotate-180")} aria-hidden />
                    </div>
                  </button>
                  {isOpen && (
                    <div className="px-5 pb-4 sm:pl-[118px]">
                      <RiskFactors factors={a.factors} />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
          {all.length > shown && (
            <div className="flex justify-center py-3">
              <Button variant="ghost" size="sm" onClick={() => setShown(shown + 12)}>
                Show more ({all.length - shown} left)
              </Button>
            </div>
          )}
          </>
          );
        }}
      </QueryState>
    </Surface>
  );
}

function RuleDialog({ rule, open, onOpenChange }: { rule: RiskRule | null; open: boolean; onOpenChange: (o: boolean) => void }) {
  const save = useSaveRiskRule();
  const [name, setName] = React.useState("");
  const [condition, setCondition] = React.useState("");
  const [points, setPoints] = React.useState("10");
  const [enabled, setEnabled] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open) return;
    setName(rule?.name ?? "");
    setCondition(rule?.condition ?? "");
    setPoints(String(rule?.points ?? 10));
    setEnabled(rule?.enabled ?? true);
    setError(null);
  }, [open, rule]);
  const issue = conditionIssue(condition);
  return (
    <Dialog open={open} onOpenChange={(o) => !save.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const p = Number(points);
            if (!name.trim() || !condition.trim()) return setError("Give the rule a name and a condition.");
            if (!Number.isInteger(p) || p < -100 || p > 100) return setError("Points are a whole number between -100 and 100.");
            if (issue) return setError(issue);
            save.mutate(
              { id: rule?.id, body: { name: name.trim(), condition: condition.trim(), points: p, enabled } },
              {
                onSuccess: () => {
                  toast.success(rule ? "Risk rule saved." : "Risk rule added. New decisions are scored with it.");
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>{rule ? "Edit risk rule" : "Add a risk rule"}</DialogTitle>
            <DialogDescription>When the condition is true, the points are added to the action&apos;s score. 0 to 24 is low, then medium, high and critical.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="Name" htmlFor="rr-name">
              <Input id="rr-name" value={name} placeholder="Large refunds" onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Condition" htmlFor="rr-cond" hint={issue ?? "The policy expression language: paths like params.amount, resource.sensitivity, agent.labels.team."}>
              <Textarea id="rr-cond" className="font-mono text-[12.5px]" value={condition} placeholder='tool.external and context.data_classes contains "pii"' onChange={(e) => setCondition(e.target.value)} />
            </Field>
            <div className="flex flex-wrap gap-1">
              {CONDITION_EXAMPLES.slice(0, 4).map((ex) => (
                <button key={ex} type="button" onClick={() => setCondition(ex)} className="rounded-md bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
                  {ex}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Points" htmlFor="rr-points">
                <Input id="rr-points" inputMode="numeric" value={points} onChange={(e) => setPoints(e.target.value)} />
              </Field>
              <label className="flex items-center gap-2 self-end pb-2 text-[13px]">
                <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Enabled" />
                Enabled
              </label>
            </div>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving..." : "Save rule"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RiskRules() {
  const q = useRiskRules();
  const del = useDeleteRiskRule();
  const [edit, setEdit] = React.useState<{ rule: RiskRule | null } | null>(null);
  const [remove, setRemove] = React.useState<RiskRule | null>(null);
  return (
    <Surface>
      <SurfaceHeader
        title="Organisation risk rules"
        description="Added to the built-in factors (operation, sensitivity, data classes, environment, history)."
        action={
          <GatedButton need="write" size="sm" onClick={() => setEdit({ rule: null })}>
            <PlusIcon />
            Add rule
          </GatedButton>
        }
      />
      <QueryState
        query={q}
        errorTitle="Could not load risk rules"
        empty={(d) => d.length === 0}
        emptyState={
          <EmptyState
            compact
            icon={GaugeIcon}
            title="No custom risk rules"
            description="Built-in factors already score every action. Add a rule for what is risky in your business, like refunds over a threshold."
            action={
              <GatedButton need="write" size="sm" variant="outline" onClick={() => setEdit({ rule: null })}>
                Add your first rule
              </GatedButton>
            }
          />
        }
      >
        {(rules) => (
          <ul className="divide-y divide-hairline">
            {rules.map((r) => (
              <li key={r.id} className={cn("flex items-start gap-3 px-5 py-3", !r.enabled && "opacity-60")}>
                <span className={cn("tabular mt-0.5 w-12 shrink-0 rounded-md px-1.5 py-0.5 text-center text-[12px] font-semibold", r.points >= 0 ? "bg-warning-soft text-warning" : "bg-primary-soft text-primary")}>
                  {r.points >= 0 ? `+${r.points}` : r.points}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">
                    {r.name}
                    {!r.enabled && <span className="ml-2 text-[11.5px] font-normal text-subtle">disabled</span>}
                  </div>
                  <code className="block font-mono text-[12px] break-words text-muted-foreground">{r.condition}</code>
                </div>
                <div className="flex shrink-0 gap-1">
                  <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Edit ${r.name}`} onClick={() => setEdit({ rule: r })}>
                    <PencilIcon />
                  </GatedButton>
                  <GatedButton need="write" size="icon-xs" variant="ghost" aria-label={`Delete ${r.name}`} onClick={() => setRemove(r)}>
                    <Trash2Icon />
                  </GatedButton>
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
      <div className="h-2" />
      <RuleDialog open={!!edit} rule={edit?.rule ?? null} onOpenChange={(o) => !o && setEdit(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Delete "${remove?.name}"?`}
        description="New decisions are no longer scored with it. Past scores stay as they were."
        confirmLabel="Delete rule"
        pending={del.isPending}
        onConfirm={() =>
          remove &&
          del.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Risk rule deleted.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </Surface>
  );
}

export function RiskScreen() {
  return (
    <>
      <PageHeader title="Risk center" description="Every action gets a level (low, medium, high, critical) from configurable rules. Policies condition on it, for example: risk.level >= &quot;high&quot; requires approval." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Assessments />
        <RiskRules />
      </div>
    </>
  );
}
