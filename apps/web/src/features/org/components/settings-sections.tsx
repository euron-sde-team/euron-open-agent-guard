"use client";

import { OctagonXIcon, PlayIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { ReasonDialog } from "@/components/reason-dialog";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { usePermissions } from "@/features/auth/api";
import { ListInput } from "@/features/policies/components/list-input";
import { errorMessage } from "@/lib/api/errors";
import type { Detection, Enforcement, Notifications, OrgSettings, Retention, ThreatResponses } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatDateTime } from "@/lib/format";
import { SEVERITIES, severitySpec } from "@/lib/labels";

import { useKillSwitch, useUpdateSettings } from "../api";

/** A settings card whose form saves one part of the organisation settings. */
function Section({ id, title, description, children, onSave, dirty, pending, extra }: { id: string; title: React.ReactNode; description: React.ReactNode; children: React.ReactNode; onSave?: () => void; dirty?: boolean; pending?: boolean; extra?: React.ReactNode }) {
  const { can } = usePermissions();
  return (
    <Surface id={id} className="scroll-mt-20">
      <SurfaceHeader title={title} description={description} action={extra} />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSave?.();
        }}
      >
        <fieldset disabled={!can("admin") && !!onSave} className="min-w-0 px-5 pb-5">
          {children}
        </fieldset>
        {onSave && can("admin") && (
          <div className="flex items-center justify-end gap-3 bg-muted/40 px-5 py-3">
            {dirty && <span className="text-[12px] text-warning">Unsaved changes</span>}
            <Button type="submit" size="sm" disabled={!dirty || pending}>
              {pending ? "Saving..." : "Save"}
            </Button>
          </div>
        )}
      </form>
    </Surface>
  );
}

function useDraft<T>(value: T): [T, React.Dispatch<React.SetStateAction<T>>, boolean] {
  const [draft, setDraft] = React.useState<T>(value);
  React.useEffect(() => setDraft(value), [value]);
  return [draft, setDraft, JSON.stringify(draft) !== JSON.stringify(value)];
}

function NumberInput({ id, value, onChange, min = 0 }: { id: string; value: number; onChange: (n: number) => void; min?: number }) {
  return <Input id={id} type="number" min={min} value={Number.isFinite(value) ? value : 0} onChange={(e) => onChange(Number(e.target.value))} />;
}

export function EnforcementSection({ settings }: { settings: OrgSettings }) {
  const update = useUpdateSettings();
  const [e, setE, dirty] = useDraft<Enforcement>(settings.enforcement);
  const set = <K extends keyof Enforcement>(k: K, v: Enforcement[K]) => setE((x) => ({ ...x, [k]: v }));
  const enforce = (e.mode ?? "enforce") === "enforce";
  return (
    <Section
      id="enforcement"
      title={
        <span className="inline-flex items-center gap-1">
          Enforcement <Hint term="enforceMode" />
        </span>
      }
      description="How decisions apply to every agent of the organisation."
      dirty={dirty}
      pending={update.isPending}
      onSave={() => update.mutate({ enforcement: e }, { onSuccess: () => toast.success(enforce ? "Saved. Decisions are enforced." : "Saved. Audit mode: nothing is blocked, decisions are recorded."), onError: (err) => toast.error(errorMessage(err)) })}
    >
      <div className="space-y-4">
        <div className="grid gap-3 md:grid-cols-2">
          {(["enforce", "audit"] as const).map((m) => (
            <label key={m} className={cn("flex cursor-pointer gap-3 rounded-xl p-4 ring-1 ring-transparent transition-colors", e.mode === m ? (m === "enforce" ? "bg-primary-soft ring-primary/40" : "bg-warning-soft ring-warning/40") : "bg-muted/60 hover:bg-muted")}>
              <input type="radio" name="mode" className="mt-1 accent-[var(--primary)]" checked={(e.mode ?? "enforce") === m} onChange={() => set("mode", m)} />
              <span>
                <span className="block text-[13.5px] font-semibold">{m === "enforce" ? "Enforce" : "Audit"}</span>
                <span className="block text-[12.5px] text-muted-foreground">
                  {m === "enforce"
                    ? "Decisions are binding. A deny never reaches the tool, a held action waits for a person."
                    : "Every action runs. Each decision records what it would have been (would_be), so you can tune policies before enforcing them."}
                </span>
              </span>
            </label>
          ))}
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="When no policy matches" htmlFor="en-default">
            <SimpleSelect
              id="en-default"
              value={e.default_decision ?? "deny"}
              onValueChange={(v) => set("default_decision", v === "allow" ? "allow" : "deny")}
              options={[
                { value: "deny", label: "Deny (recommended)" },
                { value: "allow", label: "Allow" },
              ]}
            />
          </Field>
          <Field label="Loop threshold" htmlFor="en-loop" hint="Identical calls in a row before a loop is declared.">
            <NumberInput id="en-loop" value={e.loop_threshold ?? 6} onChange={(n) => set("loop_threshold", n)} min={2} />
          </Field>
          <Field label="Burst per minute" htmlFor="en-burst" hint="Calls per minute before tool abuse fires.">
            <NumberInput id="en-burst" value={e.burst_per_minute ?? 120} onChange={(n) => set("burst_per_minute", n)} min={1} />
          </Field>
          <Field label="Deny streak" htmlFor="en-streak" hint="Denials in a row that look like privilege probing.">
            <NumberInput id="en-streak" value={e.deny_streak ?? 8} onChange={(n) => set("deny_streak", n)} min={1} />
          </Field>
          <Field label="Run idle timeout (s)" htmlFor="en-idle">
            <NumberInput id="en-idle" value={e.run_idle_s ?? 600} onChange={(n) => set("run_idle_s", n)} min={30} />
          </Field>
        </div>
        <div className="flex flex-col gap-2">
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={e.require_registered_tools ?? true} onCheckedChange={(c) => set("require_registered_tools", c)} aria-label="Require registered tools" />
            Deny tools that are not registered
          </label>
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={e.always_issue_tokens ?? false} onCheckedChange={(c) => set("always_issue_tokens", c)} aria-label="Always issue decision tokens" />
            Issue a decision token with every allow
            <Hint term="decisionToken" />
          </label>
        </div>
      </div>
    </Section>
  );
}

export function KillSwitchSection({ settings }: { settings: OrgSettings }) {
  const ks = useKillSwitch();
  const [open, setOpen] = React.useState(false);
  const active = !!settings.kill_switch.active;
  return (
    <Surface id="kill-switch" className={cn("scroll-mt-20 overflow-hidden", active && "ring-2 ring-danger/50")}>
      <div className={cn("flex flex-col gap-4 p-5 sm:flex-row sm:items-center", active ? "bg-danger-soft" : "")}>
        <span className={cn("flex size-12 shrink-0 items-center justify-center rounded-2xl", active ? "bg-danger text-danger-foreground" : "bg-danger-soft text-danger")}>
          <OctagonXIcon className="size-6" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-1 text-[15px] font-semibold">
            Kill switch {active ? "is on" : "is off"} <Hint term="killSwitch" />
          </h2>
          <p className="text-[12.5px] text-muted-foreground">
            {active
              ? `Every agent action is denied. "${settings.kill_switch.reason || "no reason"}"${settings.kill_switch.by ? `, by ${settings.kill_switch.by}` : ""}${settings.kill_switch.at ? ` at ${formatDateTime(settings.kill_switch.at)}` : ""}.`
              : "For emergencies: one switch denies every action of every agent of this organisation within a second. Agents are not suspended; turning it off resumes them."}
          </p>
        </div>
        {active ? (
          <GatedButton need="write" onClick={() => setOpen(true)}>
            <PlayIcon />
            Turn off and resume
          </GatedButton>
        ) : (
          <GatedButton need="write" variant="destructive" onClick={() => setOpen(true)}>
            <OctagonXIcon />
            Stop every agent
          </GatedButton>
        )}
      </div>
      <ReasonDialog
        open={open}
        onOpenChange={setOpen}
        title={active ? "Turn the kill switch off?" : "Stop every agent now?"}
        description={active ? "Agents resume with their normal decisions immediately. Make sure what caused this is contained." : "Every action of every agent is denied within a second, including actions already approved. Running executions are not interrupted."}
        confirmLabel={active ? "Turn off" : "Stop every agent"}
        destructive={!active}
        pending={ks.isPending}
        onConfirm={(reason) =>
          ks.mutate(
            { active: !active, reason },
            {
              onSuccess: () => {
                toast.success(active ? "Kill switch off. Agents resume." : "Kill switch on. Every agent action is denied.");
                setOpen(false);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </Surface>
  );
}

export function DetectionSection({ settings }: { settings: OrgSettings }) {
  const update = useUpdateSettings();
  const [d, setD, dirty] = useDraft<Detection>(settings.detection);
  const [key, setKey] = React.useState("");
  const set = <K extends keyof Detection>(k: K, v: Detection[K]) => setD((x) => ({ ...x, [k]: v }));
  const ai = (d.ai_provider ?? "none") !== "none";
  return (
    <Section
      id="detection"
      title="Detection"
      description="The injection guard, run taint, behavioural baselines and the optional AI-assisted classifier (never the only defence)."
      dirty={dirty || !!key}
      pending={update.isPending}
      onSave={() =>
        update.mutate(
          { detection: d, ai_api_key: key ? key : undefined },
          {
            onSuccess: () => {
              setKey("");
              toast.success("Detection settings saved.");
            },
            onError: (err) => toast.error(errorMessage(err)),
          },
        )
      }
    >
      <div className="space-y-4">
        <div className="flex flex-col gap-2">
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={d.scan_tool_outputs ?? true} onCheckedChange={(c) => set("scan_tool_outputs", c)} aria-label="Scan tool outputs" />
            Scan tool outputs for injections, personal data and credentials
          </label>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Taint a run on" htmlFor="det-taint" labelExtra={<Hint term="taint" />}>
            <SimpleSelect
              id="det-taint"
              value={d.taint_on ?? "injection"}
              onValueChange={(v) => set("taint_on", v === "suspicious" ? "suspicious" : "injection")}
              options={[
                { value: "injection", label: "Injection verdicts" },
                { value: "suspicious", label: "Suspicious or injection" },
              ]}
            />
          </Field>
          <Field label="Anomaly threshold (robust z)" htmlFor="det-z" hint="Deviation from the agent's own baseline before a behavioural anomaly fires.">
            <Input id="det-z" type="number" step="0.5" min={2} value={d.anomaly_z ?? 6} onChange={(e) => set("anomaly_z", Number(e.target.value))} />
          </Field>
          <Field label="AI-assisted classifier" htmlFor="det-ai">
            <SimpleSelect
              id="det-ai"
              value={d.ai_provider ?? "none"}
              onValueChange={(v) => set("ai_provider", v as Detection["ai_provider"])}
              options={[
                { value: "none", label: "Off (heuristics only)" },
                { value: "openai", label: "OpenAI compatible" },
                { value: "ollama", label: "Ollama" },
                { value: "anthropic", label: "Anthropic" },
              ]}
            />
          </Field>
        </div>
        {ai && (
          <div className="grid gap-4 rounded-xl bg-muted/60 p-4 sm:grid-cols-3">
            <Field label="Base URL" htmlFor="det-url">
              <Input id="det-url" className="font-mono text-[12.5px]" value={d.ai_base_url ?? ""} onChange={(e) => set("ai_base_url", e.target.value)} />
            </Field>
            <Field label="Model" htmlFor="det-model">
              <Input id="det-model" className="font-mono text-[12.5px]" value={d.ai_model ?? ""} onChange={(e) => set("ai_model", e.target.value)} />
            </Field>
            <Field label="API key" htmlFor="det-key" hint={settings.ai_api_key_set ? "Stored. Leave empty to keep it." : "Write only: never shown again."}>
              <Input id="det-key" type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)} />
            </Field>
          </div>
        )}
      </div>
    </Section>
  );
}

const RESPONSES = [
  { value: "quarantine", label: "Quarantine the agent" },
  { value: "revoke_credentials", label: "Revoke its credentials" },
  { value: "incident", label: "Open an incident" },
  { value: "notify", label: "Notify" },
] as const;

export function ResponsesSection({ settings }: { settings: OrgSettings }) {
  const update = useUpdateSettings();
  const [r, setR, dirty] = useDraft<ThreatResponses>(settings.threat_responses);
  return (
    <Section
      id="responses"
      title="Threat responses"
      description="What happens automatically when a detection of each severity fires."
      dirty={dirty}
      pending={update.isPending}
      onSave={() => update.mutate({ threat_responses: r }, { onSuccess: () => toast.success("Threat responses saved."), onError: (err) => toast.error(errorMessage(err)) })}
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-[13px]">
          <thead>
            <tr className="text-left text-[11.5px] text-subtle">
              <th className="pb-2 font-medium">Severity</th>
              {RESPONSES.map((x) => (
                <th key={x.value} className="pb-2 text-center font-medium">
                  {x.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...SEVERITIES].reverse().map((s) => {
              const list = r[s] ?? [];
              return (
                <tr key={s} className="border-t border-hairline">
                  <td className="py-2.5 font-medium">{severitySpec(s).label}</td>
                  {RESPONSES.map((x) => (
                    <td key={x.value} className="py-2.5 text-center">
                      <input
                        type="checkbox"
                        aria-label={`${severitySpec(s).label}: ${x.label}`}
                        className="size-4 accent-[var(--primary)]"
                        checked={list.includes(x.value)}
                        onChange={(e) => setR((old) => ({ ...old, [s]: e.target.checked ? [...(old[s] ?? []), x.value] : (old[s] ?? []).filter((v) => v !== x.value) }))}
                      />
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

export function RetentionSection({ settings }: { settings: OrgSettings }) {
  const update = useUpdateSettings();
  const [r, setR, dirty] = useDraft<Retention>(settings.retention);
  return (
    <Section
      id="retention"
      title="Retention"
      description="Payloads are pruned after these periods; the audit hash chain stays verifiable."
      dirty={dirty}
      pending={update.isPending}
      onSave={() => update.mutate({ retention: r }, { onSuccess: () => toast.success("Retention saved."), onError: (err) => toast.error(errorMessage(err)) })}
    >
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Decision parameters (days)" htmlFor="ret-dec">
          <NumberInput id="ret-dec" value={r.decision_payload_days ?? 90} onChange={(n) => setR((x) => ({ ...x, decision_payload_days: n }))} min={1} />
        </Field>
        <Field label="Audit details (days)" htmlFor="ret-audit">
          <NumberInput id="ret-audit" value={r.audit_details_days ?? 365} onChange={(n) => setR((x) => ({ ...x, audit_details_days: n }))} min={1} />
        </Field>
        <Field label="Connection log (days)" htmlFor="ret-egress">
          <NumberInput id="ret-egress" value={r.egress_days ?? 30} onChange={(n) => setR((x) => ({ ...x, egress_days: n }))} min={1} />
        </Field>
      </div>
    </Section>
  );
}

export function NotificationsSection({ settings }: { settings: OrgSettings }) {
  const update = useUpdateSettings();
  const [n, setN, dirty] = useDraft<Notifications>(settings.notifications);
  return (
    <Section
      id="notifications"
      title="Notifications"
      description="Email to the people who can act. Webhooks are in Integrations."
      dirty={dirty}
      pending={update.isPending}
      onSave={() => update.mutate({ notifications: n }, { onSuccess: () => toast.success("Notifications saved."), onError: (err) => toast.error(errorMessage(err)) })}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="flex items-center gap-2 self-end pb-2 text-[13px]">
          <Switch checked={n.approval_emails ?? true} onCheckedChange={(c) => setN((x) => ({ ...x, approval_emails: c }))} aria-label="Approval emails" />
          Email reviewers when an approval is requested
        </label>
        <Field label="Email threats from severity" htmlFor="not-sev">
          <SimpleSelect
            id="not-sev"
            value={n.threat_email_min_severity ?? "high"}
            onValueChange={(v) => setN((x) => ({ ...x, threat_email_min_severity: v as Notifications["threat_email_min_severity"] }))}
            options={[...SEVERITIES.map((s) => ({ value: s, label: `${severitySpec(s).label} and above` })), { value: "off", label: "Never" }]}
          />
        </Field>
        <Field label="Also send to" htmlFor="not-extra" className="sm:col-span-2" hint="Extra addresses, comma separated (a security mailbox).">
          <ListInput id="not-extra" className="text-[13px]" value={n.extra_recipients ?? []} onChange={(v) => setN((x) => ({ ...x, extra_recipients: v }))} placeholder="security@corp.example" />
        </Field>
      </div>
    </Section>
  );
}

export { Section, useDraft };
