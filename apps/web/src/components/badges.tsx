"use client";

import { Chip } from "@/components/ui/chip";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { decisionSpec, severitySpec, statusSpec, type Spec } from "@/lib/labels";

function WithTip({ tip, children }: { tip?: React.ReactNode; children: React.ReactNode }) {
  if (!tip) return <>{children}</>;
  return (
    <Tooltip>
      <TooltipTrigger render={<span tabIndex={0} className="inline-flex rounded-full focus-visible:outline-2 focus-visible:outline-ring" />}>
        {children}
      </TooltipTrigger>
      <TooltipContent>{tip}</TooltipContent>
    </Tooltip>
  );
}

function SpecChip({ spec, dot = false, tip = true }: { spec: Spec; dot?: boolean; tip?: boolean }) {
  return (
    <WithTip tip={tip ? spec.hint : undefined}>
      <Chip tone={spec.tone} dot={dot}>
        {spec.label}
      </Chip>
    </WithTip>
  );
}

/** One color per decision, everywhere: allow, restrict, approval, deny, quarantine. */
export function DecisionChip({ decision, tip = true }: { decision: string; tip?: boolean }) {
  return <SpecChip spec={decisionSpec(decision)} dot tip={tip} />;
}

/** Severity or risk level: low, medium, high, critical. */
export function SeverityChip({ level, prefix }: { level: string; prefix?: string }) {
  const s = severitySpec(level);
  return <Chip tone={s.tone}>{prefix ? `${prefix} ${s.label.toLowerCase()}` : s.label}</Chip>;
}

export function StatusChip({ kind, status }: { kind: Parameters<typeof statusSpec>[0]; status: string }) {
  return <SpecChip spec={statusSpec(kind, status)} dot />;
}
