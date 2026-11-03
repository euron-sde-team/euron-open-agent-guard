"use client";

import { ClockIcon } from "lucide-react";

import { Chip } from "@/components/ui/chip";
import { useNow } from "@/hooks/use-now";
import { formatDuration } from "@/lib/format";
import { roleLabel } from "@/lib/roles";
import { arr, num, obj, strs } from "@/lib/read";

export interface Stage {
  roles: string[];
  users: string[];
  count: number;
}

/** The approval requirement's stages, in order, from the API's free-form object. */
export function stagesOf(requirement: unknown): Stage[] {
  return arr(obj(requirement).stages).map((s) => {
    const o = obj(s);
    return { roles: strs(o.roles), users: strs(o.users), count: num(o.count) ?? 1 };
  });
}

/** "1 of: Reviewer or Security officer" */
export function stageText(s: Stage): string {
  const who = [...s.roles.map((r) => roleLabel(r)), ...s.users].join(" or ") || "any reviewer";
  return `${s.count} ${s.count === 1 ? "approval" : "approvals"} from ${who}`;
}

/** Time left before a pending approval expires, or "expired". */
export function ExpiryChip({ expiresAt, status }: { expiresAt: string; status: string }) {
  const now = useNow(30_000);
  if (status !== "pending") return null;
  const left = (new Date(expiresAt).getTime() - now.getTime()) / 1000;
  if (left <= 0) return <Chip tone="neutral">Expired</Chip>;
  return (
    <Chip tone={left < 3600 ? "danger" : "neutral"}>
      <ClockIcon />
      {formatDuration(left)} left
    </Chip>
  );
}

/** A short "key: value" list of the first parameters, for queue rows. */
export function ParamsPreview({ params, max = 4 }: { params: unknown; max?: number }) {
  const entries = Object.entries(obj(params)).slice(0, max);
  if (!entries.length) return <span className="text-[12px] text-subtle">No parameters</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {entries.map(([k, v]) => (
        <span key={k} className="max-w-[260px] truncate rounded-md bg-muted px-1.5 py-0.5 font-mono text-[11.5px] text-muted-foreground">
          {k}: {typeof v === "string" ? v : JSON.stringify(v)}
        </span>
      ))}
    </span>
  );
}
