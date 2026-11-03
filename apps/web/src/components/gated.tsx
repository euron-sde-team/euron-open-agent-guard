"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { usePermissions } from "@/features/auth/api";
import { needsRoleText, type Capability } from "@/lib/roles";

type ButtonProps = React.ComponentProps<typeof Button>;

/**
 * A button that needs a capability. When the person's role is too low it stays visible
 * but disabled, with a tooltip naming the role it needs (the API refuses it anyway).
 * `reason` disables it for another reason the API explained (an approval's why_not).
 */
export function GatedButton({ need, reason, ...props }: ButtonProps & { need: Capability; reason?: string | null }) {
  const { can } = usePermissions();
  const why = !can(need) ? needsRoleText(need) : reason || null;
  if (!why) return <Button {...props} />;
  return (
    <Tooltip>
      <TooltipTrigger render={<span tabIndex={0} className="inline-flex rounded-lg focus-visible:outline-2 focus-visible:outline-ring" />}>
        <Button {...props} disabled aria-disabled onClick={undefined} />
      </TooltipTrigger>
      <TooltipContent>{why}</TooltipContent>
    </Tooltip>
  );
}

/** Renders its children only for roles with the capability. */
export function Can({ need, children, fallback = null }: { need: Capability; children: React.ReactNode; fallback?: React.ReactNode }) {
  const { can } = usePermissions();
  return <>{can(need) ? children : fallback}</>;
}
