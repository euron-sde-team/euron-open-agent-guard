import type { LucideIcon } from "lucide-react";
import * as React from "react";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/cn";

/** One figure with its label: a fill, no outline. */
export function Stat({
  label,
  value,
  icon: Icon,
  detail,
  tone = "default",
  loading = false,
  className,
}: {
  label: string;
  value: React.ReactNode;
  icon?: LucideIcon;
  detail?: React.ReactNode;
  tone?: "default" | "good" | "warn";
  loading?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("surface flex flex-col gap-1.5 p-4", className)}>
      <div className="flex items-center gap-2 text-[12.5px] font-medium text-muted-foreground">
        {Icon && <Icon className="size-4 text-subtle" aria-hidden />}
        {label}
      </div>
      {loading ? (
        <Skeleton className="h-7 w-20" />
      ) : (
        <div
          className={cn(
            "tabular text-[22px] leading-tight font-semibold tracking-[-0.02em]",
            tone === "good" && "text-savings",
            tone === "warn" && "text-warning",
          )}
        >
          {value}
        </div>
      )}
      {detail && <div className="text-[12px] text-muted-foreground">{detail}</div>}
    </div>
  );
}
