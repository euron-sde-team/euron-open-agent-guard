import * as React from "react";

import { cn } from "@/lib/cn";

/** A definition list drawn as label and value rows on a fill, no outlines. */
export function KeyValues({ items, className, columns = 1 }: { items: { label: React.ReactNode; value: React.ReactNode; hidden?: boolean }[]; className?: string; columns?: 1 | 2 | 3 }) {
  return (
    <dl className={cn("grid gap-x-6 gap-y-3", columns === 2 && "sm:grid-cols-2", columns === 3 && "sm:grid-cols-2 lg:grid-cols-3", className)}>
      {items
        .filter((i) => !i.hidden)
        .map((i, n) => (
          <div key={n} className="min-w-0">
            <dt className="text-[11.5px] font-medium text-subtle">{i.label}</dt>
            <dd className="mt-0.5 min-w-0 text-[13px] break-words text-foreground">{i.value}</dd>
          </div>
        ))}
    </dl>
  );
}

/** Monospace, truncated identifier (hash, client id) with the full value on hover. */
export function Mono({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return (
    <span title={title ?? (typeof children === "string" ? children : undefined)} className={cn("font-mono text-[12px] break-all text-muted-foreground", className)}>
      {children}
    </span>
  );
}

/** "a1b2c3d4...9f0e" for long hashes. */
export function shortHash(value: string | null | undefined, head = 10, tail = 6): string {
  if (!value) return "";
  return value.length <= head + tail + 3 ? value : `${value.slice(0, head)}...${value.slice(-tail)}`;
}
