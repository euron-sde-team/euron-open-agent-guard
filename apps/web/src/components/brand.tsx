import { cn } from "@/lib/cn";

/** The AgentGuard mark: a shield with a check, in the accent colour. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn("size-7", className)}>
      <rect width="32" height="32" rx="9" className="fill-primary" />
      <path
        d="M16 7.5l7 2.6v5.4c0 4.6-3 8.1-7 9.5-4-1.4-7-4.9-7-9.5v-5.4z"
        fill="none"
        className="stroke-primary-foreground"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M12.6 16.1l2.4 2.4 4.4-4.6" fill="none" className="stroke-primary-foreground" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function BrandLogo({ collapsed = false, className }: { collapsed?: boolean; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <BrandMark />
      {!collapsed && <span className="text-[15px] font-semibold tracking-[-0.02em]">AgentGuard</span>}
    </span>
  );
}
