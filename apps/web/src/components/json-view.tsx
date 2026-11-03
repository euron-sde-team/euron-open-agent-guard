import { CopyButton } from "@/components/copy-button";
import { cn } from "@/lib/cn";

/** Stable, readable JSON for display: two-space indent, keys in their original order. */
export function prettyJson(value: unknown): string {
  if (value === undefined) return "";
  try {
    return JSON.stringify(value, null, 2) ?? "";
  } catch {
    return String(value);
  }
}

/** Pretty JSON in a dark code block, with a copy button. */
export function JsonView({ value, className, maxHeight = 420, label = "JSON" }: { value: unknown; className?: string; maxHeight?: number; label?: string }) {
  const text = prettyJson(value);
  return (
    <div className={cn("relative min-w-0", className)}>
      <pre className="code-block" style={{ maxHeight }} aria-label={label}>
        {text || "{}"}
      </pre>
      {text && <CopyButton value={text} iconOnly label={`Copy ${label}`} variant="subtle" className="absolute top-2 right-2 text-code-fg hover:bg-white/10" />}
    </div>
  );
}

/** A code snippet (SDK, YAML) with a title row and a copy button. */
export function CodeBlock({ code, className, label = "Code" }: { code: string; className?: string; label?: string }) {
  return (
    <div className={cn("relative min-w-0", className)}>
      <pre className="code-block" aria-label={label}>
        {code}
      </pre>
      <CopyButton value={code} iconOnly label={`Copy ${label}`} variant="subtle" className="absolute top-2 right-2 text-code-fg hover:bg-white/10" />
    </div>
  );
}
