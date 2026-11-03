"use client";

import * as React from "react";

import { cn } from "@/lib/cn";

/**
 * A monospace YAML editor with line numbers. A plain textarea (no editor dependency):
 * Tab inserts two spaces, and the gutter scrolls with the text.
 */
export function YamlEditor({ value, onChange, readOnly, invalid, id }: { value: string; onChange: (v: string) => void; readOnly?: boolean; invalid?: boolean; id?: string }) {
  const gutter = React.useRef<HTMLDivElement>(null);
  const lines = Math.max(1, value.split("\n").length);
  return (
    <div className={cn("relative flex min-h-[420px] overflow-hidden rounded-xl bg-code-bg font-mono text-[12.5px] leading-[1.6] text-code-fg", invalid && "ring-2 ring-danger/60")}>
      <div ref={gutter} aria-hidden className="no-scrollbar shrink-0 overflow-hidden py-3 pr-3 pl-3 text-right text-[11.5px] leading-[1.74] text-white/30 select-none">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>
      <textarea
        id={id}
        aria-label="Policy YAML"
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        readOnly={readOnly}
        value={value}
        wrap="off"
        onScroll={(e) => {
          if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop;
        }}
        onKeyDown={(e) => {
          if (e.key !== "Tab" || readOnly) return;
          e.preventDefault();
          const el = e.currentTarget;
          const { selectionStart: s, selectionEnd: end } = el;
          const next = `${value.slice(0, s)}  ${value.slice(end)}`;
          onChange(next);
          requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2));
        }}
        onChange={(e) => onChange(e.target.value)}
        className="min-h-[420px] w-full flex-1 resize-y bg-transparent py-3 pr-4 outline-none placeholder:text-white/30 focus-visible:outline-none"
      />
    </div>
  );
}
