"use client";

import * as React from "react";

export interface TooltipRow {
  label: string;
  value: string;
  color: string;
}

/** Shared tooltip card for every chart: title, then one row per series. */
export function ChartTooltipCard({ title, rows, footer }: { title: string; rows: TooltipRow[]; footer?: React.ReactNode }) {
  return (
    <div className="min-w-44 rounded-xl bg-popover px-3 py-2.5 text-xs text-popover-foreground shadow-[var(--elev-4)] ring-1 ring-black/5 dark:ring-white/8">
      <div className="mb-1.5 font-medium text-muted-foreground">{title}</div>
      <div className="space-y-1">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center justify-between gap-5">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="size-2 rounded-[3px]" style={{ background: r.color }} aria-hidden />
              {r.label}
            </span>
            <span className="font-semibold text-foreground tabular">{r.value}</span>
          </div>
        ))}
      </div>
      {footer && <div className="mt-1.5 pt-1.5 text-muted-foreground">{footer}</div>}
    </div>
  );
}

export function ChartLegend({ items }: { items: { label: string; color: string; value?: string }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-[3px]" style={{ background: i.color }} aria-hidden />
          {i.label}
          {i.value && <span className="font-semibold text-foreground tabular">{i.value}</span>}
        </li>
      ))}
    </ul>
  );
}

/** Chart colours, all from the design tokens so both themes stay legible. */
export const CHART = {
  c1: "var(--chart-1)",
  c2: "var(--chart-2)",
  c3: "var(--chart-3)",
  c4: "var(--chart-4)",
  c5: "var(--chart-5)",
  c6: "var(--chart-6)",
  grid: "var(--chart-grid)",
  axis: "var(--chart-axis)",
} as const;

export const SERIES_COLORS = [CHART.c1, CHART.c2, CHART.c3, CHART.c4, CHART.c5, CHART.c6] as const;
