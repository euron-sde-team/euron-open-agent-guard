"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { useChartColors } from "@/hooks/use-chart-colors";
import { formatNumber } from "@/lib/format";
import { DECISION_CHART, DECISIONS, decisionSpec } from "@/lib/labels";

import { ChartLegend, ChartTooltipCard } from "./chart-tooltip";

export interface DayRow {
  day: string;
  allow: number;
  restrict: number;
  require_approval: number;
  deny: number;
  quarantine: number;
}

/** "2026-11-02" as "Nov 2", read as a calendar day (no timezone shift). */
export function dayLabel(day: string): string {
  const [y, m, d] = day.split("-").map(Number);
  if (!y || !m || !d) return day;
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
}

/** Normalise the API's free-form day rows into numbers per decision. */
export function toDayRows(rows: Record<string, unknown>[]): DayRow[] {
  return rows.map((r) => {
    const n = (k: string) => (typeof r[k] === "number" ? (r[k] as number) : 0);
    return { day: String(r.day ?? ""), allow: n("allow"), restrict: n("restrict"), require_approval: n("require_approval"), deny: n("deny"), quarantine: n("quarantine") };
  });
}

/** Decisions per day, stacked by outcome in the decision colors. */
export function DecisionChart({ rows, height = 240 }: { rows: DayRow[]; height?: number }) {
  const colors = useChartColors();
  const totals = DECISIONS.map((d) => ({ d, total: rows.reduce((s, r) => s + r[d], 0) }));
  return (
    <div className="space-y-3">
      <ChartLegend
        items={totals.map(({ d, total }) => ({ label: decisionSpec(d).label, color: `var(--${DECISION_CHART[d]})`, value: formatNumber(total) }))}
      />
      <div style={{ height }} role="img" aria-label="Decisions per day, stacked by outcome">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -12 }} barCategoryGap="22%">
            <CartesianGrid vertical={false} stroke={colors["chart-grid"]} />
            <XAxis dataKey="day" tickFormatter={dayLabel} tick={{ fontSize: 11, fill: colors["chart-axis"] }} axisLine={false} tickLine={false} minTickGap={16} />
            <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: colors["chart-axis"] }} axisLine={false} tickLine={false} width={44} />
            <Tooltip
              cursor={{ fill: colors["chart-grid"], opacity: 0.5 }}
              content={({ active, payload, label }) =>
                active && payload?.length ? (
                  <ChartTooltipCard
                    title={dayLabel(String(label))}
                    rows={[...payload].reverse().map((p) => ({
                      label: decisionSpec(String(p.dataKey)).label,
                      value: formatNumber(Number(p.value)),
                      color: String(p.color),
                    }))}
                  />
                ) : null
              }
            />
            {DECISIONS.map((d, i) => (
              <Bar
                key={d}
                dataKey={d}
                stackId="d"
                fill={colors[DECISION_CHART[d] as keyof typeof colors]}
                radius={i === DECISIONS.length - 1 ? [3, 3, 0, 0] : 0}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
