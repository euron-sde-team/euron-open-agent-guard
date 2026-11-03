"use client";

import { useTheme } from "next-themes";
import * as React from "react";

const TOKENS = ["chart-1", "chart-2", "chart-3", "chart-4", "chart-5", "chart-6", "chart-allow", "chart-restrict", "chart-approval", "chart-deny", "chart-quarantine", "chart-grid", "chart-axis"] as const;
type Token = (typeof TOKENS)[number];

/**
 * The chart tokens from globals.css as concrete colours. SVG presentation attributes
 * (stroke, fill, stop-color) do not resolve CSS variables, so recharts needs real values;
 * they are re-read whenever the theme changes, so both themes stay on the tokens.
 */
export function useChartColors(): Record<Token, string> {
  const { resolvedTheme } = useTheme();
  const read = React.useCallback(() => {
    const out = {} as Record<Token, string>;
    const style = typeof window === "undefined" ? null : getComputedStyle(document.documentElement);
    for (const t of TOKENS) out[t] = style?.getPropertyValue(`--${t}`).trim() || "currentColor";
    return out;
  }, []);
  const [colors, setColors] = React.useState<Record<Token, string>>(read);
  React.useEffect(() => {
    // The theme class lands on <html> after this render; read on the next frame.
    const id = requestAnimationFrame(() => setColors(read()));
    return () => cancelAnimationFrame(id);
  }, [resolvedTheme, read]);
  return colors;
}
