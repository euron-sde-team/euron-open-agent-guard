"use client";

import * as React from "react";

/** Now, re-rendered every `intervalMs` while mounted (relative times, SLA countdowns). */
export function useNow(intervalMs = 1000): Date {
  const [now, setNow] = React.useState(() => new Date());
  React.useEffect(() => {
    const t = setInterval(() => setNow(new Date()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}
