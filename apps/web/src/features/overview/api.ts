"use client";

import { useQuery } from "@tanstack/react-query";

import { useLivePolling } from "@/features/live/dashboard-live";
import { api, unwrap } from "@/lib/api/client";
import { qk, STALE } from "@/lib/query-keys";

export function useOverview(days: number) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.overview(days),
    queryFn: () => unwrap(api.GET("/api/v1/security/metrics", { params: { query: { days } } })),
    staleTime: STALE.live,
    refetchInterval: poll || 30_000,
  });
}
