"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import { qk, STALE } from "@/lib/query-keys";

export function useSandboxSessions(verdict: string) {
  return useQuery({
    queryKey: qk.sandboxSessions(verdict),
    queryFn: () => unwrap(api.GET("/api/v1/sandbox/sessions", { params: { query: { verdict: verdict || undefined, limit: 100 } } })),
    staleTime: STALE.list,
    placeholderData: keepPreviousData,
  });
}

export function useSandboxHealth() {
  return useQuery({ queryKey: qk.sandboxHealth, queryFn: () => unwrap(api.GET("/api/v1/sandbox/health")), staleTime: STALE.config });
}
