"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import { qk, STALE } from "@/lib/query-keys";

export interface AuditFilters {
  action?: string;
  actor?: string;
  target_id?: string;
}

export function useAuditLog(filters: AuditFilters) {
  return useInfiniteQuery({
    queryKey: qk.auditList(filters),
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/audit-logs", {
          params: {
            query: {
              action: filters.action || undefined,
              actor: filters.actor || undefined,
              target_id: filters.target_id || undefined,
              cursor: pageParam ?? undefined,
              limit: 50,
            },
          },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor ?? null,
    staleTime: STALE.list,
  });
}

export function useVerifyChain() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/audit-logs/verify")),
    onSuccess: () => void client.invalidateQueries({ queryKey: qk.checkpoints }),
  });
}

export function useCheckpoints() {
  return useQuery({
    queryKey: qk.checkpoints,
    queryFn: () => unwrap(api.GET("/api/v1/audit-logs/checkpoints", { params: { query: { limit: 20 } } })),
    staleTime: STALE.list,
  });
}
