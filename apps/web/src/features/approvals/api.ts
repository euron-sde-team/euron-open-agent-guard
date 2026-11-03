"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { useLivePolling } from "@/features/live/dashboard-live";
import { api, unwrap } from "@/lib/api/client";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useApprovals(status: string) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.approvalList({ status }),
    queryFn: () => unwrap(api.GET("/api/v1/approvals", { params: { query: { status: status || undefined, limit: 200 } } })),
    staleTime: STALE.live,
    placeholderData: keepPreviousData,
    refetchInterval: poll,
  });
}

export function useApprovalCounts() {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.approvalCounts,
    queryFn: () => unwrap(api.GET("/api/v1/approvals/counts")),
    staleTime: STALE.live,
    refetchInterval: poll || 30_000,
  });
}

export function useApproval(id: string) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.approval(id),
    queryFn: () => unwrap(api.GET("/api/v1/approvals/{approval_id}", { params: { path: { approval_id: id } } })),
    staleTime: STALE.live,
    // Approved and waiting for AgentGuard to run it: check every few seconds until it has
    // executed (or failed), so the person who approved sees the outcome without reloading.
    refetchInterval: (q) => (q.state.data?.status === "approved" ? 3_000 : poll),
  });
}

export type VoteAction = "approve" | "reject" | "request-changes" | "expire" | "revoke";

export function useApprovalAction(id: string) {
  return useInvalidating(
    ({ action, comment }: { action: VoteAction; comment: string }) => {
      const path = { params: { path: { approval_id: id } } };
      const body = { comment };
      switch (action) {
        case "approve":
          return unwrap(api.POST("/api/v1/approvals/{approval_id}/approve", { ...path, body }));
        case "reject":
          return unwrap(api.POST("/api/v1/approvals/{approval_id}/reject", { ...path, body }));
        case "request-changes":
          return unwrap(api.POST("/api/v1/approvals/{approval_id}/request-changes", { ...path, body }));
        case "expire":
          return unwrap(api.POST("/api/v1/approvals/{approval_id}/expire", path));
        case "revoke":
          return unwrap(api.POST("/api/v1/approvals/{approval_id}/revoke", { ...path, body }));
      }
    },
    [qk.approvals, qk.metrics],
  );
}
