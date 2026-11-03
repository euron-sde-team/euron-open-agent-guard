"use client";

import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";

import { useLivePolling } from "@/features/live/dashboard-live";
import { api, unwrap } from "@/lib/api/client";
import type { AgentIn, AgentUpdate } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export interface AgentFilters {
  status?: string;
  project_id?: string;
  q?: string;
}

export function useAgents(filters: AgentFilters = {}) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.agentList(filters),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/agents", {
          params: { query: { status: filters.status || undefined, project_id: filters.project_id || undefined, q: filters.q || undefined } },
        }),
      ),
    staleTime: STALE.list,
    placeholderData: keepPreviousData,
    refetchInterval: poll,
  });
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: qk.agent(id),
    queryFn: () => unwrap(api.GET("/api/v1/agents/{agent_id}", { params: { path: { agent_id: id } } })),
    staleTime: STALE.list,
  });
}

export function useRegisterAgent() {
  return useInvalidating((body: AgentIn) => unwrap(api.POST("/api/v1/agents/register", { body })), [qk.agents, qk.metrics]);
}

export function useUpdateAgent(id: string) {
  return useInvalidating(
    (body: AgentUpdate) => unwrap(api.PATCH("/api/v1/agents/{agent_id}", { params: { path: { agent_id: id } }, body })),
    [qk.agents],
  );
}

export type AgentAction = "suspend" | "quarantine" | "reactivate" | "revoke";

export function useAgentAction(id: string) {
  return useInvalidating(
    ({ action, reason }: { action: AgentAction; reason: string }) => {
      const opts = { params: { path: { agent_id: id } }, body: { reason } };
      switch (action) {
        case "suspend":
          return unwrap(api.POST("/api/v1/agents/{agent_id}/suspend", opts));
        case "quarantine":
          return unwrap(api.POST("/api/v1/agents/{agent_id}/quarantine", opts));
        case "reactivate":
          return unwrap(api.POST("/api/v1/agents/{agent_id}/reactivate", opts));
        case "revoke":
          return unwrap(api.POST("/api/v1/agents/{agent_id}/revoke", opts));
      }
    },
    [qk.agents, qk.metrics],
  );
}

export function useIssueCredential(id: string) {
  return useInvalidating(
    (body: { label: string; expires_in_days?: number | null; allowed_cidrs?: string[] }) =>
      unwrap(api.POST("/api/v1/agents/{agent_id}/credentials", { params: { path: { agent_id: id } }, body })),
    [qk.agent(id)],
  );
}

export function useRotateCredential(id: string) {
  return useInvalidating(
    (credentialId: string) =>
      unwrap(api.POST("/api/v1/agents/{agent_id}/credentials/{credential_id}/rotate", { params: { path: { agent_id: id, credential_id: credentialId } } })),
    [qk.agent(id)],
  );
}

export function useRevokeCredential(id: string) {
  return useInvalidating(
    (credentialId: string) =>
      unwrap(api.POST("/api/v1/agents/{agent_id}/credentials/{credential_id}/revoke", { params: { path: { agent_id: id, credential_id: credentialId } } })),
    [qk.agent(id)],
  );
}

export interface DecisionFilters {
  agent_id?: string;
  decision?: string;
  tool?: string;
  risk?: string;
  hours?: number;
  limit?: number;
}

/** Keyset-paginated decision log. */
export function useDecisions(filters: DecisionFilters) {
  const poll = useLivePolling();
  return useInfiniteQuery({
    queryKey: qk.decisionList(filters),
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) =>
      unwrap(
        api.GET("/api/v1/access/decisions", {
          params: {
            query: {
              agent_id: filters.agent_id || undefined,
              decision: filters.decision || undefined,
              tool: filters.tool || undefined,
              risk: filters.risk || undefined,
              hours: filters.hours,
              limit: filters.limit ?? 25,
              cursor: pageParam ?? undefined,
            },
          },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor ?? null,
    staleTime: STALE.live,
    refetchInterval: poll,
  });
}

export function useDecision(id: string | null) {
  return useQuery({
    queryKey: qk.decision(id ?? ""),
    queryFn: () => unwrap(api.GET("/api/v1/decisions/{decision_id}", { params: { path: { decision_id: id ?? "" } } })),
    enabled: !!id,
    staleTime: STALE.static,
  });
}
