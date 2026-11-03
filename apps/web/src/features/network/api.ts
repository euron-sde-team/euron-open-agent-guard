"use client";

import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { NetworkPolicyIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useNetworkPolicies() {
  return useQuery({ queryKey: qk.networkPolicies, queryFn: () => unwrap(api.GET("/api/v1/network-policies")), staleTime: STALE.config });
}

export function useSaveNetworkPolicy() {
  return useInvalidating(
    ({ id, body }: { id?: string; body: NetworkPolicyIn }) =>
      id
        ? unwrap(api.PUT("/api/v1/network-policies/{policy_id}", { params: { path: { policy_id: id } }, body }))
        : unwrap(api.POST("/api/v1/network-policies", { body })),
    [qk.network],
  );
}

export function useDeleteNetworkPolicy() {
  return useInvalidating(
    (id: string) => unwrap(api.DELETE("/api/v1/network-policies/{policy_id}", { params: { path: { policy_id: id } } })),
    [qk.network],
  );
}

export function useTestDestination() {
  return useMutation({
    mutationFn: (body: { host: string; port: number; method?: string | null; policy_id?: string | null; agent_id?: string | null }) =>
      unwrap(api.POST("/api/v1/network-policies/test", { body })),
  });
}

export function useEgress(filters: { decision?: string }) {
  return useQuery({
    queryKey: qk.egress(filters),
    queryFn: () => unwrap(api.GET("/api/v1/egress-events", { params: { query: { decision: filters.decision || undefined, limit: 100 } } })),
    staleTime: STALE.live,
    placeholderData: keepPreviousData,
  });
}
