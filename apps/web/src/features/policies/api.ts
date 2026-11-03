"use client";

import { useMutation, useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { EvaluateRequest } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function usePolicies() {
  return useQuery({ queryKey: qk.policies, queryFn: () => unwrap(api.GET("/api/v1/policies")), staleTime: STALE.list });
}

export function usePolicy(id: string | null) {
  return useQuery({
    queryKey: qk.policy(id ?? ""),
    queryFn: () => unwrap(api.GET("/api/v1/policies/{policy_id}", { params: { path: { policy_id: id ?? "" } } })),
    enabled: !!id,
    staleTime: STALE.list,
  });
}

/** Create (no id) or save a new version (id). */
export function useSavePolicy() {
  return useInvalidating(
    ({ id, source, activate, comment }: { id?: string; source: string; activate: boolean; comment: string }) =>
      id
        ? unwrap(api.PUT("/api/v1/policies/{policy_id}", { params: { path: { policy_id: id } }, body: { source, activate, comment } }))
        : unwrap(api.POST("/api/v1/policies", { body: { source, activate, comment } })),
    [qk.policies, qk.compliance],
  );
}

export function useValidatePolicy() {
  return useMutation({ mutationFn: (source: string) => unwrap(api.POST("/api/v1/policies/validate", { body: { source } })) });
}

export function useEvaluatePolicy() {
  return useMutation({ mutationFn: (body: EvaluateRequest) => unwrap(api.POST("/api/v1/policies/evaluate", { body })) });
}

export function useSimulatePolicy() {
  return useMutation({
    mutationFn: (body: { source: string; policy_id?: string | null; days: number }) => unwrap(api.POST("/api/v1/policies/simulate", { body })),
  });
}

export function usePolicyAction() {
  return useInvalidating(
    ({ id, action, version }: { id: string; action: "activate" | "rollback" | "disable" | "delete"; version?: number }) => {
      const path = { params: { path: { policy_id: id } } };
      switch (action) {
        case "activate":
          return unwrap(api.POST("/api/v1/policies/{policy_id}/activate", { ...path, body: { version: version ?? 1 } }));
        case "rollback":
          return unwrap(api.POST("/api/v1/policies/{policy_id}/rollback", path));
        case "disable":
          return unwrap(api.POST("/api/v1/policies/{policy_id}/disable", path));
        case "delete":
          return unwrap(api.DELETE("/api/v1/policies/{policy_id}", path));
      }
    },
    [qk.policies, qk.compliance],
  );
}
