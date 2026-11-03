"use client";

import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";

import { useLivePolling } from "@/features/live/dashboard-live";
import { api, unwrap } from "@/lib/api/client";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export interface ThreatFilters {
  status?: string;
  severity?: string;
  kind?: string;
  agent_id?: string;
}

export function useThreats(filters: ThreatFilters) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.threatList(filters),
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/threats", {
          params: {
            query: {
              status: filters.status || undefined,
              severity: filters.severity || undefined,
              kind: filters.kind || undefined,
              agent_id: filters.agent_id || undefined,
              limit: 200,
            },
          },
        }),
      ),
    staleTime: STALE.live,
    placeholderData: keepPreviousData,
    refetchInterval: poll,
  });
}

export function useThreat(id: string) {
  return useQuery({
    queryKey: qk.threat(id),
    queryFn: () => unwrap(api.GET("/api/v1/threats/{threat_id}", { params: { path: { threat_id: id } } })),
    staleTime: STALE.live,
  });
}

export function useUpdateThreat(id: string) {
  return useInvalidating(
    (status: string) => unwrap(api.PATCH("/api/v1/threats/{threat_id}", { params: { path: { threat_id: id } }, body: { status } })),
    [qk.threats, qk.metrics],
  );
}

export function useAnalyze() {
  return useMutation({ mutationFn: (content: string) => unwrap(api.POST("/api/v1/threats/analyze", { body: { content } })) });
}

export function useRiskAssessments(filters: { level?: string; hours?: number }) {
  return useQuery({
    queryKey: qk.riskAssessments(filters),
    queryFn: () =>
      unwrap(api.GET("/api/v1/risk-assessments", { params: { query: { level: filters.level || undefined, hours: filters.hours ?? 24 * 7, limit: 50 } } })),
    staleTime: STALE.list,
    placeholderData: keepPreviousData,
  });
}

export function useRiskRules() {
  return useQuery({ queryKey: qk.riskRules, queryFn: () => unwrap(api.GET("/api/v1/risk-rules")), staleTime: STALE.config });
}

export function useSaveRiskRule() {
  return useInvalidating(
    ({ id, body }: { id?: string; body: { name: string; condition: string; points: number; enabled: boolean } }) =>
      id
        ? unwrap(api.PUT("/api/v1/risk-rules/{rule_id}", { params: { path: { rule_id: id } }, body }))
        : unwrap(api.POST("/api/v1/risk-rules", { body })),
    [qk.riskRules],
  );
}

export function useDeleteRiskRule() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/risk-rules/{rule_id}", { params: { path: { rule_id: id } } })), [qk.riskRules]);
}
