"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { useLivePolling } from "@/features/live/dashboard-live";
import { api, unwrap } from "@/lib/api/client";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useIncidents(status: string) {
  const poll = useLivePolling();
  return useQuery({
    queryKey: qk.incidentList(status),
    queryFn: () => unwrap(api.GET("/api/v1/incidents", { params: { query: { status: status || undefined } } })),
    staleTime: STALE.live,
    placeholderData: keepPreviousData,
    refetchInterval: poll,
  });
}

export function useIncident(id: string) {
  return useQuery({
    queryKey: qk.incident(id),
    queryFn: () => unwrap(api.GET("/api/v1/incidents/{incident_id}", { params: { path: { incident_id: id } } })),
    staleTime: STALE.live,
  });
}

export function useOpenIncident() {
  return useInvalidating(
    (body: { title: string; severity: string; summary: string; agent_ids: string[] }) => unwrap(api.POST("/api/v1/incidents", { body })),
    [qk.incidents, qk.metrics],
  );
}

export function useIncidentAction(id: string) {
  const keys = [qk.incidents, qk.metrics, qk.agents, qk.secrets, qk.settings];
  const path = { params: { path: { incident_id: id } } };
  return {
    note: useInvalidating((text: string) => unwrap(api.POST("/api/v1/incidents/{incident_id}/notes", { ...path, body: { text } })), keys),
    evidence: useInvalidating(
      (body: { kind: string; ref_id: string }) => unwrap(api.POST("/api/v1/incidents/{incident_id}/evidence", { ...path, body })),
      keys,
    ),
    contain: useInvalidating(
      (body: { action: string; target?: string | null; reason: string }) => unwrap(api.POST("/api/v1/incidents/{incident_id}/contain", { ...path, body })),
      keys,
    ),
    resolve: useInvalidating(
      (body: { root_cause: string; resolution: string }) => unwrap(api.POST("/api/v1/incidents/{incident_id}/resolve", { ...path, body })),
      keys,
    ),
    update: useInvalidating(
      (body: { title?: string; severity?: string; summary?: string }) => unwrap(api.PATCH("/api/v1/incidents/{incident_id}", { ...path, body })),
      keys,
    ),
  };
}
