"use client";

import { useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { SecretIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useSecrets() {
  return useQuery({ queryKey: qk.secrets, queryFn: () => unwrap(api.GET("/api/v1/secrets")), staleTime: STALE.list });
}

export function useSecret(id: string) {
  return useQuery({
    queryKey: qk.secret(id),
    queryFn: () => unwrap(api.GET("/api/v1/secrets/{secret_id}", { params: { path: { secret_id: id } } })),
    staleTime: STALE.list,
  });
}

export function useCreateSecret() {
  return useInvalidating((body: SecretIn) => unwrap(api.POST("/api/v1/secrets", { body })), [qk.secrets]);
}

export function useRotateSecret(id: string) {
  return useInvalidating(
    (body: { value: string; grace_s: number }) => unwrap(api.POST("/api/v1/secrets/{secret_id}/rotate", { params: { path: { secret_id: id } }, body })),
    [qk.secrets],
  );
}

export function useRevokeSecret(id: string) {
  return useInvalidating(
    (reason: string) => unwrap(api.POST("/api/v1/secrets/{secret_id}/revoke", { params: { path: { secret_id: id } }, body: { reason } })),
    [qk.secrets],
  );
}

export function useDeleteSecret() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/secrets/{secret_id}", { params: { path: { secret_id: id } } })), [qk.secrets]);
}

export function useGrantLease(id: string) {
  return useInvalidating(
    (body: { agent_id: string; minutes: number; max_uses?: number | null; reason: string }) =>
      unwrap(api.POST("/api/v1/secrets/{secret_id}/leases", { params: { path: { secret_id: id } }, body })),
    [qk.secret(id)],
  );
}

export function useEndLease(id: string) {
  return useInvalidating(
    (leaseId: string) => unwrap(api.DELETE("/api/v1/secrets/{secret_id}/leases/{lease_id}", { params: { path: { secret_id: id, lease_id: leaseId } } })),
    [qk.secret(id)],
  );
}
