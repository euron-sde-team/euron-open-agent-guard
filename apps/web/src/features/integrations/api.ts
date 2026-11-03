"use client";

import { useMutation, useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { IntegrationIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export type IntegrationKind = "tokenshield" | "opa" | "siem";

export function useIntegrations(enabled = true) {
  return useQuery({ queryKey: qk.integrations, queryFn: () => unwrap(api.GET("/api/v1/integrations")), staleTime: STALE.config, enabled });
}

export function useSaveIntegration() {
  return useInvalidating(
    ({ kind, body }: { kind: IntegrationKind; body: IntegrationIn }) =>
      unwrap(api.PUT("/api/v1/integrations/{kind}", { params: { path: { kind } }, body })),
    [qk.integrations, qk.compliance],
  );
}

export function useTestIntegration() {
  return useMutation({
    mutationFn: (kind: IntegrationKind) => unwrap(api.POST("/api/v1/integrations/{kind}/test", { params: { path: { kind } } })),
  });
}

export function useApiKeys(enabled = true) {
  return useQuery({ queryKey: qk.apiKeys, queryFn: () => unwrap(api.GET("/api/v1/api-keys")), staleTime: STALE.config, enabled });
}

export function useCreateApiKey() {
  return useInvalidating((body: { name: string; scope: "read" | "write" }) => unwrap(api.POST("/api/v1/api-keys", { body })), [qk.apiKeys]);
}

export function useRevokeApiKey() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/api-keys/{key_id}", { params: { path: { key_id: id } } })), [qk.apiKeys]);
}

export function useWebhooks(enabled = true) {
  return useQuery({ queryKey: qk.webhooks, queryFn: () => unwrap(api.GET("/api/v1/webhooks")), staleTime: STALE.config, enabled });
}

export function useWebhookEvents(enabled = true) {
  return useQuery({
    queryKey: qk.webhookEvents,
    queryFn: async () => (await unwrap(api.GET("/api/v1/webhooks/events"))) as unknown as string[],
    staleTime: STALE.static,
    enabled,
  });
}

export function useCreateWebhook() {
  return useInvalidating((body: { url: string; events: string[] }) => unwrap(api.POST("/api/v1/webhooks", { body })), [qk.webhooks]);
}

export function useWebhookAction() {
  return useInvalidating<{ id: string; action: "test" | "delete" | "toggle"; active?: boolean }, unknown>(
    ({ id, action, active }) => {
      const path = { params: { path: { webhook_id: id } } };
      if (action === "test") return unwrap(api.POST("/api/v1/webhooks/{webhook_id}/test", path));
      if (action === "toggle") return unwrap(api.PATCH("/api/v1/webhooks/{webhook_id}", { ...path, body: { active } }));
      return unwrap(api.DELETE("/api/v1/webhooks/{webhook_id}", path));
    },
    [qk.webhooks],
  );
}
