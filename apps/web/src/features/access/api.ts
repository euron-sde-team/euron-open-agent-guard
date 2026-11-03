"use client";

import { useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { AccessRoleIn, ResourceIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useRoles() {
  return useQuery({ queryKey: qk.roles, queryFn: () => unwrap(api.GET("/api/v1/roles")), staleTime: STALE.config });
}

export function useSaveRole() {
  return useInvalidating(
    ({ id, body }: { id?: string; body: AccessRoleIn }) =>
      id
        ? unwrap(
            api.PUT("/api/v1/roles/{role_id}", {
              params: { path: { role_id: id } },
              body: { description: body.description, inherits: body.inherits, permissions: body.permissions },
            }),
          )
        : unwrap(api.POST("/api/v1/roles", { body })),
    [qk.roles, qk.tools, qk.agents],
  );
}

export function useDeleteRole() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/roles/{role_id}", { params: { path: { role_id: id } } })), [qk.roles]);
}

export function useBind() {
  return useInvalidating(
    (body: { role: string; subject_type: string; subject_id?: string | null }) => unwrap(api.POST("/api/v1/role-bindings", { body })),
    [qk.roles, qk.agents],
  );
}

export function useUnbind() {
  return useInvalidating(
    (id: string) => unwrap(api.DELETE("/api/v1/role-bindings/{binding_id}", { params: { path: { binding_id: id } } })),
    [qk.roles, qk.agents],
  );
}

export function useResources() {
  return useQuery({ queryKey: qk.resources, queryFn: () => unwrap(api.GET("/api/v1/resources")), staleTime: STALE.config });
}

export function useSaveResource() {
  return useInvalidating(
    ({ id, body }: { id?: string; body: ResourceIn }) =>
      id
        ? unwrap(
            api.PATCH("/api/v1/resources/{resource_id}", {
              params: { path: { resource_id: id } },
              body: { name: body.name, sensitivity: body.sensitivity, environment: body.environment, data_classes: body.data_classes, project_id: body.project_id },
            }),
          )
        : unwrap(api.POST("/api/v1/resources", { body })),
    [qk.resources],
  );
}

export function useDeleteResource() {
  return useInvalidating(
    (id: string) => unwrap(api.DELETE("/api/v1/resources/{resource_id}", { params: { path: { resource_id: id } } })),
    [qk.resources],
  );
}
