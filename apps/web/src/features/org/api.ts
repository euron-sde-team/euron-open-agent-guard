"use client";

import { useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { InvitationCreated, LimitIn, OidcIn, OrgSettingsUpdate, ProjectIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useSettings() {
  return useQuery({ queryKey: qk.settings, queryFn: () => unwrap(api.GET("/api/v1/settings")), staleTime: STALE.config });
}

export function useUpdateSettings() {
  return useInvalidating((body: OrgSettingsUpdate) => unwrap(api.PATCH("/api/v1/settings", { body })), [qk.settings, qk.compliance]);
}

export function useKillSwitch() {
  return useInvalidating(
    (body: { active: boolean; reason: string }) => unwrap(api.PUT("/api/v1/kill-switch", { body })),
    [qk.settings, qk.metrics],
  );
}

export function useOrg() {
  return useQuery({ queryKey: qk.org, queryFn: () => unwrap(api.GET("/api/v1/org")), staleTime: STALE.static });
}

export function useProjects() {
  return useQuery({ queryKey: qk.projects, queryFn: () => unwrap(api.GET("/api/v1/projects")), staleTime: STALE.config });
}

export function useCreateProject() {
  return useInvalidating((body: ProjectIn) => unwrap(api.POST("/api/v1/projects", { body })), [qk.projects]);
}

export function useUpdateProject() {
  return useInvalidating(
    ({ id, ...body }: { id: string; name?: string; description?: string; environment?: ProjectIn["environment"] }) =>
      unwrap(api.PATCH("/api/v1/projects/{project_id}", { params: { path: { project_id: id } }, body })),
    [qk.projects],
  );
}

export function useLimits() {
  return useQuery({ queryKey: qk.limits, queryFn: () => unwrap(api.GET("/api/v1/limits")), staleTime: STALE.config });
}

export function useSaveLimit() {
  return useInvalidating(
    ({ id, body }: { id?: string; body: LimitIn }) =>
      id
        ? unwrap(api.PUT("/api/v1/limits/{limit_id}", { params: { path: { limit_id: id } }, body }))
        : unwrap(api.POST("/api/v1/limits", { body })),
    [qk.limits],
  );
}

export function useDeleteLimit() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/limits/{limit_id}", { params: { path: { limit_id: id } } })), [qk.limits]);
}

export function useUsers() {
  return useQuery({ queryKey: qk.users, queryFn: () => unwrap(api.GET("/api/v1/users")), staleTime: STALE.config });
}

export function useUpdateUser() {
  return useInvalidating(
    ({ id, ...body }: { id: string; role?: "auditor" | "reviewer" | "security_officer" | "org_admin"; disabled?: boolean }) =>
      unwrap(api.PATCH("/api/v1/users/{user_id}", { params: { path: { user_id: id } }, body })),
    [qk.users],
  );
}

export function useInvitations(enabled = true) {
  return useQuery({ queryKey: qk.invitations, queryFn: () => unwrap(api.GET("/api/v1/invitations")), staleTime: STALE.config, enabled });
}

export function useInvite() {
  return useInvalidating(
    (body: { email: string; role: "auditor" | "reviewer" | "security_officer" | "org_admin" }): Promise<InvitationCreated> =>
      unwrap(api.POST("/api/v1/invitations", { body })),
    [qk.invitations],
  );
}

export function useRevokeInvitation() {
  return useInvalidating(
    (id: string) => unwrap(api.DELETE("/api/v1/invitations/{invitation_id}", { params: { path: { invitation_id: id } } })),
    [qk.invitations],
  );
}

export function useOidc(enabled = true) {
  return useQuery({ queryKey: qk.oidc, queryFn: () => unwrap(api.GET("/api/v1/auth/oidc")), staleTime: STALE.config, enabled });
}

export function useSaveOidc() {
  return useInvalidating((body: OidcIn) => unwrap(api.PUT("/api/v1/auth/oidc", { body })), [qk.oidc]);
}

/** Deployment status; the API only answers org admins. */
export function useSystem(enabled = true) {
  return useQuery({ queryKey: qk.system, queryFn: () => unwrap(api.GET("/api/v1/system")), staleTime: STALE.config, retry: false, enabled });
}
