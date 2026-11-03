"use client";

import { useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import type { McpServerIn, ToolIn } from "@/lib/api/types";
import { useInvalidating } from "@/lib/mutation";
import { qk, STALE } from "@/lib/query-keys";

export function useTools() {
  return useQuery({ queryKey: qk.tools, queryFn: () => unwrap(api.GET("/api/v1/tools")), staleTime: STALE.list });
}

export function useTool(id: string | null) {
  return useQuery({
    queryKey: qk.tool(id ?? ""),
    queryFn: () => unwrap(api.GET("/api/v1/tools/{tool_id}", { params: { path: { tool_id: id ?? "" } } })),
    enabled: !!id,
  });
}

export function useToolVersions(id: string | null) {
  return useQuery({
    queryKey: qk.toolVersions(id ?? ""),
    queryFn: () => unwrap(api.GET("/api/v1/tools/{tool_id}/versions", { params: { path: { tool_id: id ?? "" } } })),
    enabled: !!id,
  });
}

export function useRegisterTool() {
  return useInvalidating((body: ToolIn) => unwrap(api.POST("/api/v1/tools/register", { body })), [qk.tools]);
}

export function useUpdateTool() {
  return useInvalidating(
    ({ id, body }: { id: string; body: { status?: string; risk?: string; sensitive?: boolean; external?: boolean; description?: string } }) =>
      unwrap(api.PATCH("/api/v1/tools/{tool_id}", { params: { path: { tool_id: id } }, body })),
    [qk.tools],
  );
}

export function useDeleteTool() {
  return useInvalidating((id: string) => unwrap(api.DELETE("/api/v1/tools/{tool_id}", { params: { path: { tool_id: id } } })), [qk.tools]);
}

export function useGrantTool() {
  return useInvalidating(
    ({ id, body }: { id: string; body: { role: string; actions: string[]; resource: string; condition: string } }) =>
      unwrap(api.POST("/api/v1/tools/{tool_id}/permissions", { params: { path: { tool_id: id } }, body })),
    [qk.tools, qk.roles],
  );
}

export function useReviewTool() {
  return useInvalidating(
    ({ id, approve }: { id: string; approve: boolean }) =>
      unwrap(api.POST("/api/v1/tools/{tool_id}/review", { params: { path: { tool_id: id } }, body: { approve } })),
    [qk.tools, qk.mcpServers],
  );
}

export function useMcpServers() {
  return useQuery({ queryKey: qk.mcpServers, queryFn: () => unwrap(api.GET("/api/v1/mcp/servers")), staleTime: STALE.list });
}

export function useAddMcpServer() {
  return useInvalidating((body: McpServerIn) => unwrap(api.POST("/api/v1/mcp/servers", { body })), [qk.mcpServers, qk.tools]);
}

export function useMcpAction() {
  return useInvalidating<{ id: string; action: "discover" | "check" | "delete" }, unknown>(
    ({ id, action }) => {
      const path = { params: { path: { server_id: id } } };
      if (action === "discover") return unwrap(api.POST("/api/v1/mcp/servers/{server_id}/discover", path));
      if (action === "check") return unwrap(api.POST("/api/v1/mcp/servers/{server_id}/check", path));
      return unwrap(api.DELETE("/api/v1/mcp/servers/{server_id}", path));
    },
    [qk.mcpServers, qk.tools],
  );
}

export function useToggleMcpServer() {
  return useInvalidating(
    ({ id, enabled }: { id: string; enabled: boolean }) =>
      unwrap(api.PATCH("/api/v1/mcp/servers/{server_id}", { params: { path: { server_id: id } }, body: { enabled } })),
    [qk.mcpServers],
  );
}
