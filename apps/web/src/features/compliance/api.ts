"use client";

import { useQuery } from "@tanstack/react-query";

import { api, unwrap } from "@/lib/api/client";
import { qk, STALE } from "@/lib/query-keys";
import { obj } from "@/lib/read";

export function useComplianceReport() {
  return useQuery({
    queryKey: qk.compliance,
    queryFn: async () => obj(await unwrap(api.GET("/api/v1/compliance/report"))),
    staleTime: STALE.config,
  });
}
