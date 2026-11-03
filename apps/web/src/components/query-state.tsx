"use client";

import type { UseQueryResult } from "@tanstack/react-query";
import * as React from "react";

import { ErrorState } from "@/components/error-state";
import { TableSkeleton } from "@/components/table-skeleton";

/**
 * Loading, error and empty handling for one query, so every async view says what is
 * happening. `empty` decides when the data counts as empty; `emptyState` explains it.
 */
export function QueryState<T>({
  query,
  children,
  empty,
  emptyState,
  loading,
  errorTitle = "Could not load this",
}: {
  query: UseQueryResult<T>;
  children: (data: T) => React.ReactNode;
  empty?: (data: T) => boolean;
  emptyState?: React.ReactNode;
  loading?: React.ReactNode;
  errorTitle?: string;
}) {
  if (query.isPending) return <>{loading ?? <TableSkeleton />}</>;
  if (query.isError) return <ErrorState error={query.error} title={errorTitle} onRetry={() => void query.refetch()} compact />;
  if (empty?.(query.data) && emptyState) return <>{emptyState}</>;
  return <>{children(query.data)}</>;
}
