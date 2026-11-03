"use client";

import { ActivityIcon } from "lucide-react";
import * as React from "react";

import { DecisionChip, SeverityChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { SimpleSelect } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/table-skeleton";
import { useNow } from "@/hooks/use-now";
import { formatMs, formatRelative } from "@/lib/format";
import { DECISIONS, decisionSpec, reasonLabel } from "@/lib/labels";

import { useDecisions, type DecisionFilters } from "../api";
import { DecisionSheet } from "./decision-sheet";

/** The decision log, keyset paginated, with an outcome filter and a detail sheet per row. */
export function DecisionsTable({ filters, showAgent = true, emptyText }: { filters: DecisionFilters; showAgent?: boolean; emptyText?: string }) {
  const [decision, setDecision] = React.useState("");
  const q = useDecisions({ ...filters, decision: decision || filters.decision });
  const [open, setOpen] = React.useState<string | null>(null);
  const now = useNow(60_000);
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-2 px-5 pb-3">
        <SimpleSelect
          size="sm"
          aria-label="Filter by outcome"
          className="w-44"
          value={decision}
          onValueChange={setDecision}
          options={[{ value: "", label: "Every outcome" }, ...DECISIONS.map((d) => ({ value: d, label: decisionSpec(d).label }))]}
        />
      </div>
      {q.isPending ? (
        <TableSkeleton rows={6} cols={5} />
      ) : q.isError ? (
        <ErrorState compact error={q.error} title="Could not load decisions" onRetry={() => void q.refetch()} />
      ) : !items.length ? (
        <EmptyState
          compact
          icon={ActivityIcon}
          title="No decisions here"
          description={emptyText ?? "Each authorize, execute or MCP call becomes a decision with its reason, policy and risk."}
          action={decision ? <Button size="sm" variant="outline" onClick={() => setDecision("")}>Show every outcome</Button> : undefined}
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Outcome</TableHead>
                {showAgent && <TableHead>Agent</TableHead>}
                <TableHead>Action</TableHead>
                <TableHead className="hidden md:table-cell">Reason</TableHead>
                <TableHead className="hidden sm:table-cell">Risk</TableHead>
                <TableHead className="text-right">When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((d) => (
                <TableRow
                  key={d.id}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open decision ${d.tool}.${d.action}`}
                  className="cursor-pointer focus-visible:bg-muted focus-visible:outline-none"
                  onClick={() => setOpen(d.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setOpen(d.id);
                    }
                  }}
                >
                  <TableCell>
                    <DecisionChip decision={d.decision} tip={false} />
                  </TableCell>
                  {showAgent && <TableCell className="font-medium">{d.agent ?? "unknown"}</TableCell>}
                  <TableCell>
                    <div className="font-mono text-[12.5px]">
                      {d.tool}.{d.action}
                    </div>
                    {d.resource && <div className="max-w-[220px] truncate font-mono text-[11.5px] text-subtle">{d.resource}</div>}
                  </TableCell>
                  <TableCell className="hidden max-w-[320px] text-muted-foreground md:table-cell">
                    <div className="truncate">{reasonLabel(d.reason_code)}</div>
                    {d.policy_name && <div className="truncate text-[11.5px] text-subtle">{d.policy_name} v{d.policy_version}</div>}
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <SeverityChip level={d.risk_level} prefix={String(d.risk_score)} />
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap text-muted-foreground">
                    <div>{formatRelative(d.at, now)}</div>
                    <div className="text-[11px] text-subtle">{formatMs(d.latency_ms)}</div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {q.hasNextPage && (
            <div className="flex justify-center py-3">
              <Button variant="ghost" size="sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
                {q.isFetchingNextPage ? "Loading..." : "Load older decisions"}
              </Button>
            </div>
          )}
        </>
      )}
      <DecisionSheet id={open} onClose={() => setOpen(null)} />
    </>
  );
}
