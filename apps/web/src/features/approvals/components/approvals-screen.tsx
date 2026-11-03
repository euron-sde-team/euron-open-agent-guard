"use client";

import { CheckCheckIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { SeverityChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Stat } from "@/components/stat";
import { Surface } from "@/components/surface";
import { Button, buttonVariants } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNow } from "@/hooks/use-now";
import { formatNumber, formatRelative } from "@/lib/format";

import { useApprovalCounts, useApprovals } from "../api";
import { ExpiryChip, ParamsPreview } from "./approval-bits";

const TABS = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "executed", label: "Executed" },
  { value: "rejected", label: "Rejected" },
  { value: "changes_requested", label: "Changes requested" },
  { value: "expired", label: "Expired" },
  { value: "", label: "All" },
];

export function ApprovalsScreen() {
  const [status, setStatus] = React.useState("pending");
  const counts = useApprovalCounts();
  const list = useApprovals(status);
  const now = useNow(60_000);
  const c = counts.data;

  return (
    <>
      <PageHeader
        title="Approvals"
        description="Actions held for a person. Each one is bound to a hash of its exact parameters: what you approve is exactly what runs, and AgentGuard re-checks policy before it does."
      />
      <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Waiting for a person" value={formatNumber(c?.pending)} tone={c?.pending ? "warn" : "default"} loading={counts.isPending} />
        <Stat label="Approved, 24 hours" value={formatNumber(c?.approved_24h)} loading={counts.isPending} />
        <Stat label="Rejected, 24 hours" value={formatNumber(c?.rejected_24h)} loading={counts.isPending} />
        <Stat label="Expired, 24 hours" value={formatNumber(c?.expired_24h)} loading={counts.isPending} />
      </div>
      <Tabs value={status} onValueChange={(v) => setStatus(String(v))} className="mb-4">
        <div className="no-scrollbar -mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <TabsList className="flex-nowrap">
            {TABS.map((t) => (
              <TabsTrigger key={t.value || "all"} value={t.value}>
                {t.label}
                {t.value === "pending" && !!c?.pending && <span className="tabular rounded-full bg-warning-soft px-1.5 text-[11px] font-semibold text-warning">{c.pending}</span>}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
      </Tabs>
      <Surface>
        <QueryState
          query={list}
          errorTitle="Could not load approvals"
          empty={(d) => d.length === 0}
          emptyState={
            <EmptyState
              icon={CheckCheckIcon}
              title={status === "pending" ? "Nothing is waiting for you" : "No approvals here"}
              description={
                status === "pending"
                  ? "When a policy rule says require_approval, the action stops here until a person decides. Write one in the policy builder."
                  : "Approvals in this state appear here, with their votes and history."
              }
              action={
                status === "pending" ? (
                  <Link href="/policies" className={buttonVariants({ variant: "outline", size: "sm" })}>
                    Open the policy builder
                  </Link>
                ) : (
                  <Button variant="outline" size="sm" onClick={() => setStatus("")}>
                    Show all approvals
                  </Button>
                )
              }
            />
          }
        >
          {(items) => (
            <ul className="divide-y divide-hairline">
              {items.map((a) => (
                <li key={a.id}>
                  <Link
                    href={`/approvals/${a.id}`}
                    className="flex flex-col gap-2 px-5 py-4 transition-colors hover:bg-muted/50 focus-visible:bg-muted focus-visible:outline-none sm:flex-row sm:items-center sm:gap-4"
                  >
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[13px] font-semibold">
                          {a.tool}.{a.action}
                        </span>
                        {a.resource && <span className="font-mono text-[12px] text-subtle">on {a.resource}</span>}
                      </div>
                      <div className="text-[13px] text-muted-foreground">{a.reason}</div>
                      <ParamsPreview params={a.params_preview} />
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-2 sm:flex-col sm:items-end">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <SeverityChip level={a.risk_level} prefix="Risk" />
                        <StatusChip kind="approval" status={a.status} />
                        <ExpiryChip expiresAt={a.expires_at} status={a.status} />
                      </div>
                      <div className="text-[12px] text-subtle">
                        {a.agent || "agent"}
                        {a.on_behalf_of ? ` for ${a.on_behalf_of}` : ""} · {formatRelative(a.created_at, now)}
                      </div>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      </Surface>
    </>
  );
}
