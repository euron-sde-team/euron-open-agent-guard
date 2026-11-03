"use client";

import { ChevronRightIcon, FileDownIcon, ScrollTextIcon, ShieldCheckIcon, ShieldXIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { Hint } from "@/components/hint";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono, shortHash } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface, SurfaceHeader } from "@/components/surface";
import { TableSkeleton } from "@/components/table-skeleton";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Input } from "@/components/ui/input";
import { useNow } from "@/hooks/use-now";
import { download } from "@/lib/api/client";
import { errorMessage } from "@/lib/api/errors";
import type { AuditEntry } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatDateTime, formatNumber, formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";
import { obj, str } from "@/lib/read";

import { useAuditLog, useCheckpoints, useVerifyChain } from "../api";

function useDebounced(value: string, ms = 300): string {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function Row({ e, now }: { e: AuditEntry; now: Date }) {
  const [open, setOpen] = React.useState(false);
  return (
    <li>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="grid w-full grid-cols-[16px_minmax(0,1fr)_auto] items-center gap-3 px-5 py-2.5 text-left hover:bg-muted/50 focus-visible:bg-muted focus-visible:outline-none sm:grid-cols-[16px_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1fr)_140px]"
      >
        <ChevronRightIcon className={cn("size-4 text-subtle transition-transform", open && "rotate-90")} aria-hidden />
        <span className="min-w-0">
          <span className="block truncate font-mono text-[12.5px] font-medium">{e.action}</span>
          <span className="block truncate text-[11.5px] text-subtle sm:hidden">{e.actor_name ?? e.actor_type}</span>
        </span>
        <span className="hidden min-w-0 truncate text-[12.5px] sm:block">
          {e.actor_name ?? e.actor_id ?? "system"} <span className="text-subtle">({humanize(e.actor_type)})</span>
        </span>
        <span className="hidden min-w-0 truncate text-[12.5px] text-muted-foreground sm:block">{e.target_type ? `${humanize(e.target_type)} ${e.target_id ? e.target_id.slice(0, 8) : ""}` : "None"}</span>
        <span className="text-right text-[12px] whitespace-nowrap text-muted-foreground" title={formatDateTime(e.at)}>
          {e.seq != null ? <span className="mr-2 font-mono text-subtle">#{e.seq}</span> : <Chip className="mr-2">unsealed</Chip>}
          {formatRelative(e.at, now)}
        </span>
      </button>
      {open && (
        <div className="space-y-3 bg-muted/30 px-5 py-4 sm:pl-12">
          <KeyValues
            columns={3}
            items={[
              { label: "Record id", value: <Mono>{String(e.id)}</Mono> },
              { label: "At", value: formatDateTime(e.at) },
              { label: "IP", value: e.ip ?? "None" },
              { label: "Target", value: e.target_id ? <Mono>{e.target_id}</Mono> : "None" },
              { label: "Hash", value: e.hash ? <Mono title={e.hash}>{shortHash(e.hash, 16, 8)}</Mono> : "Not sealed yet" },
              { label: "Previous hash", value: e.prev_hash ? <Mono title={e.prev_hash}>{shortHash(e.prev_hash, 16, 8)}</Mono> : "None" },
            ]}
          />
          {e.details && Object.keys(e.details).length > 0 && <JsonView value={e.details} label="Details" maxHeight={260} />}
        </div>
      )}
    </li>
  );
}

function VerifyPanel() {
  const verify = useVerifyChain();
  const checkpoints = useCheckpoints();
  const r = verify.data;
  return (
    <div className="space-y-4">
      <Surface>
        <SurfaceHeader title="Verify the chain" titleExtra={<Hint term="auditChain" />} description="Recomputes every hash and checks the signed checkpoints." />
        <div className="space-y-3 px-5 pb-5">
          <Button onClick={() => verify.mutate(undefined, { onError: (e) => toast.error(errorMessage(e)) })} disabled={verify.isPending}>
            <ShieldCheckIcon />
            {verify.isPending ? "Verifying..." : "Verify chain"}
          </Button>
          {r && (
            <div className={cn("space-y-2 rounded-xl p-3", r.ok ? "bg-primary-soft" : "bg-danger-soft")} aria-live="polite">
              <div className={cn("flex items-center gap-2 text-[13.5px] font-semibold", r.ok ? "text-primary" : "text-danger")}>
                {r.ok ? <ShieldCheckIcon className="size-4" /> : <ShieldXIcon className="size-4" />}
                {r.ok ? "The chain is intact" : `${r.problems.length} problem${r.problems.length === 1 ? "" : "s"} found`}
              </div>
              <div className="text-[12.5px] text-muted-foreground">
                {formatNumber(r.checked)} records and {formatNumber(r.checkpoints_checked)} checkpoints checked. Head #{r.head_seq} <Mono title={r.head_hash}>{shortHash(r.head_hash, 12, 6)}</Mono>.
                {r.unsealed > 0 && ` ${formatNumber(r.unsealed)} newer records are not sealed yet (the worker seals them).`}
              </div>
              {r.problems.length > 0 && (
                <ul className="space-y-1">
                  {r.problems.slice(0, 20).map((p, i) => {
                    const o = obj(p);
                    return (
                      <li key={i} className="rounded-md bg-card/70 px-2.5 py-1.5 font-mono text-[12px] text-danger">
                        {str(o.seq) ?? (o.seq != null ? `#${String(o.seq)}` : "")} {str(o.problem) ?? str(o.kind) ?? JSON.stringify(o)}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          )}
        </div>
      </Surface>
      <Surface>
        <SurfaceHeader title="Signed checkpoints" description="Ed25519 signatures over the chain head, exported to storage." />
        <QueryState
          query={checkpoints}
          loading={<TableSkeleton rows={3} cols={2} />}
          empty={(d) => d.length === 0}
          emptyState={<EmptyState compact icon={ScrollTextIcon} title="No checkpoints yet" description="The worker seals the chain and signs a checkpoint on a schedule." />}
        >
          {(items) => (
            <ul className="space-y-1 px-3 pb-4">
              {items.map((c) => (
                <li key={c.id} className="rounded-lg px-2 py-1.5 text-[12.5px] hover:bg-muted/50">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">#{c.seq}</span>
                    <span className="text-subtle">{formatDateTime(c.at)}</span>
                  </div>
                  <div className="truncate text-[11.5px] text-muted-foreground">
                    head <Mono title={c.head_hash}>{shortHash(c.head_hash, 12, 6)}</Mono> · key {c.kid}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      </Surface>
    </div>
  );
}

export function AuditScreen() {
  const [action, setAction] = React.useState("");
  const [actor, setActor] = React.useState("");
  const [target, setTarget] = React.useState("");
  const filters = { action: useDebounced(action.trim()), actor: useDebounced(actor.trim()), target_id: useDebounced(target.trim()) };
  const q = useAuditLog(filters);
  const now = useNow(60_000);
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  const filtered = !!(filters.action || filters.actor || filters.target_id);
  return (
    <>
      <PageHeader
        title="Audit logs"
        description="Every decision and every administrative change, as an append-only, hash-chained record. The database refuses edits and deletes."
        actions={
          <Button variant="outline" onClick={() => download("/api/v1/audit-logs/export", "agentguard-audit.jsonl").catch((e) => toast.error(errorMessage(e)))}>
            <FileDownIcon />
            Export JSON lines
          </Button>
        }
      />
      <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Surface className="min-w-0">
          <div className="grid gap-2 px-5 pt-4 pb-3 sm:grid-cols-3">
            <Input aria-label="Action prefix" className="font-mono text-[12.5px]" placeholder="Action prefix: agent." value={action} onChange={(e) => setAction(e.target.value)} />
            <Input aria-label="Actor" placeholder="Actor: omar@kestrel.example" value={actor} onChange={(e) => setActor(e.target.value)} />
            <Input aria-label="Target id" className="font-mono text-[12.5px]" placeholder="Target id" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          {q.isPending ? (
            <TableSkeleton rows={8} cols={4} />
          ) : q.isError ? (
            <ErrorState compact error={q.error} title="Could not load the audit log" onRetry={() => void q.refetch()} />
          ) : !items.length ? (
            <EmptyState
              compact
              icon={ScrollTextIcon}
              title={filtered ? "No records match" : "No audit records yet"}
              description={filtered ? "The action filter matches a prefix (agent. finds agent.suspend). Clear the filters to see everything." : "Every sign-in, change and decision is recorded here."}
              action={
                filtered ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setAction("");
                      setActor("");
                      setTarget("");
                    }}
                  >
                    Clear filters
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <>
              <div className="hidden grid-cols-[16px_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1fr)_140px] gap-3 px-5 pb-2 text-[11px] font-semibold tracking-wide text-subtle uppercase sm:grid">
                <span />
                <span>Action</span>
                <span>Actor</span>
                <span>Target</span>
                <span className="text-right">When</span>
              </div>
              <ul className="divide-y divide-hairline">
                {items.map((e) => (
                  <Row key={e.id} e={e} now={now} />
                ))}
              </ul>
              {q.hasNextPage && (
                <div className="flex justify-center py-3">
                  <Button variant="ghost" size="sm" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
                    {q.isFetchingNextPage ? "Loading..." : "Load older records"}
                  </Button>
                </div>
              )}
            </>
          )}
        </Surface>
        <VerifyPanel />
      </div>
    </>
  );
}
