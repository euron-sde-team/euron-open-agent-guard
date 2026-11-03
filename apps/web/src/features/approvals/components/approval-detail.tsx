"use client";

import { ArrowLeftIcon, CheckIcon, CircleDotIcon, ClockIcon, MessageSquareWarningIcon, TimerOffIcon, UndoIcon, XIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { Hint } from "@/components/hint";
import { JsonView } from "@/components/json-view";
import { KeyValues, Mono, shortHash } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { ReasonDialog } from "@/components/reason-dialog";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Chip } from "@/components/ui/chip";
import { Textarea } from "@/components/ui/input";
import { FieldError, Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { ApprovalDetail } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatDateTime, formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";
import { obj, str } from "@/lib/read";

import { useApproval, useApprovalAction, type VoteAction } from "../api";
import { ExpiryChip, stagesOf, stageText } from "./approval-bits";

function VotePanel({ a }: { a: ApprovalDetail }) {
  const act = useApprovalAction(a.id);
  const [comment, setComment] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<VoteAction | null>(null);
  const why = a.can_vote ? null : a.why_not || "You cannot vote on this request.";

  function vote(action: VoteAction) {
    if ((action === "reject" || action === "request-changes") && !comment.trim()) {
      setError(action === "reject" ? "Say why you reject it: the agent receives this reason." : "Say what should change: the agent receives this comment.");
      return;
    }
    setError(null);
    setBusy(action);
    act.mutate(
      { action, comment: comment.trim() },
      {
        onSuccess: (r) => {
          setComment("");
          toast.success(
            action === "approve"
              ? r.status === "approved" || r.status === "executed"
                ? "Approved. The exact parameters you saw may now run, once."
                : "Your approval is recorded. The next stage needs another person."
              : action === "reject"
                ? "Rejected. The agent receives your reason."
                : "Changes requested. The agent receives your comment.",
          );
        },
        onError: (e) => toast.error(errorMessage(e)),
        onSettled: () => setBusy(null),
      },
    );
  }

  return (
    <Surface>
      <SurfaceHeader title="Your decision" description="Approve only what you see above. Changing any parameter makes it a new request." />
      <div className="space-y-3 px-5 pb-5">
        <div className="space-y-1.5">
          <Label htmlFor="vote-comment">Comment</Label>
          <Textarea
            id="vote-comment"
            value={comment}
            disabled={!a.can_vote}
            placeholder="Required to reject or request changes"
            onChange={(e) => setComment(e.target.value)}
            aria-invalid={!!error || undefined}
          />
          {error && <FieldError>{error}</FieldError>}
        </div>
        <div className="flex flex-wrap gap-2">
          <GatedButton need="vote" reason={why} onClick={() => vote("approve")} disabled={act.isPending}>
            <CheckIcon />
            {busy === "approve" ? "Approving..." : "Approve"}
          </GatedButton>
          <GatedButton need="vote" reason={why} variant="destructive-soft" onClick={() => vote("reject")} disabled={act.isPending}>
            <XIcon />
            {busy === "reject" ? "Rejecting..." : "Reject"}
          </GatedButton>
          <GatedButton need="vote" reason={why} variant="outline" onClick={() => vote("request-changes")} disabled={act.isPending}>
            <MessageSquareWarningIcon />
            Request changes
          </GatedButton>
        </div>
        {why && <p className="text-[12.5px] text-muted-foreground">{why}</p>}
      </div>
    </Surface>
  );
}

function OfficerActions({ a }: { a: ApprovalDetail }) {
  const act = useApprovalAction(a.id);
  const [open, setOpen] = React.useState<"expire" | "revoke" | null>(null);
  const live = a.status === "pending" || a.status === "approved";
  if (!live) return null;
  return (
    <>
      {a.status === "pending" && (
        <GatedButton need="write" variant="outline" size="sm" onClick={() => setOpen("expire")}>
          <TimerOffIcon />
          Expire now
        </GatedButton>
      )}
      <GatedButton need="write" variant="destructive-soft" size="sm" onClick={() => setOpen("revoke")}>
        <UndoIcon />
        Emergency revoke
      </GatedButton>
      <ReasonDialog
        open={!!open}
        onOpenChange={(o) => !o && setOpen(null)}
        title={open === "expire" ? "Expire this request now?" : "Revoke this approval?"}
        description={
          open === "expire"
            ? "It can no longer be approved or run. The agent has to ask again."
            : "Even if it was approved, it can no longer run. Use this when something changed after the vote."
        }
        confirmLabel={open === "expire" ? "Expire" : "Revoke"}
        required={open === "revoke"}
        pending={act.isPending}
        onConfirm={(reason) =>
          open &&
          act.mutate(
            { action: open, comment: reason },
            {
              onSuccess: () => {
                toast.success(open === "expire" ? "Request expired." : "Approval revoked.");
                setOpen(null);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </>
  );
}

function Stages({ a }: { a: ApprovalDetail }) {
  const stages = stagesOf(a.requirement);
  const votes = a.votes ?? [];
  const final = !["pending"].includes(a.status);
  return (
    <ol className="space-y-2">
      {stages.map((s, i) => {
        const stageVotes = votes.filter((v) => v.stage === i);
        const approvals = stageVotes.filter((v) => v.vote === "approve").length;
        const current = a.status === "pending" && a.current_stage === i;
        const done = approvals >= s.count || (final && i < a.current_stage);
        return (
          <li key={i} className={cn("rounded-xl p-3", current ? "bg-warning-soft/60" : "bg-muted/60")}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-[13px] font-medium">
                {done ? <CheckIcon className="size-4 text-primary" /> : current ? <CircleDotIcon className="size-4 text-warning" /> : <ClockIcon className="size-4 text-subtle" />}
                Stage {i + 1}: {stageText(s)}
              </div>
              <span className="tabular text-[12px] text-muted-foreground">
                {approvals} of {s.count}
              </span>
            </div>
            {stageVotes.length > 0 && (
              <ul className="mt-2 space-y-1 pl-6">
                {stageVotes.map((v, n) => (
                  <li key={n} className="text-[12.5px]">
                    <Chip tone={v.vote === "approve" ? "success" : v.vote === "reject" ? "danger" : "info"}>{humanize(v.vote)}</Chip>{" "}
                    <span className="font-medium">{v.user || "someone"}</span> <span className="text-subtle">{formatDateTime(v.at)}</span>
                    {v.comment && <div className="mt-0.5 text-muted-foreground">&ldquo;{v.comment}&rdquo;</div>}
                  </li>
                ))}
              </ul>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function History({ a }: { a: ApprovalDetail }) {
  const now = useNow(60_000);
  const items = a.history ?? [];
  return (
    <ol className="relative space-y-4 pl-5 before:absolute before:top-1.5 before:bottom-1.5 before:left-[5px] before:w-px before:bg-hairline">
      {items.map((h, i) => {
        const d = obj(h.details);
        const note = str(d.comment) || str(d.reason) || "";
        return (
          <li key={i} className="relative">
            <span className="absolute top-1.5 -left-5 size-2.5 rounded-full bg-primary ring-4 ring-card" aria-hidden />
            <div className="text-[13px]">
              <span className="font-medium">{humanize(h.event)}</span> <span className="text-muted-foreground">by {h.actor}</span>
            </div>
            <div className="text-[11.5px] text-subtle" title={formatDateTime(h.at)}>
              {formatRelative(h.at, now)}
            </div>
            {note && <div className="mt-0.5 text-[12.5px] text-muted-foreground">{note}</div>}
          </li>
        );
      })}
    </ol>
  );
}

export function ApprovalDetailScreen({ id }: { id: string }) {
  const q = useApproval(id);
  if (q.isPending)
    return (
      <div className="space-y-4" aria-busy>
        <Skeleton className="h-10 w-full max-w-96" />
        <Skeleton className="h-64" />
      </div>
    );
  if (q.isError)
    return (
      <Surface>
        <ErrorState error={q.error} title="Could not load this approval" onRetry={() => void q.refetch()} />
      </Surface>
    );
  const a = q.data;
  const params = a.params ?? a.params_preview;
  return (
    <>
      <Link href="/approvals" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Approvals
      </Link>
      <PageHeader
        title={
          <span className="font-mono">
            {a.tool}.{a.action}
          </span>
        }
        eyebrow={
          <div className="flex flex-wrap items-center gap-1.5">
            <StatusChip kind="approval" status={a.status} />
            <SeverityChip level={a.risk_level} prefix="Risk" />
            <ExpiryChip expiresAt={a.expires_at} status={a.status} />
          </div>
        }
        description={a.reason}
        actions={<OfficerActions a={a} />}
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Surface>
            <SurfaceHeader
              title="Exact parameters"
              titleExtra={<Hint term="actionHash" />}
              description="This is precisely what will run if approved. Any change creates a new request."
            />
            <div className="space-y-4 px-5 pb-5">
              <JsonView value={params} label="Parameters" />
              <KeyValues
                columns={2}
                items={[
                  { label: "Agent", value: a.agent ? <Link className="text-primary hover:underline" href={`/agents/${a.agent_id}`}>{a.agent}</Link> : a.agent_id },
                  { label: "On behalf of", value: a.on_behalf_of ?? "Nobody", hidden: !a.on_behalf_of },
                  { label: "Resource", value: a.resource ? <Mono>{a.resource}</Mono> : "None" },
                  { label: "Policy", value: a.policy_name ? `${a.policy_name} v${a.policy_version ?? "?"}` : "None" },
                  { label: "Requested", value: formatDateTime(a.created_at) },
                  { label: "Expires", value: formatDateTime(a.expires_at) },
                  { label: "Runs by", value: str(obj(a.requirement).execute) === "agent" ? "The agent, with the approval id" : "AgentGuard, through the trusted path" },
                  { label: "Action hash", value: <Mono>{a.action_hash}</Mono> },
                ]}
              />
            </div>
          </Surface>
          {a.status === "pending" && <VotePanel a={a} />}
          {(a.decision_comment || a.decided_at) && (
            <Surface className="p-5">
              <div className="text-[13px] font-semibold">Outcome</div>
              <p className="mt-1 text-[13px] text-muted-foreground">
                {humanize(a.status)} {a.decided_at ? formatDateTime(a.decided_at) : ""}
                {a.executed_at ? `, executed ${formatDateTime(a.executed_at)}` : ""}.
              </p>
              {a.decision_comment && <p className="mt-1 text-[13px]">&ldquo;{a.decision_comment}&rdquo;</p>}
              {a.result && Object.keys(a.result).length > 0 && <JsonView className="mt-3" value={a.result} label="Result" />}
            </Surface>
          )}
        </div>
        <div className="min-w-0 space-y-4">
          <Surface>
            <SurfaceHeader title="Who may approve" description={obj(a.requirement).forbid_requester === false ? "Stages run in order." : "Stages run in order. The requester never approves their own request."} />
            <div className="px-5 pb-5">
              <Stages a={a} />
            </div>
          </Surface>
          <Surface>
            <SurfaceHeader title="History" description="Append-only: nothing here can be edited." />
            <div className="px-5 pb-5">
              <History a={a} />
            </div>
          </Surface>
          {a.decision_id && (
            <p className="px-1 text-[12px] text-subtle">
              Original decision <Mono title={a.decision_id}>{shortHash(a.decision_id, 8, 4)}</Mono>
            </p>
          )}
        </div>
      </div>
    </>
  );
}
