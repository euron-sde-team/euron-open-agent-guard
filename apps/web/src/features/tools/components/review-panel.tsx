"use client";

import { CheckIcon, ShieldCheckIcon, XIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { prettyJson } from "@/components/json-view";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Chip } from "@/components/ui/chip";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/api/errors";
import type { Tool } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { diffLines, diffStats } from "@/lib/diff";
import { formatDateTime } from "@/lib/format";

import { useReviewTool, useToolVersions } from "../api";

function ToolDiff({ tool }: { tool: Tool }) {
  const versions = useToolVersions(tool.id);
  const review = useReviewTool();
  if (versions.isPending) return <Skeleton className="m-5 h-40" />;
  if (versions.isError) return <ErrorState compact error={versions.error} title="Could not load the versions" onRetry={() => void versions.refetch()} />;
  const list = versions.data;
  const current = list[0];
  const previous = list.find((v, i) => i > 0 && v.reviewed_at) ?? list[1];
  const lines = diffLines(prettyJson(previous?.definition ?? {}), prettyJson(current?.definition ?? {}));
  const stats = diffStats(lines);
  const decide = (approve: boolean) =>
    review.mutate(
      { id: tool.id, approve },
      {
        onSuccess: () => toast.success(approve ? `${tool.name} accepted: calls run again with the new definition.` : `${tool.name} refused: it stays blocked.`),
        onError: (e) => toast.error(errorMessage(e)),
      },
    );
  return (
    <div className="space-y-3 px-5 pb-5">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <Chip tone="success">+{stats.added}</Chip>
        <Chip tone="danger">-{stats.removed}</Chip>
        {current && <span>changed {formatDateTime(current.seen_at)}</span>}
        {previous && <span>compared with the version seen {formatDateTime(previous.seen_at)}</span>}
      </div>
      <pre className="code-block max-h-[420px] !p-0 !whitespace-pre-wrap" aria-label={`Changes to ${tool.name}`}>
        {lines.map((l, i) => (
          <div key={i} className={cn("px-3 pl-7 -indent-4 break-words", l.kind === "add" && "diff-add", l.kind === "del" && "diff-del")}>
            <span className="mr-2 inline-block w-3 text-white/40 select-none">{l.kind === "add" ? "+" : l.kind === "del" ? "-" : " "}</span>
            {l.text}
          </div>
        ))}
      </pre>
      <div className="flex flex-wrap gap-2">
        <GatedButton need="write" size="sm" disabled={review.isPending} onClick={() => decide(true)}>
          <CheckIcon />
          Accept the new definition
        </GatedButton>
        <GatedButton need="write" size="sm" variant="destructive-soft" disabled={review.isPending} onClick={() => decide(false)}>
          <XIcon />
          Refuse
        </GatedButton>
      </div>
    </div>
  );
}

/** Tools whose definition changed upstream (rug pull detection): held until a person reviews the diff. */
export function ReviewPanel({ tools }: { tools: Tool[] }) {
  const pending = tools.filter((t) => t.status === "pending_review");
  if (!pending.length)
    return (
      <Surface>
        <EmptyState
          icon={ShieldCheckIcon}
          title="Nothing to review"
          description="When an MCP server changes a tool's description or schema, AgentGuard holds the tool and shows the change here. A silent change is how a tool poisoning attack starts."
        />
      </Surface>
    );
  return (
    <div className="space-y-4">
      {pending.map((t) => (
        <Surface key={t.id}>
          <SurfaceHeader title={<span className="font-mono">{t.name}</span>} description="Calls to this tool are held until you accept or refuse the change. Read the description carefully: tool poisoning hides instructions there." />
          <ToolDiff tool={t} />
        </Surface>
      ))}
    </div>
  );
}
