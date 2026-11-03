"use client";

import { BoxIcon, CircleCheckIcon, CircleXIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { Mono, shortHash } from "@/components/kv";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { buttonVariants } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { SimpleSelect } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useNow } from "@/hooks/use-now";
import { cn } from "@/lib/cn";
import { formatBytes, formatMs, formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";
import { num, obj } from "@/lib/read";

import { useSandboxHealth, useSandboxSessions } from "../api";

function Health() {
  const q = useSandboxHealth();
  if (q.isPending) return <Skeleton className="mb-4 h-16 rounded-[14px]" />;
  const ok = q.data?.reachable;
  return (
    <Surface className={cn("mb-4 flex items-center gap-3 px-5 py-4")}>
      <span className={cn("flex size-9 items-center justify-center rounded-xl", ok ? "bg-primary-soft text-primary" : "bg-danger-soft text-danger")}>
        {ok ? <CircleCheckIcon className="size-5" /> : <CircleXIcon className="size-5" />}
      </span>
      <div className="min-w-0">
        <div className="text-[13.5px] font-semibold">{q.isError ? "Could not check the sandbox" : ok ? "Sandbox service is reachable" : "Sandbox service is not reachable"}</div>
        <div className="truncate text-[12.5px] text-muted-foreground">
          {q.isError ? "Retry in a moment." : ok ? q.data?.detail || "Untrusted code runs in unprivileged nsjail with no network unless the egress proxy is granted." : `${q.data?.detail || "No answer"}. Sandbox tools are denied until it is back (fail closed).`}
        </div>
      </div>
    </Surface>
  );
}

export function SandboxesScreen() {
  const [verdict, setVerdict] = React.useState("");
  const q = useSandboxSessions(verdict);
  const now = useNow(60_000);
  return (
    <>
      <PageHeader title="Sandboxes" description="Every run of untrusted Python, Node.js or shell code: the limits it ran under, what it used and how it ended. The code itself is kept only as a hash." />
      <Health />
      <Surface>
        <div className="flex px-5 pt-4 pb-3">
          <SimpleSelect
            aria-label="Filter by verdict"
            className="sm:w-48"
            value={verdict}
            onValueChange={setVerdict}
            options={[
              { value: "", label: "Every verdict" },
              { value: "ok", label: "Completed" },
              { value: "nonzero_exit", label: "Non-zero exit" },
              { value: "error", label: "Error" },
              { value: "timeout", label: "Timed out" },
              { value: "killed", label: "Killed" },
              { value: "oom", label: "Out of memory" },
            ]}
          />
        </div>
        <QueryState
          query={q}
          errorTitle="Could not load sandbox sessions"
          empty={(d) => d.length === 0}
          emptyState={
            <EmptyState
              icon={BoxIcon}
              title={verdict ? "No sessions with this verdict" : "No sandbox runs yet"}
              description="Register a sandbox tool and let an agent execute code through AgentGuard. Each run is recorded here."
              action={
                <Link href="/tools?register=1" className={buttonVariants({ size: "sm", variant: "outline" })}>
                  Register a sandbox tool
                </Link>
              }
            />
          }
        >
          {(items) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Run</TableHead>
                  <TableHead className="hidden md:table-cell">Network</TableHead>
                  <TableHead className="hidden lg:table-cell">CPU / wall</TableHead>
                  <TableHead className="hidden lg:table-cell">Memory</TableHead>
                  <TableHead className="hidden sm:table-cell">Exit</TableHead>
                  <TableHead className="text-right">When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((s) => {
                  const limits = obj(s.limits);
                  const memLimit = num(limits.memory_mb);
                  return (
                    <TableRow key={s.id}>
                      <TableCell>
                        <StatusChip kind="sandbox" status={s.verdict} />
                      </TableCell>
                      <TableCell>
                        <div className="text-[13px]">
                          <span className="font-medium">{s.agent ?? "unknown"}</span> <span className="font-mono text-[12px] text-muted-foreground">{s.tool}</span> <Chip>{humanize(s.language)}</Chip>
                        </div>
                        <div className="text-[11.5px] text-subtle">
                          sha256 <Mono title={s.code_sha256}>{shortHash(s.code_sha256, 10, 4)}</Mono> · {formatBytes(s.code_bytes)}
                        </div>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <Chip tone={s.network === "none" ? "neutral" : "info"}>{s.network === "none" ? "No network" : "Egress proxy"}</Chip>
                      </TableCell>
                      <TableCell className="tabular hidden text-muted-foreground lg:table-cell">
                        {formatMs(s.cpu_ms)} / {formatMs(s.wall_ms)}
                        {num(limits.wall_s) != null && <div className="text-[11px] text-subtle">limit {num(limits.cpu_s)} s / {num(limits.wall_s)} s</div>}
                      </TableCell>
                      <TableCell className="tabular hidden text-muted-foreground lg:table-cell">
                        {formatBytes(s.memory_kb * 1024)}
                        {memLimit != null && <div className="text-[11px] text-subtle">limit {memLimit} MB</div>}
                      </TableCell>
                      <TableCell className="tabular hidden sm:table-cell">{s.exit_code ?? (s.signal != null ? `signal ${s.signal}` : "none")}</TableCell>
                      <TableCell className="text-right whitespace-nowrap text-muted-foreground">{formatRelative(s.started_at, now)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </QueryState>
      </Surface>
    </>
  );
}
