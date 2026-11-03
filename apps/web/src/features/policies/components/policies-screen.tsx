"use client";

import { FileCode2Icon, PlusIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { DecisionChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { buttonVariants } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { usePermissions } from "@/features/auth/api";
import { useNow } from "@/hooks/use-now";
import { formatRelative } from "@/lib/format";

import { usePolicies } from "../api";

export function PoliciesScreen() {
  const q = usePolicies();
  const router = useRouter();
  const now = useNow(60_000);
  const { can } = usePermissions();
  const newButton = can("write") ? (
    <Link href="/policies/new" className={buttonVariants()}>
      <PlusIcon />
      New policy
    </Link>
  ) : null;
  return (
    <>
      <PageHeader
        title="Policy builder"
        description="Deterministic YAML policies decide every action. Explicit deny wins at any level; with no matching rule the default is deny in enforce mode. Build visually or in YAML, test one request, simulate against history."
        actions={newButton}
      />
      <Surface>
        <QueryState
          query={q}
          errorTitle="Could not load policies"
          empty={(d) => d.length === 0}
          emptyState={
            <EmptyState
              icon={FileCode2Icon}
              title="No policies"
              description="Policies decide which actions are allowed, restricted, held for a person or denied."
              action={newButton}
            />
          }
        >
          {(items) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Policy</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden sm:table-cell">Version</TableHead>
                  <TableHead className="hidden md:table-cell">Rules</TableHead>
                  <TableHead className="hidden lg:table-cell">Decides</TableHead>
                  <TableHead className="hidden text-right md:table-cell">Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...items]
                  .sort((a, b) => Number(a.builtin) - Number(b.builtin) || a.name.localeCompare(b.name))
                  .map((p) => (
                    <TableRow key={p.id} className="cursor-pointer" onClick={() => router.push(`/policies/${p.id}`)}>
                      <TableCell className="max-w-[460px]">
                        <Link href={`/policies/${p.id}`} className="flex items-center gap-2 font-mono text-[13px] font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={(e) => e.stopPropagation()}>
                          {p.name}
                          {p.builtin && <Chip tone="info">Built in</Chip>}
                        </Link>
                        <div className="truncate text-[12px] text-muted-foreground">{p.description}</div>
                      </TableCell>
                      <TableCell>
                        <StatusChip kind="policy" status={p.status} />
                      </TableCell>
                      <TableCell className="tabular hidden text-muted-foreground sm:table-cell">
                        v{p.active_version ?? "none"}
                        {p.latest_version !== p.active_version && <span className="text-subtle"> (latest v{p.latest_version})</span>}
                      </TableCell>
                      <TableCell className="tabular hidden md:table-cell">{p.rules ?? 0}</TableCell>
                      <TableCell className="hidden lg:table-cell">
                        <div className="flex flex-wrap gap-1">
                          {(p.decisions ?? []).map((d) => (
                            <DecisionChip key={d} decision={d} tip={false} />
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="hidden text-right whitespace-nowrap text-muted-foreground md:table-cell">{formatRelative(p.updated_at, now)}</TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          )}
        </QueryState>
      </Surface>
    </>
  );
}
