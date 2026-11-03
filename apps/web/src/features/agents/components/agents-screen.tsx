"use client";

import { BotIcon, PlusIcon, SearchIcon, ShieldAlertIcon } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

import { StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { Chip } from "@/components/ui/chip";
import { Input } from "@/components/ui/input";
import { SimpleSelect } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useNow } from "@/hooks/use-now";
import type { Issued } from "@/lib/api/types";
import { formatNumber, formatRelative } from "@/lib/format";
import { frameworkLabel } from "@/lib/labels";

import { useAgents } from "../api";
import { CredentialDialog } from "./credential-dialog";
import { RegisterAgentDialog } from "./register-agent-dialog";

export function AgentsScreen() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [q, setQ] = React.useState("");
  const [registerOpen, setRegisterOpen] = React.useState(false);
  const [issued, setIssued] = React.useState<{ credential: Issued; signed: boolean } | null>(null);
  const now = useNow(60_000);
  React.useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 250);
    return () => clearTimeout(t);
  }, [search]);
  React.useEffect(() => {
    if (params.get("register") === "1") setRegisterOpen(true);
  }, [params]);
  const agents = useAgents({ status, q });
  const filtered = !!status || !!q;

  return (
    <>
      <PageHeader
        title="Agents"
        description="Every agent has its own identity, credentials, roles and network policy. Suspend or quarantine one and every action it tries is denied."
        actions={
          <GatedButton need="write" onClick={() => setRegisterOpen(true)}>
            <PlusIcon />
            Register agent
          </GatedButton>
        }
      />
      <Surface>
        <div className="flex flex-col gap-2 px-5 pt-4 pb-3 sm:flex-row sm:items-center">
          <div className="relative sm:w-72">
            <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" aria-hidden />
            <Input aria-label="Search agents" placeholder="Search by name or short name" className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <SimpleSelect
            aria-label="Filter by status"
            className="sm:w-44"
            value={status}
            onValueChange={setStatus}
            options={[
              { value: "", label: "Every status" },
              { value: "active", label: "Active" },
              { value: "suspended", label: "Suspended" },
              { value: "quarantined", label: "Quarantined" },
              { value: "revoked", label: "Revoked" },
            ]}
          />
        </div>
        <QueryState
          query={agents}
          errorTitle="Could not load agents"
          empty={(d) => d.length === 0}
          emptyState={
            filtered ? (
              <EmptyState compact icon={SearchIcon} title="No agent matches" description="Try another name, or clear the status filter." />
            ) : (
              <EmptyState
                icon={BotIcon}
                title="No agents yet"
                description="Register the first agent to give it an identity. Its SDK exchanges the credential for a short-lived token and asks AgentGuard before every action."
                action={
                  <GatedButton need="write" onClick={() => setRegisterOpen(true)}>
                    <PlusIcon />
                    Register your first agent
                  </GatedButton>
                }
              />
            )
          }
        >
          {(list) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden md:table-cell">Framework</TableHead>
                  <TableHead className="hidden lg:table-cell">Roles</TableHead>
                  <TableHead className="hidden text-right sm:table-cell">Decisions 24h</TableHead>
                  <TableHead className="hidden text-right sm:table-cell">Threats</TableHead>
                  <TableHead className="hidden text-right xl:table-cell">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => router.push(`/agents/${a.id}`)}>
                    <TableCell>
                      <Link href={`/agents/${a.id}`} className="group flex items-center gap-3 rounded-md focus-visible:outline-2 focus-visible:outline-ring" onClick={(e) => e.stopPropagation()}>
                        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary">
                          <BotIcon className="size-4" aria-hidden />
                        </span>
                        <span className="min-w-0">
                          <span className="block truncate font-medium group-hover:underline">{a.name}</span>
                          <span className="block truncate font-mono text-[11.5px] text-subtle">
                            {a.slug}
                            {a.project ? ` · ${a.project}` : ""}
                          </span>
                        </span>
                      </Link>
                    </TableCell>
                    <TableCell>
                      <StatusChip kind="agent" status={a.status} />
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{frameworkLabel(a.framework)}</TableCell>
                    <TableCell className="hidden lg:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {(a.roles ?? []).length ? (a.roles ?? []).map((r) => <Chip key={r}>{r}</Chip>) : <span className="text-[12px] text-subtle">No roles</span>}
                      </div>
                    </TableCell>
                    <TableCell className="tabular hidden text-right sm:table-cell">
                      {formatNumber(a.decisions_24h ?? 0)}
                      {!!a.denied_24h && <span className="ml-1.5 text-[12px] text-danger">{a.denied_24h} denied</span>}
                    </TableCell>
                    <TableCell className="hidden text-right sm:table-cell">
                      {a.open_threats ? (
                        <Chip tone="danger">
                          <ShieldAlertIcon />
                          {a.open_threats}
                        </Chip>
                      ) : (
                        <span className="text-subtle">0</span>
                      )}
                    </TableCell>
                    <TableCell className="hidden text-right whitespace-nowrap text-muted-foreground xl:table-cell">{a.last_seen_at ? formatRelative(a.last_seen_at, now) : "Never"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryState>
      </Surface>
      <RegisterAgentDialog open={registerOpen} onOpenChange={setRegisterOpen} onRegistered={(r, signed) => setIssued({ credential: r.credential, signed })} />
      <CredentialDialog issued={issued?.credential ?? null} signed={issued?.signed ?? false} onClose={() => setIssued(null)} />
    </>
  );
}
