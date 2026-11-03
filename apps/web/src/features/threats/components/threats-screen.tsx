"use client";

import { ShieldAlertIcon, ShieldCheckIcon } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

import { SeverityChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { SimpleSelect } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNow } from "@/hooks/use-now";
import { formatRelative } from "@/lib/format";
import { detectorLabel, humanize, SEVERITIES, severitySpec, THREAT_KINDS, threatKindLabel } from "@/lib/labels";

import { useThreats } from "../api";
import { AnalyzePanel } from "./analyze-panel";

/** "incident:INC-4" becomes "Incident INC-4"; "quarantined" becomes "Quarantined". */
export function responseLabel(r: unknown): string {
  const s = typeof r === "string" ? r : JSON.stringify(r);
  if (s.startsWith("incident:")) return `Incident ${s.slice("incident:".length)}`;
  return humanize(s);
}

function Detections() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = React.useState("open");
  const [severity, setSeverity] = React.useState("");
  const [kind, setKind] = React.useState("");
  const agent = params.get("agent") ?? "";
  const q = useThreats({ status, severity, kind, agent_id: agent });
  const now = useNow(60_000);
  const filtered = status !== "" || severity !== "" || kind !== "";
  return (
    <Surface>
      <div className="flex flex-col gap-2 px-5 pt-4 pb-3 sm:flex-row sm:flex-wrap sm:items-center">
        <SimpleSelect
          aria-label="Filter by status"
          className="sm:w-44"
          value={status}
          onValueChange={setStatus}
          options={[
            { value: "open", label: "Open" },
            { value: "acknowledged", label: "Acknowledged" },
            { value: "resolved", label: "Resolved" },
            { value: "false_positive", label: "False positive" },
            { value: "", label: "Every status" },
          ]}
        />
        <SimpleSelect
          aria-label="Filter by severity"
          className="sm:w-40"
          value={severity}
          onValueChange={setSeverity}
          options={[{ value: "", label: "Every severity" }, ...[...SEVERITIES].reverse().map((s) => ({ value: s, label: severitySpec(s).label }))]}
        />
        <SimpleSelect
          aria-label="Filter by kind"
          className="sm:w-56"
          value={kind}
          onValueChange={setKind}
          options={[{ value: "", label: "Every kind" }, ...Object.entries(THREAT_KINDS).map(([value, label]) => ({ value, label }))]}
        />
        {agent && (
          <Button variant="ghost" size="sm" onClick={() => router.replace("/threats")}>
            Clear agent filter
          </Button>
        )}
      </div>
      <QueryState
        query={q}
        errorTitle="Could not load threats"
        empty={(d) => d.length === 0}
        emptyState={
          <EmptyState
            icon={ShieldCheckIcon}
            title={status === "open" ? "No open threats" : "No threats match"}
            description="Detections for prompt injection, exfiltration, credential leaks, loops, bursts and privilege probing appear here, with the automatic response taken."
            action={
              filtered ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setStatus("");
                    setSeverity("");
                    setKind("");
                  }}
                >
                  Show every threat
                </Button>
              ) : undefined
            }
          />
        }
      >
        {(items) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Threat</TableHead>
                <TableHead className="hidden md:table-cell">Agent</TableHead>
                <TableHead className="hidden lg:table-cell">Automatic response</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden text-right sm:table-cell">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((t) => (
                <TableRow key={t.id} className="cursor-pointer" onClick={() => router.push(`/threats/${t.id}`)}>
                  <TableCell>
                    <SeverityChip level={t.severity} />
                  </TableCell>
                  <TableCell className="max-w-[420px]">
                    <Link href={`/threats/${t.id}`} className="block truncate font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={(e) => e.stopPropagation()}>
                      {t.summary}
                    </Link>
                    <div className="text-[12px] text-muted-foreground">
                      {threatKindLabel(t.kind)} · {detectorLabel(t.detector)} detection
                      {t.occurrences > 1 ? ` · ${t.occurrences} times` : ""}
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{t.agent ?? <span className="text-subtle">None</span>}</TableCell>
                  <TableCell className="hidden lg:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {t.responses.length ? t.responses.map((r, i) => <Chip key={i} tone="violet">{responseLabel(r)}</Chip>) : <span className="text-[12px] text-subtle">None</span>}
                    </div>
                  </TableCell>
                  <TableCell>
                    <StatusChip kind="threat" status={t.status} />
                  </TableCell>
                  <TableCell className="hidden text-right whitespace-nowrap text-muted-foreground sm:table-cell">{formatRelative(t.last_seen_at, now)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
    </Surface>
  );
}

export function ThreatsScreen() {
  return (
    <>
      <PageHeader
        title="Threat detection"
        description="Rules, behavioural baselines and the optional classifier watch every decision and tool output. Automatic responses quarantine agents, revoke credentials and open incidents."
      />
      <Tabs defaultValue="detections">
        <TabsList>
          <TabsTrigger value="detections">
            <ShieldAlertIcon />
            Detections
          </TabsTrigger>
          <TabsTrigger value="analyze">Analyze content</TabsTrigger>
        </TabsList>
        <TabsContent value="detections">
          <Detections />
        </TabsContent>
        <TabsContent value="analyze">
          <AnalyzePanel />
        </TabsContent>
      </Tabs>
    </>
  );
}
