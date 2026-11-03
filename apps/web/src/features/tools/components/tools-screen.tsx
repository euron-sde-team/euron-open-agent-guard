"use client";

import { PlusIcon, WrenchIcon } from "lucide-react";
import { useSearchParams } from "next/navigation";
import * as React from "react";

import { SeverityChip, StatusChip } from "@/components/badges";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface } from "@/components/surface";
import { Chip } from "@/components/ui/chip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { Tool } from "@/lib/api/types";
import { formatNumber } from "@/lib/format";
import { toolKindLabel } from "@/lib/labels";

import { useTools } from "../api";
import { McpPanel } from "./mcp-panel";
import { RegisterToolDialog } from "./register-tool-dialog";
import { ReviewPanel } from "./review-panel";
import { ToolSheet } from "./tool-sheet";

function Registry({ tools, onOpen, onRegister }: { tools: Tool[]; onOpen: (t: Tool) => void; onRegister: () => void }) {
  if (!tools.length)
    return (
      <EmptyState
        icon={WrenchIcon}
        title="No tools registered"
        description="Register the tools your agents call: their parameters, risk and how they run. Unregistered tools are denied when require_registered_tools is on."
        action={
          <GatedButton need="write" size="sm" onClick={onRegister}>
            <PlusIcon />
            Register a tool
          </GatedButton>
        }
      />
    );
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Tool</TableHead>
          <TableHead className="hidden sm:table-cell">Kind</TableHead>
          <TableHead>Risk</TableHead>
          <TableHead className="hidden md:table-cell">Flags</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="hidden lg:table-cell">Granted to</TableHead>
          <TableHead className="text-right">Calls 24h</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {tools.map((t) => (
          <TableRow
            key={t.id}
            tabIndex={0}
            role="button"
            aria-label={`Open ${t.name}`}
            className="cursor-pointer focus-visible:bg-muted focus-visible:outline-none"
            onClick={() => onOpen(t)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onOpen(t);
              }
            }}
          >
            <TableCell className="max-w-[340px]">
              <div className="font-mono text-[13px] font-medium">{t.name}</div>
              <div className="truncate text-[12px] text-muted-foreground">{t.description}</div>
            </TableCell>
            <TableCell className="hidden sm:table-cell">
              <Chip>{toolKindLabel(t.kind)}</Chip>
            </TableCell>
            <TableCell>
              <SeverityChip level={t.risk} />
            </TableCell>
            <TableCell className="hidden md:table-cell">
              <div className="flex flex-wrap gap-1">
                {t.sensitive && <Chip tone="orange">Sensitive</Chip>}
                {t.external && <Chip tone="info">External</Chip>}
                {!t.sensitive && !t.external && <span className="text-[12px] text-subtle">None</span>}
              </div>
            </TableCell>
            <TableCell>
              <StatusChip kind="tool" status={t.status} />
            </TableCell>
            <TableCell className="hidden lg:table-cell">
              <div className="flex flex-wrap gap-1">{(t.granted_roles ?? []).length ? (t.granted_roles ?? []).map((r) => <Chip key={r}>{r}</Chip>) : <span className="text-[12px] text-subtle">No role</span>}</div>
            </TableCell>
            <TableCell className="tabular text-right">
              {formatNumber(t.calls_24h ?? 0)}
              {!!t.denied_24h && <div className="text-[11.5px] text-danger">{t.denied_24h} denied</div>}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ToolsScreen() {
  const q = useTools();
  const params = useSearchParams();
  const [registering, setRegistering] = React.useState(false);
  const [openId, setOpenId] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (params.get("register") === "1") setRegistering(true);
  }, [params]);
  const pending = (q.data ?? []).filter((t) => t.status === "pending_review").length;
  const open = q.data?.find((t) => t.id === openId) ?? null;
  return (
    <>
      <PageHeader
        title="Tool security"
        description="What agents may call, with which parameters, and how it runs. HTTP and MCP tools and sandbox code run through AgentGuard with secrets injected; in-process tools verify a signed decision token."
        actions={
          <GatedButton need="write" onClick={() => setRegistering(true)}>
            <PlusIcon />
            Register tool
          </GatedButton>
        }
      />
      <Tabs value={tab ?? (pending ? "review" : "registry")} onValueChange={(v) => setTab(String(v))}>
        <TabsList>
          <TabsTrigger value="registry">Registry</TabsTrigger>
          <TabsTrigger value="mcp">MCP servers</TabsTrigger>
          <TabsTrigger value="review">
            Pending review
            {!!pending && <span className="tabular rounded-full bg-warning-soft px-1.5 text-[11px] font-semibold text-warning">{pending}</span>}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="registry">
          <Surface>
            <QueryState query={q} errorTitle="Could not load tools">
              {(tools) => <Registry tools={tools} onOpen={(t) => setOpenId(t.id)} onRegister={() => setRegistering(true)} />}
            </QueryState>
          </Surface>
        </TabsContent>
        <TabsContent value="mcp">
          <McpPanel />
        </TabsContent>
        <TabsContent value="review">
          <QueryState query={q} errorTitle="Could not load tools">
            {(tools) => <ReviewPanel tools={tools} />}
          </QueryState>
        </TabsContent>
      </Tabs>
      <RegisterToolDialog open={registering} onOpenChange={setRegistering} />
      <ToolSheet tool={open} onClose={() => setOpenId(null)} />
    </>
  );
}
