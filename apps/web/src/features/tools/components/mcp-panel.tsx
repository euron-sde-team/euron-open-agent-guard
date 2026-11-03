"use client";

import { PlusIcon, RadarIcon, RefreshCwIcon, ServerIcon, Trash2Icon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { SeverityChip, StatusChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState } from "@/components/empty-state";
import { GatedButton } from "@/components/gated";
import { Mono } from "@/components/kv";
import { QueryState } from "@/components/query-state";
import { Segmented } from "@/components/segmented";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { usePermissions } from "@/features/auth/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import type { Discover, McpServer } from "@/lib/api/types";
import { formatMs, formatRelative } from "@/lib/format";
import { parseHeaderLines, slugify, splitList } from "@/lib/forms";
import { SEVERITIES, severitySpec } from "@/lib/labels";
import { str } from "@/lib/read";

import { useAddMcpServer, useMcpAction, useMcpServers, useToggleMcpServer } from "../api";

function discoverText(d: Discover): string {
  const parts = [];
  if (d.added.length) parts.push(`${d.added.length} added`);
  if (d.changed.length) parts.push(`${d.changed.length} changed`);
  if (d.removed.length) parts.push(`${d.removed.length} removed`);
  if (d.flagged.length) parts.push(`${d.flagged.length} held for review`);
  return parts.length ? `Discovery: ${parts.join(", ")}.` : "Discovery: no change.";
}

function AddServerDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const add = useAddMcpServer();
  const [transport, setTransport] = React.useState<"http" | "stdio">("http");
  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [command, setCommand] = React.useState("");
  const [args, setArgs] = React.useState("");
  const [risk, setRisk] = React.useState("medium");
  const [bindings, setBindings] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (open) {
      setTransport("http");
      setName("");
      setSlug("");
      setUrl("");
      setCommand("");
      setArgs("");
      setRisk("medium");
      setBindings("");
      setError(null);
    }
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={(o) => !add.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-lg">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            const s = slug || slugify(name);
            if (!name.trim() || !s) return setError("Name the server; its short name becomes the tool namespace (files.read_file).");
            if (transport === "http" && !/^https?:\/\//.test(url.trim())) return setError("Give the streamable HTTP URL, starting with http:// or https://.");
            if (transport === "stdio" && !command.trim()) return setError("Give the command (it must be on the server's allowlist).");
            setError(null);
            add.mutate(
              {
                name: name.trim(),
                slug: s,
                transport,
                url: transport === "http" ? url.trim() : null,
                command: transport === "stdio" ? command.trim() : null,
                args: transport === "stdio" ? splitList(args) : [],
                default_risk: risk,
                secret_bindings: parseHeaderLines(bindings),
                discover: true,
              },
              {
                onSuccess: (srv) => {
                  toast.success(`${srv.name} added with ${srv.tools ?? 0} tools. Grant them to roles to use them.`);
                  onOpenChange(false);
                },
                onError: (err) => setError(errorMessage(err)),
              },
            );
          }}
        >
          <DialogHeader>
            <DialogTitle>Add an MCP server</DialogTitle>
            <DialogDescription>Its tools are discovered, fingerprinted and served through the one /mcp endpoint under its namespace.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Segmented
              ariaLabel="Transport"
              value={transport}
              onChange={setTransport}
              options={[
                { value: "http", label: "Streamable HTTP" },
                { value: "stdio", label: "stdio (allowlisted)" },
              ]}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" htmlFor="mcp-name">
                <Input id="mcp-name" autoFocus value={name} placeholder="Shared documents" onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Namespace" htmlFor="mcp-slug">
                <Input id="mcp-slug" className="font-mono text-[13px]" value={slug || slugify(name)} onChange={(e) => setSlug(slugify(e.target.value))} />
              </Field>
            </div>
            {transport === "http" ? (
              <Field label="URL" htmlFor="mcp-url">
                <Input id="mcp-url" className="font-mono text-[13px]" placeholder="https://mcp.internal.example/mcp" value={url} onChange={(e) => setUrl(e.target.value)} />
              </Field>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Command" htmlFor="mcp-cmd">
                  <Input id="mcp-cmd" className="font-mono text-[13px]" value={command} onChange={(e) => setCommand(e.target.value)} />
                </Field>
                <Field label="Arguments" htmlFor="mcp-args" hint="Comma separated.">
                  <Input id="mcp-args" className="font-mono text-[13px]" value={args} onChange={(e) => setArgs(e.target.value)} />
                </Field>
              </div>
            )}
            <Field label="Default risk" htmlFor="mcp-risk">
              <SimpleSelect id="mcp-risk" value={risk} onValueChange={setRisk} options={SEVERITIES.map((s) => ({ value: s, label: severitySpec(s).label }))} />
            </Field>
            <Field label="Secrets injected at connect" htmlFor="mcp-bind" hint="One per line: Header: secret-name|template, like Authorization: crm-token|Bearer {value}.">
              <Textarea id="mcp-bind" className="font-mono text-[12.5px]" value={bindings} onChange={(e) => setBindings(e.target.value)} />
            </Field>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={add.isPending}>
              {add.isPending ? "Connecting..." : "Add and discover"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function McpPanel() {
  const q = useMcpServers();
  const act = useMcpAction();
  const toggle = useToggleMcpServer();
  const { can } = usePermissions();
  const now = useNow(60_000);
  const [adding, setAdding] = React.useState(false);
  const [remove, setRemove] = React.useState<McpServer | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const run = (s: McpServer, action: "discover" | "check") => {
    setBusy(`${s.id}:${action}`);
    act.mutate(
      { id: s.id, action },
      {
        onSuccess: (r) => {
          if (action === "discover") toast.success(discoverText(r as Discover));
          else toast.success(`${s.name}: ${(r as McpServer).health}.`);
        },
        onError: (e) => toast.error(errorMessage(e)),
        onSettled: () => setBusy(null),
      },
    );
  };
  return (
    <Surface>
      <SurfaceHeader
        title="MCP servers"
        description="One governed endpoint for every server: tools a client may not use are hidden, arguments constrained, outputs scanned, and silent description changes held for review."
        action={
          <GatedButton need="write" size="sm" onClick={() => setAdding(true)}>
            <PlusIcon />
            Add server
          </GatedButton>
        }
      />
      <QueryState
        query={q}
        errorTitle="Could not load MCP servers"
        empty={(d) => d.length === 0}
        emptyState={
          <EmptyState
            compact
            icon={ServerIcon}
            title="No MCP servers"
            description="Register a streamable HTTP or allowlisted stdio server. Its tools appear in the registry under its namespace."
            action={
              <GatedButton need="write" size="sm" variant="outline" onClick={() => setAdding(true)}>
                Add your first server
              </GatedButton>
            }
          />
        }
      >
        {(servers) => (
          <ul className="grid gap-3 px-5 pb-5 lg:grid-cols-2">
            {servers.map((s) => (
              <li key={s.id} className="flex flex-col gap-3 rounded-xl bg-muted/60 p-4">
                <div className="flex items-start gap-3">
                  <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-card text-primary shadow-[var(--elev-1)]">
                    <ServerIcon className="size-4" aria-hidden />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 text-[13.5px] font-semibold">
                      {s.name}
                      <StatusChip kind="health" status={s.enabled ? s.health : "unknown"} />
                      {!s.enabled && <Chip>Disabled</Chip>}
                    </div>
                    <Mono className="block truncate">{s.url ?? `${s.command ?? ""} ${(s.args ?? []).join(" ")}`}</Mono>
                    {s.health_detail && <div className="mt-0.5 text-[12px] text-danger">{s.health_detail}</div>}
                  </div>
                  {can("write") && <Switch checked={s.enabled} aria-label={s.enabled ? `Disable ${s.name}` : `Enable ${s.name}`} onCheckedChange={(c) => toggle.mutate({ id: s.id, enabled: c }, { onError: (e) => toast.error(errorMessage(e)) })} />}
                </div>
                <div className="flex flex-wrap gap-x-5 gap-y-1 text-[12px] text-muted-foreground">
                  <span>
                    Namespace <span className="font-mono text-foreground">{s.slug}</span>
                  </span>
                  <span>
                    <span className="tabular font-semibold text-foreground">{s.tools ?? 0}</span> tools
                  </span>
                  {!!s.pending_review && <Chip tone="warning">{s.pending_review} pending review</Chip>}
                  <span>Latency {formatMs(s.latency_ms)}</span>
                  <SeverityChip level={s.default_risk} prefix="Default risk" />
                  <span>Discovered {s.last_discovered_at ? formatRelative(s.last_discovered_at, now) : "never"}</span>
                  {str(s.server_info.version) && <span>v{str(s.server_info.version)}</span>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <GatedButton need="write" size="xs" variant="outline" disabled={!!busy} onClick={() => run(s, "check")}>
                    <RefreshCwIcon className={busy === `${s.id}:check` ? "animate-spin" : undefined} />
                    Check health
                  </GatedButton>
                  <GatedButton need="write" size="xs" variant="outline" disabled={!!busy} onClick={() => run(s, "discover")}>
                    <RadarIcon className={busy === `${s.id}:discover` ? "animate-pulse" : undefined} />
                    Discover tools
                  </GatedButton>
                  <GatedButton need="write" size="xs" variant="ghost" className="ml-auto" onClick={() => setRemove(s)}>
                    <Trash2Icon />
                    Remove
                  </GatedButton>
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
      <AddServerDialog open={adding} onOpenChange={setAdding} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Remove ${remove?.name}?`}
        description="Its tools disappear from the registry and the /mcp endpoint. Past decisions keep their tool names."
        confirmLabel="Remove server"
        pending={act.isPending}
        onConfirm={() =>
          remove &&
          act.mutate(
            { id: remove.id, action: "delete" },
            {
              onSuccess: () => {
                toast.success("Server removed.");
                setRemove(null);
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </Surface>
  );
}
