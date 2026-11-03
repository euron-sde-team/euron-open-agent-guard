"use client";

import { KeyRoundIcon, LockIcon, PlusIcon, SendIcon, Trash2Icon, WebhookIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { CopyButton } from "@/components/copy-button";
import { EmptyState } from "@/components/empty-state";
import { CodeBlock } from "@/components/json-view";
import { PageHeader } from "@/components/page-header";
import { QueryState } from "@/components/query-state";
import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePermissions } from "@/features/auth/api";
import { useNow } from "@/hooks/use-now";
import { errorMessage } from "@/lib/api/errors";
import { formatRelative } from "@/lib/format";
import { humanize } from "@/lib/labels";
import { curlTokenSnippet, mcpSnippet, nodeSnippet, publicBaseUrl, pythonSnippet } from "@/lib/snippets";

import { useApiKeys, useCreateApiKey, useCreateWebhook, useIntegrations, useRevokeApiKey, useWebhookAction, useWebhookEvents, useWebhooks } from "../api";
import { OpaCard, SiemCard, TokenShieldCard } from "./connections";
import { SecretOnceDialog } from "./secret-once-dialog";

const CLIENT_ID = "YOUR_CLIENT_ID";

function QuickStart() {
  const [base, setBase] = React.useState("http://localhost:5110");
  React.useEffect(() => setBase(publicBaseUrl(window.location)), []);
  const input = { baseUrl: base, clientId: CLIENT_ID };
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
      <Surface>
        <SurfaceHeader
          title="SDK quick start"
          description={`Replace ${CLIENT_ID} with the client id of the agent's credential (Agents, Credentials). The secret comes from the environment, never from code.`}
        />
        <div className="px-5 pb-5">
          <Tabs defaultValue="python">
            <TabsList>
              <TabsTrigger value="python">Python</TabsTrigger>
              <TabsTrigger value="node">Node.js</TabsTrigger>
              <TabsTrigger value="curl">curl</TabsTrigger>
            </TabsList>
            <TabsContent value="python">
              <CodeBlock code={pythonSnippet(input)} label="Python snippet" />
            </TabsContent>
            <TabsContent value="node">
              <CodeBlock code={nodeSnippet(input)} label="Node.js snippet" />
            </TabsContent>
            <TabsContent value="curl">
              <CodeBlock code={curlTokenSnippet(base, CLIENT_ID)} label="curl snippet" />
            </TabsContent>
          </Tabs>
        </div>
      </Surface>
      <Surface>
        <SurfaceHeader title="MCP gateway" description="One endpoint for every registered MCP server. Each agent sees only the tools it may use; calls are decided, constrained and their outputs scanned." />
        <div className="space-y-3 px-5 pb-5">
          <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
            <code className="min-w-0 flex-1 truncate font-mono text-[12.5px]">{base}/mcp</code>
            <CopyButton value={`${base}/mcp`} iconOnly label="Copy the MCP URL" variant="subtle" />
          </div>
          <p className="text-[12.5px] text-muted-foreground">Authenticate with the agent&apos;s access token from /oauth/token. A client configuration:</p>
          <CodeBlock code={mcpSnippet(base)} label="MCP client configuration" />
        </div>
      </Surface>
    </div>
  );
}

function Webhooks() {
  const q = useWebhooks();
  const events = useWebhookEvents();
  const create = useCreateWebhook();
  const act = useWebhookAction();
  const now = useNow(60_000);
  const [open, setOpen] = React.useState(false);
  const [url, setUrl] = React.useState("");
  const [picked, setPicked] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [secret, setSecret] = React.useState<string | null>(null);
  const [remove, setRemove] = React.useState<string | null>(null);
  return (
    <Surface>
      <SurfaceHeader
        title="Webhooks"
        description="Signed events to your systems: denied decisions, approvals, threats, incidents, agent status, policy activations, expiring secrets and tool changes."
        action={
          <Button
            size="sm"
            onClick={() => {
              setUrl("");
              setPicked(["approval.requested", "threat.detected", "incident.opened"]);
              setError(null);
              setOpen(true);
            }}
          >
            <PlusIcon />
            Add webhook
          </Button>
        }
      />
      <QueryState
        query={q}
        errorTitle="Could not load webhooks"
        empty={(d) => d.length === 0}
        emptyState={<EmptyState compact icon={WebhookIcon} title="No webhooks" description="Send approvals to your chat, threats to your on-call tool, or everything to your own service." />}
      >
        {(items) => (
          <ul className="divide-y divide-hairline">
            {items.map((w) => (
              <li key={w.id} className="flex flex-col gap-2 px-5 py-3 sm:flex-row sm:items-center">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[12.5px] font-medium">{w.url}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {w.events.map((e) => (
                      <Chip key={e}>{e}</Chip>
                    ))}
                  </div>
                  <div className="mt-1 text-[11.5px] text-subtle">
                    {w.disabled_reason ? <span className="text-danger">Disabled: {w.disabled_reason}</span> : w.last_success_at ? `Last delivered ${formatRelative(w.last_success_at, now)}` : "Nothing delivered yet"}
                    {w.consecutive_failures > 0 && `, ${w.consecutive_failures} failures in a row`}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <Switch checked={w.active} aria-label={w.active ? "Pause webhook" : "Resume webhook"} onCheckedChange={(c) => act.mutate({ id: w.id, action: "toggle", active: c }, { onError: (e) => toast.error(errorMessage(e)) })} />
                  <Button size="xs" variant="outline" onClick={() => act.mutate({ id: w.id, action: "test" }, { onSuccess: () => toast.success("Test event queued. Check your endpoint."), onError: (e) => toast.error(errorMessage(e)) })}>
                    <SendIcon />
                    Test
                  </Button>
                  <Button size="icon-xs" variant="ghost" aria-label="Delete webhook" onClick={() => setRemove(w.id)}>
                    <Trash2Icon />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
      <Dialog open={open} onOpenChange={(o) => !create.isPending && setOpen(o)}>
        <DialogContent className="max-w-lg">
          <form
            className="flex min-h-0 flex-col"
            onSubmit={(e) => {
              e.preventDefault();
              if (!/^https?:\/\//.test(url.trim())) return setError("Give the endpoint URL, starting with https://.");
              if (!picked.length) return setError("Pick at least one event.");
              create.mutate(
                { url: url.trim(), events: picked },
                {
                  onSuccess: (w) => {
                    setOpen(false);
                    setSecret(w.secret);
                  },
                  onError: (err) => setError(errorMessage(err)),
                },
              );
            }}
          >
            <DialogHeader>
              <DialogTitle>Add a webhook</DialogTitle>
              <DialogDescription>Each delivery carries an HMAC signature made with a secret shown once.</DialogDescription>
            </DialogHeader>
            <DialogBody className="space-y-4">
              <Field label="Endpoint" htmlFor="wh-url">
                <Input id="wh-url" autoFocus className="font-mono text-[12.5px]" placeholder="https://hooks.example/agentguard" value={url} onChange={(e) => setUrl(e.target.value)} />
              </Field>
              <fieldset>
                <legend className="mb-2 text-[13px] font-medium">Events</legend>
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {(events.data ?? []).map((ev) => (
                    <label key={ev} className="flex items-center gap-2 font-mono text-[12px]">
                      <input type="checkbox" className="size-3.5 accent-[var(--primary)]" checked={picked.includes(ev)} onChange={(e) => setPicked(e.target.checked ? [...picked, ev] : picked.filter((x) => x !== ev))} />
                      {ev}
                    </label>
                  ))}
                </div>
              </fieldset>
              {error && <FieldError>{error}</FieldError>}
            </DialogBody>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending}>
                Add webhook
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <SecretOnceDialog value={secret} title="Webhook signing secret" description="Verify the X-AgentGuard-Signature header of each delivery with it." onClose={() => setSecret(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title="Delete this webhook?"
        description="No more events are sent to it."
        confirmLabel="Delete webhook"
        pending={act.isPending}
        onConfirm={() =>
          remove &&
          act.mutate(
            { id: remove, action: "delete" },
            {
              onSuccess: () => {
                toast.success("Webhook deleted.");
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

function ApiKeys() {
  const q = useApiKeys();
  const create = useCreateApiKey();
  const revoke = useRevokeApiKey();
  const now = useNow(60_000);
  const [name, setName] = React.useState("");
  const [scope, setScope] = React.useState<"read" | "write">("read");
  const [key, setKey] = React.useState<string | null>(null);
  const [remove, setRemove] = React.useState<{ id: string; name: string } | null>(null);
  return (
    <Surface>
      <SurfaceHeader title="Management API keys" description="For scripts and CI that manage AgentGuard (not for agents: agents use their own credentials)." />
      <form
        className="flex flex-col gap-2 px-5 pb-4 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return toast.error("Name the key after what uses it, like terraform or ci.");
          create.mutate(
            { name: name.trim(), scope },
            {
              onSuccess: (k) => {
                setName("");
                setKey(k.key);
              },
              onError: (err) => toast.error(errorMessage(err)),
            },
          );
        }}
      >
        <Input aria-label="Key name" placeholder="Name, like ci-pipeline" value={name} onChange={(e) => setName(e.target.value)} />
        <SimpleSelect
          aria-label="Scope"
          className="sm:w-40"
          value={scope}
          onValueChange={(v) => setScope(v === "write" ? "write" : "read")}
          options={[
            { value: "read", label: "Read only" },
            { value: "write", label: "Read and write" },
          ]}
        />
        <Button type="submit" disabled={create.isPending}>
          <KeyRoundIcon />
          Create key
        </Button>
      </form>
      <QueryState query={q} errorTitle="Could not load API keys" empty={(d) => d.length === 0} emptyState={<p className="px-5 pb-5 text-[12.5px] text-muted-foreground">No keys yet.</p>}>
        {(items) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead className="hidden sm:table-cell">Last used</TableHead>
                <TableHead className="text-right">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((k) => (
                <TableRow key={k.id} className={k.revoked_at ? "opacity-50" : undefined}>
                  <TableCell className="font-medium">{k.name}</TableCell>
                  <TableCell className="font-mono text-[12px] text-muted-foreground">{k.prefix}...</TableCell>
                  <TableCell>
                    <Chip tone={k.scope === "write" ? "warning" : "neutral"}>{humanize(k.scope)}</Chip>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground sm:table-cell">{k.last_used_at ? formatRelative(k.last_used_at, now) : "Never"}</TableCell>
                  <TableCell className="text-right">
                    {k.revoked_at ? (
                      <Chip>Revoked</Chip>
                    ) : (
                      <Button size="xs" variant="ghost" className="text-danger" onClick={() => setRemove({ id: k.id, name: k.name })}>
                        Revoke
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
      <div className="h-2" />
      <SecretOnceDialog value={key} title="Your new API key" description="Send it as Authorization: Bearer <key>." onClose={() => setKey(null)} />
      <ConfirmDialog
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Revoke ${remove?.name}?`}
        description="Anything using it is refused from now on."
        confirmLabel="Revoke key"
        pending={revoke.isPending}
        onConfirm={() =>
          remove &&
          revoke.mutate(remove.id, {
            onSuccess: () => {
              toast.success("Key revoked.");
              setRemove(null);
            },
            onError: (e) => toast.error(errorMessage(e)),
          })
        }
      />
    </Surface>
  );
}

function AdminOnly() {
  return (
    <Surface>
      <EmptyState icon={LockIcon} title="Org admins manage connections" description="TokenShield, OPA, SIEM, webhooks and API keys hold credentials, so only org admins see and change them. Ask an org admin of your organisation." />
    </Surface>
  );
}

export function IntegrationsScreen() {
  const { can } = usePermissions();
  const admin = can("admin");
  const integrations = useIntegrations(admin);
  const byKind = new Map((integrations.data ?? []).map((i) => [i.kind, i]));
  return (
    <>
      <PageHeader title="Integrations" description="Connect agents through the SDK or the MCP gateway, and connect AgentGuard to TokenShield, OPA, your SIEM and your own systems." />
      <Tabs defaultValue="sdk">
        <TabsList className="flex-nowrap overflow-x-auto">
          <TabsTrigger value="sdk">SDK and MCP</TabsTrigger>
          <TabsTrigger value="connections">Connections</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="keys">API keys</TabsTrigger>
        </TabsList>
        <TabsContent value="sdk">
          <QuickStart />
        </TabsContent>
        <TabsContent value="connections">
          {!admin ? (
            <AdminOnly />
          ) : (
            <QueryState query={integrations} errorTitle="Could not load integrations">
              {() => (
                <div className="grid gap-4 xl:grid-cols-3">
                  <TokenShieldCard item={byKind.get("tokenshield")} />
                  <OpaCard item={byKind.get("opa")} />
                  <SiemCard item={byKind.get("siem")} />
                </div>
              )}
            </QueryState>
          )}
        </TabsContent>
        <TabsContent value="webhooks">{admin ? <Webhooks /> : <AdminOnly />}</TabsContent>
        <TabsContent value="keys">{admin ? <ApiKeys /> : <AdminOnly />}</TabsContent>
      </Tabs>
    </>
  );
}
