"use client";

import { CheckCircle2Icon, PlugZapIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { Surface, SurfaceHeader } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/lib/api/errors";
import type { Integration, IntegrationIn } from "@/lib/api/types";
import { formatRelative } from "@/lib/format";
import { joinList, splitList } from "@/lib/forms";
import { num, str, strs } from "@/lib/read";

import { useSaveIntegration, useTestIntegration, type IntegrationKind } from "../api";

function Shell({
  kind,
  item,
  title,
  description,
  children,
  build,
}: {
  kind: IntegrationKind;
  item: Integration | undefined;
  title: string;
  description: string;
  children: (enabled: boolean) => React.ReactNode;
  build: () => IntegrationIn | string;
}) {
  const save = useSaveIntegration();
  const test = useTestIntegration();
  const [enabled, setEnabled] = React.useState(item?.enabled ?? false);
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => setEnabled(item?.enabled ?? false), [item]);
  return (
    <Surface className="flex flex-col">
      <SurfaceHeader
        title={title}
        description={description}
        titleExtra={item?.configured ? <Chip tone={item.enabled ? "success" : "neutral"}>{item.enabled ? "Connected" : "Off"}</Chip> : <Chip>Not set up</Chip>}
        action={<Switch checked={enabled} onCheckedChange={setEnabled} aria-label={`Enable ${title}`} />}
      />
      <form
        className="flex flex-1 flex-col gap-3 px-5 pb-5"
        onSubmit={(e) => {
          e.preventDefault();
          const body = build();
          if (typeof body === "string") return setError(body);
          setError(null);
          save.mutate({ kind, body: { ...body, enabled } }, { onSuccess: () => toast.success(`${title} saved.`), onError: (err) => setError(errorMessage(err)) });
        }}
      >
        {children(enabled)}
        {item?.last_error && <p className="text-[12px] text-danger">Last error: {item.last_error}</p>}
        {item?.last_ok_at && (
          <p className="flex items-center gap-1 text-[12px] text-muted-foreground">
            <CheckCircle2Icon className="size-3.5 text-primary" /> Last answered {formatRelative(item.last_ok_at)}
          </p>
        )}
        {error && <FieldError>{error}</FieldError>}
        <div className="mt-auto flex flex-wrap gap-2 pt-1">
          <Button type="submit" size="sm" disabled={save.isPending}>
            {save.isPending ? "Saving..." : "Save"}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!item?.configured || test.isPending}
            onClick={() =>
              test.mutate(kind, {
                onSuccess: (r) => (r.ok ? toast.success(`${title}: ${r.detail || "it answers."}`) : toast.error(`${title}: ${r.detail || "no answer"}. Check the URL and credentials.`)),
                onError: (e) => toast.error(errorMessage(e)),
              })
            }
          >
            <PlugZapIcon />
            {test.isPending ? "Testing..." : "Test connection"}
          </Button>
        </div>
      </form>
    </Surface>
  );
}

export function TokenShieldCard({ item }: { item: Integration | undefined }) {
  const c = item?.config ?? {};
  const [url, setUrl] = React.useState(str(c.url) ?? "");
  const [email, setEmail] = React.useState(str(c.email) ?? "");
  const [password, setPassword] = React.useState("");
  const [projects, setProjects] = React.useState(joinList(strs(c.projects)));
  const [failMode, setFailMode] = React.useState(str(c.fail_mode) ?? "open");
  React.useEffect(() => {
    setUrl(str(c.url) ?? "");
    setEmail(str(c.email) ?? "");
    setProjects(joinList(strs(c.projects)));
    setFailMode(str(c.fail_mode) ?? "open");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item]);
  return (
    <Shell
      kind="tokenshield"
      item={item}
      title="TokenShield"
      description="Deny actions when the project's token or spend budget is used up. Local limits still apply when TokenShield is down."
      build={() => {
        if (!/^https?:\/\//.test(url.trim())) return "Give TokenShield's URL, starting with http:// or https://.";
        return { config: { url: url.trim(), email: email.trim(), projects: splitList(projects), fail_mode: failMode }, secret: password ? password : null };
      }}
    >
      {() => (
        <>
          <Field label="URL" htmlFor="ts-url">
            <Input id="ts-url" className="font-mono text-[12.5px]" placeholder="http://tokenshield:4930" value={url} onChange={(e) => setUrl(e.target.value)} />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Viewer account" htmlFor="ts-email">
              <Input id="ts-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </Field>
            <Field label="Password" htmlFor="ts-pw" hint={item?.secret_set ? "Stored. Leave empty to keep it." : "Write only."}>
              <Input id="ts-pw" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <Field label="Projects" htmlFor="ts-projects">
              <Input id="ts-projects" value={projects} placeholder="support, finance" onChange={(e) => setProjects(e.target.value)} />
            </Field>
            <Field label="When TokenShield is down" htmlFor="ts-fail">
              <SimpleSelect
                id="ts-fail"
                value={failMode}
                onValueChange={setFailMode}
                options={[
                  { value: "open", label: "Allow (local limits apply)" },
                  { value: "closed", label: "Deny" },
                ]}
              />
            </Field>
          </div>
        </>
      )}
    </Shell>
  );
}

export function OpaCard({ item }: { item: Integration | undefined }) {
  const c = item?.config ?? {};
  const [url, setUrl] = React.useState(str(c.url) ?? "");
  const [pkg, setPkg] = React.useState(str(c.package) ?? "");
  const [rego, setRego] = React.useState("");
  React.useEffect(() => {
    setUrl(str(c.url) ?? "");
    setPkg(str(c.package) ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item]);
  const lines = num(c.rego_lines);
  return (
    <Shell
      kind="opa"
      item={item}
      title="Open Policy Agent"
      description="Add Rego evaluated by an OPA sidecar. Its result is combined deny-overrides with the native decision, so OPA can only add caution."
      build={() => ({ config: { url: url.trim(), package: pkg.trim() }, rego: rego.trim() ? rego : null })}
    >
      {() => (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="URL" htmlFor="opa-url" hint="Empty uses the server's default sidecar.">
              <Input id="opa-url" className="font-mono text-[12.5px]" placeholder="http://opa:8181" value={url} onChange={(e) => setUrl(e.target.value)} />
            </Field>
            <Field label="Package" htmlFor="opa-pkg">
              <Input id="opa-pkg" className="font-mono text-[12.5px]" placeholder="agentguard.org_..." value={pkg} onChange={(e) => setPkg(e.target.value)} />
            </Field>
          </div>
          <Field label="Rego" htmlFor="opa-rego" hint={lines ? `${lines} lines stored. Paste new Rego to replace it; leave empty to keep it.` : "Return decision (deny, require_approval, ...) and reason."}>
            <Textarea
              id="opa-rego"
              className="min-h-36 font-mono text-[12px]"
              placeholder={'package agentguard.org\n\ndecision := "deny" if {\n  input.tool.name == "db.drop"\n}'}
              value={rego}
              onChange={(e) => setRego(e.target.value)}
            />
          </Field>
        </>
      )}
    </Shell>
  );
}

export function SiemCard({ item }: { item: Integration | undefined }) {
  const c = item?.config ?? {};
  const [url, setUrl] = React.useState(str(c.url) ?? "");
  React.useEffect(() => {
    setUrl(str(c.url) ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item]);
  return (
    <Shell
      kind="siem"
      item={item}
      title="SIEM export"
      description="Forward audit records and security events to your SIEM as JSON lines (application/x-ndjson), every 30 seconds."
      build={() => (/^https?:\/\//.test(url.trim()) ? { config: { url: url.trim(), format: "ndjson" } } : "Give the collector URL, starting with http:// or https://.")}
    >
      {() => (
        <Field label="Collector URL" htmlFor="siem-url">
          <Input id="siem-url" className="font-mono text-[12.5px]" placeholder="https://siem.example/ingest" value={url} onChange={(e) => setUrl(e.target.value)} />
        </Field>
      )}
    </Shell>
  );
}
