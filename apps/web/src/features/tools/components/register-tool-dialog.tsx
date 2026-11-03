"use client";

import * as React from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field, FieldError } from "@/components/ui/label";
import { Segmented } from "@/components/segmented";
import { SimpleSelect } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/lib/api/errors";
import { parseHeaderLines, parseJsonObject, splitList } from "@/lib/forms";
import { SEVERITIES, severitySpec } from "@/lib/labels";

import { useRegisterTool } from "../api";

type Kind = "http" | "sandbox" | "function";

const KIND_HELP: Record<Kind, string> = {
  http: "AgentGuard calls the URL itself, injecting secrets into headers, so the agent never holds the key.",
  sandbox: "Code runs in the unprivileged sandbox with CPU, memory and time limits, network off unless allowed.",
  function: "Runs in the agent's own process. Protect it with decision-token verification so it refuses calls AgentGuard did not allow.",
};

export function RegisterToolDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const register = useRegisterTool();
  const [kind, setKind] = React.useState<Kind>("http");
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [actions, setActions] = React.useState("call");
  const [risk, setRisk] = React.useState("medium");
  const [sensitive, setSensitive] = React.useState(false);
  const [external, setExternal] = React.useState(false);
  const [resourceTemplate, setResourceTemplate] = React.useState("");
  const [schema, setSchema] = React.useState('{\n  "type": "object",\n  "properties": {}\n}');
  const [constraints, setConstraints] = React.useState("{}");
  const [url, setUrl] = React.useState("");
  const [method, setMethod] = React.useState("POST");
  const [headers, setHeaders] = React.useState("");
  const [language, setLanguage] = React.useState("python");
  const [network, setNetwork] = React.useState("none");
  const [cpu, setCpu] = React.useState("5");
  const [wall, setWall] = React.useState("10");
  const [memory, setMemory] = React.useState("256");
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) return;
    setKind("http");
    setName("");
    setDescription("");
    setActions("call");
    setRisk("medium");
    setSensitive(false);
    setExternal(false);
    setResourceTemplate("");
    setSchema('{\n  "type": "object",\n  "properties": {}\n}');
    setConstraints("{}");
    setUrl("");
    setMethod("POST");
    setHeaders("");
    setError(null);
  }, [open]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(name.trim())) return setError("Name the tool like crm.get_customer: letters, digits, dots, dashes and underscores.");
    const s = parseJsonObject(schema);
    if ("error" in s) return setError(`Input schema: ${s.error}`);
    const c = parseJsonObject(constraints);
    if ("error" in c) return setError(`Constraints: ${c.error}`);
    let config: Record<string, unknown> = {};
    if (kind === "http") {
      if (!/^https?:\/\//.test(url.trim())) return setError("An HTTP tool needs a URL starting with http:// or https://.");
      config = { url: url.trim(), method };
      const h = parseHeaderLines(headers);
      if (Object.keys(h).length) config.secret_headers = h;
    } else if (kind === "sandbox") {
      config = { language, network, limits: { cpu_s: Number(cpu) || 5, wall_s: Number(wall) || 10, memory_mb: Number(memory) || 256 } };
    }
    setError(null);
    register.mutate(
      {
        name: name.trim(),
        kind,
        description: description.trim(),
        actions: splitList(actions),
        risk,
        sensitive,
        external,
        resource_template: resourceTemplate.trim(),
        input_schema: s.value,
        constraints: c.value,
        config,
      },
      {
        onSuccess: (t) => {
          toast.success(`${t.name} is registered. Grant it to a role so agents may call it.`);
          onOpenChange(false);
        },
        onError: (err) => setError(errorMessage(err)),
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !register.isPending && onOpenChange(o)}>
      <DialogContent className="max-w-2xl">
        <form onSubmit={submit} className="flex min-h-0 flex-col">
          <DialogHeader>
            <DialogTitle>Register a tool</DialogTitle>
            <DialogDescription>Parameters are validated against the schema and constraints before anything else is decided.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="space-y-1.5">
              <Segmented
                ariaLabel="Tool kind"
                value={kind}
                onChange={setKind}
                options={[
                  { value: "http", label: "HTTP" },
                  { value: "sandbox", label: "Sandbox code" },
                  { value: "function", label: "In-process function" },
                ]}
              />
              <p className="text-[12px] text-muted-foreground">{KIND_HELP[kind]}</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" htmlFor="tool-name">
                <Input id="tool-name" autoFocus className="font-mono text-[13px]" placeholder="crm.get_customer" value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Actions" htmlFor="tool-actions" hint="Comma separated: read, write, refund.">
                <Input id="tool-actions" className="font-mono text-[13px]" value={actions} onChange={(e) => setActions(e.target.value)} />
              </Field>
              <Field label="Description" htmlFor="tool-desc" className="sm:col-span-2">
                <Input id="tool-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
              </Field>
              <Field label="Baseline risk" htmlFor="tool-risk">
                <SimpleSelect id="tool-risk" value={risk} onValueChange={setRisk} options={SEVERITIES.map((s) => ({ value: s, label: severitySpec(s).label }))} />
              </Field>
              <Field label="Resource template" htmlFor="tool-res" hint="Built from parameters, like customer:{customer_id}.">
                <Input id="tool-res" className="font-mono text-[13px]" value={resourceTemplate} placeholder="customer:{customer_id}" onChange={(e) => setResourceTemplate(e.target.value)} />
              </Field>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              <label className="flex items-center gap-2 text-[13px]">
                <Switch checked={sensitive} onCheckedChange={setSensitive} aria-label="Sensitive" />
                Sensitive (fails closed when AgentGuard cannot decide)
              </label>
              <label className="flex items-center gap-2 text-[13px]">
                <Switch checked={external} onCheckedChange={setExternal} aria-label="External" />
                Sends data outside the organisation
              </label>
            </div>
            {kind === "http" && (
              <div className="grid gap-4 rounded-xl bg-muted/60 p-4 sm:grid-cols-[1fr_140px]">
                <Field label="URL" htmlFor="tool-url" hint="Parameters fill {placeholders}; the rest go in the body or query.">
                  <Input id="tool-url" className="font-mono text-[13px]" placeholder="https://crm.example/api/customers/{customer_id}" value={url} onChange={(e) => setUrl(e.target.value)} />
                </Field>
                <Field label="Method" htmlFor="tool-method">
                  <SimpleSelect id="tool-method" value={method} onValueChange={setMethod} options={["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => ({ value: m, label: m }))} />
                </Field>
                <Field label="Secret headers" htmlFor="tool-headers" className="sm:col-span-2" hint="One per line. {secret:name} is replaced at execution time; the agent never sees the value.">
                  <Textarea id="tool-headers" className="font-mono text-[12.5px]" placeholder="Authorization: Bearer {secret:crm-api-key}" value={headers} onChange={(e) => setHeaders(e.target.value)} />
                </Field>
              </div>
            )}
            {kind === "sandbox" && (
              <div className="grid gap-4 rounded-xl bg-muted/60 p-4 sm:grid-cols-5">
                <Field label="Language" htmlFor="tool-lang" className="sm:col-span-2">
                  <SimpleSelect
                    id="tool-lang"
                    value={language}
                    onValueChange={setLanguage}
                    options={[
                      { value: "python", label: "Python" },
                      { value: "node", label: "Node.js" },
                      { value: "bash", label: "Shell" },
                    ]}
                  />
                </Field>
                <Field label="Network" htmlFor="tool-net" className="sm:col-span-3">
                  <SimpleSelect
                    id="tool-net"
                    value={network}
                    onValueChange={setNetwork}
                    options={[
                      { value: "none", label: "None" },
                      { value: "proxy", label: "Through the egress guard" },
                    ]}
                  />
                </Field>
                <Field label="CPU (s)" htmlFor="tool-cpu">
                  <Input id="tool-cpu" inputMode="numeric" value={cpu} onChange={(e) => setCpu(e.target.value)} />
                </Field>
                <Field label="Wall (s)" htmlFor="tool-wall">
                  <Input id="tool-wall" inputMode="numeric" value={wall} onChange={(e) => setWall(e.target.value)} />
                </Field>
                <Field label="Memory (MB)" htmlFor="tool-mem">
                  <Input id="tool-mem" inputMode="numeric" value={memory} onChange={(e) => setMemory(e.target.value)} />
                </Field>
              </div>
            )}
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Input schema (JSON Schema)" htmlFor="tool-schema">
                <Textarea id="tool-schema" className="min-h-32 font-mono text-[12px]" value={schema} onChange={(e) => setSchema(e.target.value)} />
              </Field>
              <Field label="Constraints" htmlFor="tool-cons" hint='{"amount": {"max": 500}, "currency": {"one_of": ["EUR"]}}'>
                <Textarea id="tool-cons" className="min-h-32 font-mono text-[12px]" value={constraints} onChange={(e) => setConstraints(e.target.value)} />
              </Field>
            </div>
            {error && <FieldError>{error}</FieldError>}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={register.isPending}>
              {register.isPending ? "Registering..." : "Register tool"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
