"use client";

import { ArrowLeftIcon, BanIcon, CheckCircle2Icon, CodeIcon, LayoutListIcon, SaveIcon, Trash2Icon, TriangleAlertIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { StatusChip } from "@/components/badges";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorState } from "@/components/error-state";
import { GatedButton } from "@/components/gated";
import { PageHeader } from "@/components/page-header";
import { Surface } from "@/components/surface";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePermissions } from "@/features/auth/api";
import { errorMessage } from "@/lib/api/errors";
import type { PolicyDetail } from "@/lib/api/types";
import { cleanPolicyError, parsePolicy, policyToYaml, POLICY_TEMPLATE, type PolicyModel } from "@/lib/policy-model";

import { usePolicy, usePolicyAction, useSavePolicy, useValidatePolicy } from "../api";
import { SimulatePanel, TestPanel, VersionsPanel } from "./policy-panels";
import { VisualBuilder } from "./visual-builder";
import { YamlEditor } from "./yaml-editor";

type Validation = { state: "idle" | "checking" | "valid" | "invalid"; error?: string | null };

/** Validate the YAML with the API, debounced, so errors come from the real compiler. */
function useLiveValidation(source: string): Validation {
  const validate = useValidatePolicy();
  const [v, setV] = React.useState<Validation>({ state: "idle" });
  const mutate = validate.mutateAsync;
  React.useEffect(() => {
    if (!source.trim()) {
      setV({ state: "invalid", error: "The policy is empty." });
      return;
    }
    setV((old) => ({ ...old, state: "checking" }));
    let cancelled = false;
    const t = setTimeout(() => {
      mutate(source)
        .then((r) => !cancelled && setV(r.valid ? { state: "valid" } : { state: "invalid", error: cleanPolicyError(r.error ?? "The policy does not compile.") }))
        .catch((e) => !cancelled && setV({ state: "invalid", error: errorMessage(e) }));
    }, 450);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [source, mutate]);
  return v;
}

function ValidationBadge({ v }: { v: Validation }) {
  if (v.state === "valid")
    return (
      <Chip tone="success">
        <CheckCircle2Icon />
        Compiles
      </Chip>
    );
  if (v.state === "invalid")
    return (
      <Chip tone="danger">
        <TriangleAlertIcon />
        Does not compile
      </Chip>
    );
  return <Chip>Checking...</Chip>;
}

function SaveDialog({ open, onOpenChange, onSave, pending, isNew }: { open: boolean; onOpenChange: (o: boolean) => void; onSave: (activate: boolean, comment: string) => void; pending: boolean; isNew: boolean }) {
  const [activate, setActivate] = React.useState(true);
  const [comment, setComment] = React.useState("");
  React.useEffect(() => {
    if (open) {
      setActivate(true);
      setComment("");
    }
  }, [open]);
  return (
    <Dialog open={open} onOpenChange={(o) => !pending && onOpenChange(o)}>
      <DialogContent className="max-w-md">
        <form
          className="flex min-h-0 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            onSave(activate, comment.trim());
          }}
        >
          <DialogHeader>
            <DialogTitle>{isNew ? "Create the policy" : "Save a new version"}</DialogTitle>
            <DialogDescription>Versions are kept forever; you can roll back at any time.</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <Field label="What changed" htmlFor="save-comment">
              <Input id="save-comment" autoFocus value={comment} placeholder="Raise the refund threshold to 500" onChange={(e) => setComment(e.target.value)} />
            </Field>
            <label className="flex items-start gap-3 rounded-lg bg-muted/70 p-3">
              <Switch checked={activate} onCheckedChange={setActivate} aria-label="Activate now" />
              <span className="text-[13px]">
                <span className="font-medium">Activate now</span>
                <span className="block text-[12px] text-muted-foreground">Off saves a draft version that decides nothing until you activate it.</span>
              </span>
            </label>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? "Saving..." : activate ? "Save and activate" : "Save draft"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Editor({ policy }: { policy?: PolicyDetail }) {
  const router = useRouter();
  const { can } = usePermissions();
  const editable = can("write");
  const [source, setSource] = React.useState(policy?.source ?? POLICY_TEMPLATE);
  const [baseline, setBaseline] = React.useState(policy?.source ?? "");
  const [viewing, setViewing] = React.useState<number | null>(null);
  const [mode, setMode] = React.useState<"visual" | "yaml">("visual");
  const [model, setModel] = React.useState<PolicyModel | null>(() => {
    const r = parsePolicy(policy?.source ?? POLICY_TEMPLATE);
    return r.ok && !r.unknown.length ? r.model : null;
  });
  const [visualIssue, setVisualIssue] = React.useState<string | null>(null);
  const [saveOpen, setSaveOpen] = React.useState(false);
  const [confirm, setConfirm] = React.useState<"disable" | "delete" | null>(null);
  const save = useSavePolicy();
  const act = usePolicyAction();
  const validation = useLiveValidation(source);

  function toVisual(src: string): boolean {
    const r = parsePolicy(src);
    if (!r.ok) {
      setVisualIssue(`${r.error} Fix it in YAML first.`);
      return false;
    }
    if (r.unknown.length) {
      setVisualIssue(`The visual builder does not edit ${r.unknown.slice(0, 3).join(", ")}. Keep editing in YAML so nothing is lost.`);
      return false;
    }
    setVisualIssue(null);
    setModel(r.model);
    return true;
  }

  function switchMode(next: "visual" | "yaml") {
    if (next === "visual" && !toVisual(source)) {
      setMode("visual");
      return;
    }
    setMode(next);
  }

  React.useEffect(() => {
    toVisual(policy?.source ?? POLICY_TEMPLATE);
    // Only on load: later switches re-parse explicitly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dirty = source !== baseline;
  const readOnly = !editable || viewing != null;

  function doSave(activate: boolean, comment: string) {
    save.mutate(
      { id: policy?.id, source, activate, comment },
      {
        onSuccess: (p) => {
          setSaveOpen(false);
          setBaseline(source);
          toast.success(activate ? `${p.name} v${p.latest_version} is active. The next decision follows it.` : `Draft v${p.latest_version} saved.`);
          if (!policy) router.replace(`/policies/${p.id}`);
        },
        onError: (e) => toast.error(errorMessage(e)),
      },
    );
  }

  const name = (model?.name || policy?.name || "New policy").trim();
  return (
    <>
      <Link href="/policies" className="mb-3 inline-flex items-center gap-1.5 rounded-md text-[12.5px] text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
        <ArrowLeftIcon className="size-3.5" />
        Policies
      </Link>
      <PageHeader
        eyebrow={
          <div className="flex flex-wrap items-center gap-1.5">
            {policy ? <StatusChip kind="policy" status={policy.status} /> : <Chip tone="primary">New</Chip>}
            {policy?.builtin && <Chip tone="info">Built in</Chip>}
            {policy && <Chip>v{policy.active_version ?? policy.latest_version}</Chip>}
            <ValidationBadge v={validation} />
          </div>
        }
        title={<span className="font-mono">{name}</span>}
        description={policy?.description || "Write the rules, test one request, simulate against history, then save and activate."}
        actions={
          <>
            {policy && policy.status === "active" && (
              <GatedButton need="write" variant="outline" size="sm" onClick={() => setConfirm("disable")}>
                <BanIcon />
                Disable
              </GatedButton>
            )}
            {policy && !policy.builtin && (
              <GatedButton need="write" variant="destructive-soft" size="sm" onClick={() => setConfirm("delete")}>
                <Trash2Icon />
                Delete
              </GatedButton>
            )}
            <GatedButton need="write" size="sm" disabled={validation.state === "invalid" || (!!policy && !dirty) || viewing != null} onClick={() => setSaveOpen(true)}>
              <SaveIcon />
              {policy ? "Save version" : "Create policy"}
            </GatedButton>
          </>
        }
      />
      {viewing != null && (
        <div role="status" className="mb-4 flex flex-wrap items-center gap-3 rounded-xl bg-info-soft px-4 py-3 text-[13px] text-info">
          Viewing v{viewing} (read only).
          <Button
            size="xs"
            variant="outline"
            onClick={() => {
              setViewing(null);
              setSource(baseline);
              toVisual(baseline);
            }}
          >
            Back to the current version
          </Button>
          {editable && (
            <Button size="xs" variant="ghost" onClick={() => setViewing(null)}>
              Edit from this version
            </Button>
          )}
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="min-w-0">
          <Tabs value={mode} onValueChange={(v) => switchMode(v as "visual" | "yaml")}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <TabsList>
                <TabsTrigger value="visual">
                  <LayoutListIcon />
                  Visual
                </TabsTrigger>
                <TabsTrigger value="yaml">
                  <CodeIcon />
                  YAML
                </TabsTrigger>
              </TabsList>
              {dirty && policy && <span className="text-[12px] text-warning">Unsaved changes</span>}
            </div>
            <TabsContent value="visual">
              {visualIssue || !model ? (
                <Surface className="p-5">
                  <p className="text-[13px] text-muted-foreground">{visualIssue ?? "This policy cannot be shown visually."}</p>
                  <Button className="mt-3" size="sm" variant="outline" onClick={() => setMode("yaml")}>
                    Open the YAML editor
                  </Button>
                </Surface>
              ) : (
                <VisualBuilder
                  model={model}
                  disabled={readOnly}
                  nameLocked={!!policy}
                  onChange={(m) => {
                    setModel(m);
                    setSource(policyToYaml(m));
                  }}
                />
              )}
            </TabsContent>
            <TabsContent value="yaml" className="space-y-2">
              <YamlEditor value={source} readOnly={readOnly} invalid={validation.state === "invalid"} onChange={setSource} />
              {validation.state === "invalid" && validation.error && (
                <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 font-mono text-[12px] text-danger">
                  {validation.error}
                </p>
              )}
            </TabsContent>
          </Tabs>
        </div>
        <div className="min-w-0 space-y-4">
          <TestPanel
            source={source}
            defaults={{
              tool: model?.tools.find((t) => !t.includes("*")) ?? model?.rules.flatMap((r) => r.tools).find((t) => !t.includes("*")),
              action: model?.rules.flatMap((r) => r.actions).find((a) => a !== "*") ?? model?.actions[0],
            }}
          />
          <SimulatePanel source={source} policyId={policy?.id} />
          {policy && (
            <VersionsPanel
              policy={policy}
              onLoad={(src, version) => {
                setViewing(version === (policy.active_version ?? policy.latest_version) ? null : version);
                setSource(src);
                toVisual(src);
              }}
            />
          )}
        </div>
      </div>
      <SaveDialog open={saveOpen} onOpenChange={setSaveOpen} onSave={doSave} pending={save.isPending} isNew={!policy} />
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={confirm === "delete" ? `Delete ${policy?.name}?` : `Disable ${policy?.name}?`}
        description={
          confirm === "delete"
            ? "Its versions are removed. Past decisions keep the policy name and version they recorded."
            : "It stops deciding immediately. Activate a version to turn it back on."
        }
        confirmLabel={confirm === "delete" ? "Delete policy" : "Disable"}
        pending={act.isPending}
        onConfirm={() =>
          policy &&
          confirm &&
          act.mutate(
            { id: policy.id, action: confirm },
            {
              onSuccess: () => {
                setConfirm(null);
                toast.success(confirm === "delete" ? "Policy deleted." : "Policy disabled.");
                if (confirm === "delete") router.replace("/policies");
              },
              onError: (e) => toast.error(errorMessage(e)),
            },
          )
        }
      />
    </>
  );
}

export function NewPolicyScreen() {
  return <Editor />;
}

export function EditPolicyScreen({ id }: { id: string }) {
  const q = usePolicy(id);
  if (q.isPending)
    return (
      <div className="space-y-4" aria-busy>
        <Skeleton className="h-10 w-full max-w-96" />
        <Skeleton className="h-[480px]" />
      </div>
    );
  if (q.isError)
    return (
      <Surface>
        <ErrorState error={q.error} title="Could not load this policy" onRetry={() => void q.refetch()} />
      </Surface>
    );
  return <Editor key={`${q.data.id}`} policy={q.data} />;
}
