"use client";

import { TriangleAlertIcon } from "lucide-react";
import * as React from "react";

import { CopyButton } from "@/components/copy-button";
import { CodeBlock } from "@/components/json-view";
import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { Issued } from "@/lib/api/types";
import { baseFromTokenUrl, envSnippet, nodeSnippet, publicBaseUrl, pythonSnippet } from "@/lib/snippets";

function SecretRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <div className="text-[12px] font-medium text-muted-foreground">{label}</div>
      <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
        <code className="min-w-0 flex-1 font-mono text-[12.5px] break-all">{value}</code>
        <CopyButton value={value} iconOnly label={`Copy ${label.toLowerCase()}`} variant="subtle" />
      </div>
    </div>
  );
}

/**
 * The only time a client secret and signing secret are visible. AgentGuard stores a hash,
 * so closing this dialog loses them for good; the copy says so plainly.
 */
export function CredentialDialog({ issued, signed, onClose }: { issued: Issued | null; signed: boolean; onClose: () => void }) {
  const [base, setBase] = React.useState("");
  React.useEffect(() => {
    setBase(baseFromTokenUrl(issued?.token_url) ?? publicBaseUrl(window.location));
  }, [issued]);
  const input = { baseUrl: base, clientId: issued?.client_id ?? "", signed };
  return (
    <Dialog open={!!issued} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Copy the credential now</DialogTitle>
          <DialogDescription>This is the only time the secrets are shown. AgentGuard keeps only a hash, so store them in your secret manager before closing.</DialogDescription>
        </DialogHeader>
        {issued && (
          <DialogBody className="space-y-4">
            <div role="note" className="flex items-start gap-2 rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning">
              <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
              Lost secrets cannot be recovered. Rotate the credential to get a new pair.
            </div>
            <SecretRow label="Client id" value={issued.client_id} />
            <SecretRow label="Client secret" value={issued.client_secret} />
            <SecretRow label="Signing secret" value={issued.signing_secret} />
            <SecretRow label="Token URL" value={issued.token_url} />
            <Tabs defaultValue="python">
              <TabsList>
                <TabsTrigger value="python">Python</TabsTrigger>
                <TabsTrigger value="node">Node.js</TabsTrigger>
                <TabsTrigger value="env">.env</TabsTrigger>
              </TabsList>
              <TabsContent value="python">
                <CodeBlock code={pythonSnippet(input)} label="Python snippet" />
              </TabsContent>
              <TabsContent value="node">
                <CodeBlock code={nodeSnippet(input)} label="Node.js snippet" />
              </TabsContent>
              <TabsContent value="env">
                <CodeBlock code={envSnippet(input)} label="Environment" />
              </TabsContent>
            </Tabs>
          </DialogBody>
        )}
        <DialogFooter>
          <Button onClick={onClose}>I stored the secrets</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
