"use client";

import { TriangleAlertIcon } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/** A key or signing secret shown once, with a copy button. */
export function SecretOnceDialog({ value, title, description, onClose }: { value: string | null; title: string; description: string; onClose: () => void }) {
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <div role="note" className="flex items-start gap-2 rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning">
            <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
            This is the only time it is shown. Store it in your secret manager now.
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2">
            <code className="min-w-0 flex-1 font-mono text-[12.5px] break-all">{value}</code>
            {value && <CopyButton value={value} iconOnly label="Copy" variant="subtle" />}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button onClick={onClose}>I stored it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
