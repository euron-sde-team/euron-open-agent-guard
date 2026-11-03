"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/input";
import { FieldError, FieldHint, Label } from "@/components/ui/label";

/**
 * A confirmation that needs a written reason (suspend, quarantine, revoke, kill switch,
 * reject). The reason goes to the audit log. The dialog stays open until the action settles.
 */
export function ReasonDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  onConfirm,
  pending = false,
  destructive = true,
  required = true,
  label = "Reason",
  placeholder = "What happened, and why this is the right action",
  hint = "Recorded in the audit log with your name.",
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  confirmLabel: string;
  onConfirm: (reason: string) => void;
  pending?: boolean;
  destructive?: boolean;
  required?: boolean;
  label?: string;
  placeholder?: string;
  hint?: string;
  children?: React.ReactNode;
}) {
  const [reason, setReason] = React.useState("");
  const [touched, setTouched] = React.useState(false);
  React.useEffect(() => {
    if (open) {
      setReason("");
      setTouched(false);
    }
  }, [open]);
  const missing = required && !reason.trim();
  function submit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (missing) return;
    onConfirm(reason.trim());
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !pending && onOpenChange(o)}>
      <DialogContent className="max-w-md" showCloseButton={false}>
        <form onSubmit={submit} className="flex min-h-0 flex-col">
          <DialogHeader className="pr-6">
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3 pt-4 pb-5">
            {children}
            <div className="space-y-1.5">
              <Label htmlFor="reason-text">
                {label}
                {!required && <span className="font-normal text-subtle">(optional)</span>}
              </Label>
              <Textarea id="reason-text" autoFocus value={reason} placeholder={placeholder} onChange={(e) => setReason(e.target.value)} aria-invalid={(touched && missing) || undefined} />
              {touched && missing ? <FieldError>Write a reason first: it is how the next person understands what happened.</FieldError> : <FieldHint>{hint}</FieldHint>}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" variant={destructive ? "destructive" : "default"} disabled={pending}>
              {pending ? "Working..." : confirmLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
