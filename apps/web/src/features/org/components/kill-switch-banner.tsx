"use client";

import { OctagonXIcon } from "lucide-react";
import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";
import { formatRelative } from "@/lib/format";

import { useSettings } from "../api";

/** Shown on every page while the kill switch is on: every agent action is denied. */
export function KillSwitchBanner() {
  const settings = useSettings();
  const ks = settings.data?.kill_switch;
  if (!ks?.active) return null;
  return (
    <div role="alert" className="mx-4 mt-1 flex flex-col gap-3 rounded-xl bg-danger px-4 py-3 text-danger-foreground shadow-[var(--elev-2)] sm:mx-6 sm:flex-row sm:items-center lg:mx-8">
      <OctagonXIcon className="size-5 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1 text-[13px] leading-snug">
        <div className="font-semibold">Kill switch is on: every agent action is denied.</div>
        <div className="opacity-90">
          {ks.reason ? `"${ks.reason}"` : "No reason given"}
          {ks.by ? `, by ${ks.by}` : ""}
          {ks.at ? ` ${formatRelative(ks.at)}` : ""}.
        </div>
      </div>
      <Link href="/settings#kill-switch" className={buttonVariants({ size: "sm", variant: "secondary", className: "shrink-0 bg-white/15 text-inherit hover:bg-white/25" })}>
        Review in Settings
      </Link>
    </div>
  );
}
