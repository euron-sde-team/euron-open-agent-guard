"use client";

import { MenuIcon } from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { BrandLogo } from "@/components/brand";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useLive } from "@/features/live/dashboard-live";
import { useSettings } from "@/features/org/api";
import { cn } from "@/lib/cn";

import { SidebarNav } from "./sidebar";
import { UserMenu } from "./user-menu";

/** Enforce or audit: the single most important fact about how decisions apply. */
function ModeBadge() {
  const settings = useSettings();
  const mode = settings.data?.enforcement.mode;
  if (!mode) return null;
  const enforce = mode === "enforce";
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Link
            href="/settings"
            className={cn(
              "hidden h-7 items-center gap-1.5 rounded-full px-2.5 text-[11.5px] font-semibold focus-visible:outline-2 focus-visible:outline-ring sm:inline-flex",
              enforce ? "bg-primary-soft text-primary" : "bg-warning-soft text-warning",
            )}
          />
        }
      >
        <span className={cn("size-1.5 rounded-full", enforce ? "bg-primary" : "bg-warning")} aria-hidden />
        {enforce ? "Enforce mode" : "Audit mode"}
      </TooltipTrigger>
      <TooltipContent>
        {enforce
          ? "Decisions are binding: a deny never reaches the tool."
          : "Nothing is blocked: decisions are recorded as what they would have been. Switch to enforce in Settings."}
      </TooltipContent>
    </Tooltip>
  );
}

/** Whether live updates are flowing. When not, views poll every few seconds instead. */
function LiveIndicator() {
  const { status } = useLive();
  const open = status === "open";
  return (
    <Tooltip>
      <TooltipTrigger
        render={<span tabIndex={0} className="inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[11.5px] text-subtle focus-visible:outline-2 focus-visible:outline-ring" />}
      >
        <span className="relative flex size-2">
          {open && <span className="absolute inline-flex size-full animate-ping rounded-full bg-savings opacity-40 motion-reduce:hidden" />}
          <span className={cn("relative inline-flex size-2 rounded-full", open ? "bg-savings" : status === "connecting" || status === "idle" ? "bg-faint" : "bg-warning")} />
        </span>
        <span className="hidden sm:inline">{open ? "Live" : status === "connecting" || status === "idle" ? "Connecting" : "Reconnecting"}</span>
      </TooltipTrigger>
      <TooltipContent>
        {open ? "Decisions, approvals and threats appear as they happen." : "Live updates are reconnecting. Pages refresh every 15 seconds meanwhile."}
      </TooltipContent>
    </Tooltip>
  );
}

export function Topbar() {
  const [menuOpen, setMenuOpen] = React.useState(false);
  return (
    <header className="sticky top-0 z-30 bg-background/80 backdrop-blur-md supports-[backdrop-filter]:bg-background/70">
      <div className="flex h-14 items-center gap-2 px-4 sm:px-6 lg:px-8">
        <Button variant="subtle" size="icon" className="-ml-2 lg:hidden" aria-label="Open navigation" onClick={() => setMenuOpen(true)}>
          <MenuIcon />
        </Button>
        <Link href="/overview" className="rounded-lg lg:hidden" aria-label="AgentGuard overview">
          <BrandLogo />
        </Link>
        <div className="ml-auto flex items-center gap-1.5">
          <ModeBadge />
          <LiveIndicator />
          <ThemeToggle />
          <UserMenu />
        </div>
      </div>
      <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
        <SheetContent side="left" className="bg-sidebar">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <div className="flex h-14 items-center px-4">
            <BrandLogo />
          </div>
          <div className="overflow-y-auto px-3 pb-6">
            <SidebarNav onNavigate={() => setMenuOpen(false)} />
          </div>
        </SheetContent>
      </Sheet>
    </header>
  );
}
