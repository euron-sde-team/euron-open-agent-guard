"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { BrandMark } from "@/components/brand";
import { ErrorState } from "@/components/error-state";
import { useMe } from "@/features/auth/api";
import { DashboardLiveProvider } from "@/features/live/dashboard-live";
import { KillSwitchBanner } from "@/features/org/components/kill-switch-banner";
import { loginUrl } from "@/lib/auth-redirect";

import { Sidebar } from "./sidebar";
import { Topbar } from "./topbar";

/**
 * Dashboard chrome. A missing or expired session sends the person to sign in; only a
 * failure to reach the API stops the page with an explanation.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const me = useMe();
  const router = useRouter();

  React.useEffect(() => {
    if (me.data === null) router.replace(loginUrl(window.location.pathname, window.location.search));
  }, [me.data, router]);

  if (me.isError) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background p-4">
        <div className="surface w-full max-w-md">
          <ErrorState error={me.error} title="AgentGuard is unreachable" onRetry={me.refetch} />
        </div>
      </div>
    );
  }

  if (!me.data) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background" aria-busy>
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <BrandMark className="size-10 animate-pulse" />
          <span className="text-[13px]">Loading AgentGuard...</span>
        </div>
      </div>
    );
  }

  return (
    <DashboardLiveProvider>
      <div className="flex min-h-dvh bg-background">
        <a
          href="#main"
          className="sr-only z-50 rounded-lg bg-card px-3 py-2 text-sm shadow-[var(--elev-3)] focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Skip to content
        </a>
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <KillSwitchBanner />
          <main id="main" className="mx-auto w-full max-w-[1500px] min-w-0 flex-1 px-4 pt-4 pb-16 sm:px-6 lg:px-8">
            {children}
          </main>
        </div>
      </div>
    </DashboardLiveProvider>
  );
}
