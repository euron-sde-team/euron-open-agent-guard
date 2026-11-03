"use client";

import * as React from "react";

import { ErrorState } from "@/components/error-state";
import { PageHeader } from "@/components/page-header";
import { Surface } from "@/components/surface";
import { ThemeSelector } from "@/components/theme-toggle";
import { Skeleton } from "@/components/ui/skeleton";
import { usePermissions } from "@/features/auth/api";
import { cn } from "@/lib/cn";
import { roleLabel } from "@/lib/roles";

import { useOrg, useSettings, useSystem } from "../api";
import { LimitsSection, PeopleSection, ProjectsSection, SsoSection } from "./settings-people";
import { DetectionSection, EnforcementSection, KillSwitchSection, NotificationsSection, ResponsesSection, RetentionSection } from "./settings-sections";

const INDEX = [
  { id: "enforcement", label: "Enforcement" },
  { id: "kill-switch", label: "Kill switch" },
  { id: "detection", label: "Detection" },
  { id: "responses", label: "Threat responses" },
  { id: "limits", label: "Limits" },
  { id: "people", label: "Users and roles" },
  { id: "sso", label: "Single sign-on" },
  { id: "projects", label: "Projects" },
  { id: "notifications", label: "Notifications" },
  { id: "retention", label: "Retention" },
  { id: "appearance", label: "Appearance" },
];

function SystemCard() {
  const { can } = usePermissions();
  const q = useSystem(can("admin"));
  if (!q.data) return null;
  const s = q.data;
  return (
    <p className="text-[12px] text-subtle">
      AgentGuard {s.version} · {s.environment} · keys {s.key_mode} · storage {s.storage} · cache {s.cache} · {s.live_connections} live connections
    </p>
  );
}

export function SettingsScreen() {
  const settings = useSettings();
  const org = useOrg();
  const { can, role } = usePermissions();
  const [active, setActive] = React.useState("enforcement");
  React.useEffect(() => {
    const els = INDEX.map((i) => document.getElementById(i.id)).filter((e): e is HTMLElement => !!e);
    if (!els.length || typeof IntersectionObserver === "undefined") return;
    const obs = new IntersectionObserver((entries) => {
      const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible) setActive(visible.target.id);
    }, { rootMargin: "-80px 0px -60% 0px" });
    els.forEach((e) => obs.observe(e));
    return () => obs.disconnect();
  }, [settings.data]);

  return (
    <>
      <PageHeader
        title="Settings"
        description={
          <>
            {org.data ? `${org.data.name} (${org.data.slug}). ` : ""}
            {can("admin") ? "You can change everything here." : `Your role (${roleLabel(role)}) can read these settings; org admins change them.`}
          </>
        }
      />
      {settings.isPending ? (
        <div className="space-y-4" aria-busy>
          <Skeleton className="h-56 rounded-[14px]" />
          <Skeleton className="h-28 rounded-[14px]" />
        </div>
      ) : settings.isError ? (
        <Surface>
          <ErrorState error={settings.error} title="Could not load the settings" onRetry={() => void settings.refetch()} />
        </Surface>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[180px_minmax(0,1fr)]">
          <nav aria-label="Settings sections" className="hidden lg:block">
            <ul className="sticky top-20 space-y-0.5">
              {INDEX.map((i) => (
                <li key={i.id}>
                  <a
                    href={`#${i.id}`}
                    className={cn(
                      "block rounded-md px-2.5 py-1.5 text-[12.5px] text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring",
                      active === i.id && "bg-card font-medium text-foreground shadow-[var(--elev-1)] dark:bg-accent",
                    )}
                  >
                    {i.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <div className="min-w-0 space-y-4">
            <EnforcementSection settings={settings.data} />
            <KillSwitchSection settings={settings.data} />
            <DetectionSection settings={settings.data} />
            <ResponsesSection settings={settings.data} />
            <LimitsSection />
            <PeopleSection />
            <SsoSection />
            <ProjectsSection />
            <NotificationsSection settings={settings.data} />
            <RetentionSection settings={settings.data} />
            <Surface id="appearance" className="scroll-mt-20 p-5">
              <h2 className="mb-1 text-[14px] font-semibold">Appearance</h2>
              <p className="mb-3 text-[12.5px] text-muted-foreground">Only for this browser.</p>
              <ThemeSelector />
            </Surface>
            <SystemCard />
          </div>
        </div>
      )}
    </>
  );
}
