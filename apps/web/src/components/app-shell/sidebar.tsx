"use client";

import { ChevronRightIcon, PanelLeftCloseIcon, PanelLeftOpenIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as React from "react";

import { BrandLogo } from "@/components/brand";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { usePermissions } from "@/features/auth/api";
import { useApprovalCounts } from "@/features/approvals/api";
import { cn } from "@/lib/cn";
import { groupContains, isActive, NAV, visibleTo, type NavItem } from "@/lib/nav";
import { useUiPrefs } from "@/lib/store";

/** Small count next to an item: approvals waiting for a person. */
function useBadges(): Record<string, number> {
  const counts = useApprovalCounts();
  if (!counts.data) return {};
  return { "/approvals": counts.data.pending };
}

function NavLink({ item, active, collapsed, badge, onNavigate }: { item: NavItem; active: boolean; collapsed: boolean; badge?: number; onNavigate?: () => void }) {
  const link = (
    <Link
      href={item.href}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-[13px] font-medium text-muted-foreground transition-colors outline-none hover:bg-accent/70 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring",
        active && "bg-card text-foreground shadow-[var(--elev-1)] hover:bg-card dark:bg-accent dark:hover:bg-accent",
        collapsed && "justify-center px-0",
      )}
    >
      <item.icon className={cn("size-4 shrink-0", active ? "text-primary" : "text-subtle group-hover:text-foreground")} />
      {!collapsed && <span className="flex-1 truncate">{item.label}</span>}
      {!collapsed && !!badge && (
        <span className="tabular rounded-full bg-warning-soft px-1.5 text-[11px] leading-5 font-semibold text-warning">{badge}</span>
      )}
      {collapsed && <span className="sr-only">{item.label}</span>}
    </Link>
  );
  return collapsed ? (
    <Tooltip>
      <TooltipTrigger render={link} />
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  ) : (
    link
  );
}

export function SidebarNav({ collapsed = false, onNavigate }: { collapsed?: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { user } = usePermissions();
  const badges = useBadges();
  const settingsOpen = useUiPrefs((s) => s.settingsOpen);
  const setSettingsOpen = useUiPrefs((s) => s.setSettingsOpen);
  const groups = NAV.map((g) => ({ ...g, items: g.items.filter((i) => visibleTo(i, user?.role)) })).filter((g) => g.items.length);
  return (
    <nav aria-label="Main" className="flex flex-col gap-5">
      {groups.map((group) => {
        const open = !group.collapsible || collapsed || settingsOpen || groupContains(group, pathname);
        const id = `nav-${group.label.toLowerCase()}`;
        return (
          <div key={group.label} className="flex flex-col gap-0.5">
            {collapsed ? (
              <div className="mx-auto mb-1 h-px w-5 bg-hairline first:hidden" aria-hidden />
            ) : group.collapsible ? (
              <button
                type="button"
                aria-expanded={open}
                aria-controls={id}
                onClick={() => setSettingsOpen(!open)}
                className="flex items-center gap-1 rounded-md px-2.5 pb-1 text-left text-[10.5px] font-semibold tracking-[0.08em] text-faint uppercase hover:text-muted-foreground focus-visible:outline-2 focus-visible:outline-ring"
              >
                {group.label}
                <ChevronRightIcon className={cn("size-3 transition-transform", open && "rotate-90")} />
              </button>
            ) : (
              <div className="px-2.5 pb-1 text-[10.5px] font-semibold tracking-[0.08em] text-faint uppercase">{group.label}</div>
            )}
            {open && (
              <div id={id} className="flex flex-col gap-0.5">
                {group.items.map((item) => (
                  <NavLink
                    key={item.href}
                    item={item}
                    active={isActive(item, pathname)}
                    collapsed={collapsed}
                    badge={badges[item.href]}
                    onNavigate={onNavigate}
                  />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </nav>
  );
}

export function Sidebar() {
  const collapsed = useUiPrefs((s) => s.sidebarCollapsed);
  const toggle = useUiPrefs((s) => s.toggleSidebar);
  return (
    <div className={cn("hidden shrink-0 bg-sidebar transition-[width] duration-200 lg:block", collapsed ? "w-[60px]" : "w-[236px]")}>
      <aside className="sticky top-0 flex h-dvh flex-col">
        <div className={cn("flex h-14 items-center", collapsed ? "justify-center" : "px-4")}>
          <Link href="/overview" className="rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="AgentGuard overview">
            <BrandLogo collapsed={collapsed} />
          </Link>
        </div>
        <div className={cn("no-scrollbar flex-1 overflow-y-auto pt-2 pb-4", collapsed ? "px-2" : "px-3")}>
          <SidebarNav collapsed={collapsed} />
        </div>
        <div className={cn("pb-3", collapsed ? "px-2" : "px-3")}>
          <button
            type="button"
            onClick={toggle}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "flex h-8 w-full items-center gap-2.5 rounded-lg px-2.5 text-[12.5px] text-subtle transition-colors hover:bg-accent/70 hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring",
              collapsed && "justify-center px-0",
            )}
          >
            {collapsed ? <PanelLeftOpenIcon className="size-4" /> : <PanelLeftCloseIcon className="size-4" />}
            {!collapsed && "Collapse"}
          </button>
        </div>
      </aside>
    </div>
  );
}
