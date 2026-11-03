import {
  BoxIcon,
  BotIcon,
  CheckCheckIcon,
  ClipboardCheckIcon,
  FileCode2Icon,
  GaugeIcon,
  GlobeLockIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  PlugIcon,
  ScrollTextIcon,
  SettingsIcon,
  ShieldAlertIcon,
  SirenIcon,
  UserCogIcon,
  WrenchIcon,
  type LucideIcon,
} from "lucide-react";

import type { Role } from "./roles";
import { atLeast } from "./roles";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** The lowest role that sees the item. */
  min?: Role;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
  /** Advanced groups start collapsed; core daily surfaces are always open. */
  collapsible?: boolean;
}

export const NAV: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { href: "/overview", label: "Overview", icon: LayoutDashboardIcon },
      { href: "/approvals", label: "Approvals", icon: CheckCheckIcon },
      { href: "/threats", label: "Threat detection", icon: ShieldAlertIcon },
      { href: "/incidents", label: "Incidents", icon: SirenIcon },
      { href: "/risk", label: "Risk center", icon: GaugeIcon },
    ],
  },
  {
    label: "Control",
    items: [
      { href: "/agents", label: "Agents", icon: BotIcon },
      { href: "/access", label: "Access control", icon: UserCogIcon },
      { href: "/policies", label: "Policy builder", icon: FileCode2Icon },
      { href: "/tools", label: "Tool security", icon: WrenchIcon },
      { href: "/secrets", label: "Secrets", icon: KeyRoundIcon },
      { href: "/network", label: "Network guard", icon: GlobeLockIcon },
      { href: "/sandboxes", label: "Sandboxes", icon: BoxIcon },
    ],
  },
  {
    label: "Evidence",
    items: [
      { href: "/audit", label: "Audit logs", icon: ScrollTextIcon },
      { href: "/compliance", label: "Compliance", icon: ClipboardCheckIcon },
    ],
  },
  {
    label: "Configure",
    items: [
      { href: "/integrations", label: "Integrations", icon: PlugIcon },
      { href: "/settings", label: "Settings", icon: SettingsIcon },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV.flatMap((g) => g.items);

/** Whether someone with this role sees an item. */
export function visibleTo(item: NavItem, role: string | null | undefined): boolean {
  if (!role) return false;
  return item.min ? atLeast(role, item.min) : true;
}

/** The nav item a path belongs to: the longest matching prefix. */
export function activeNavItem(pathname: string): NavItem | undefined {
  const path = pathname.replace(/\/+$/, "") || "/";
  return NAV_ITEMS.filter((i) => path === i.href || path.startsWith(`${i.href}/`)).sort((a, b) => b.href.length - a.href.length)[0];
}

export function isActive(item: NavItem, pathname: string): boolean {
  return activeNavItem(pathname)?.href === item.href;
}

export function groupContains(group: NavGroup, pathname: string): boolean {
  return group.items.some((i) => isActive(i, pathname));
}
