"use client";

import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

/**
 * Persisted UI preferences only (never server data). Rehydrated after mount so the
 * first client render matches the server render. The theme itself is persisted by
 * next-themes.
 */
interface UiPrefs {
  sidebarCollapsed: boolean;
  settingsOpen: boolean;
  toggleSidebar: () => void;
  setSettingsOpen: (open: boolean) => void;
}

export const useUiPrefs = create<UiPrefs>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      settingsOpen: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSettingsOpen: (open) => set({ settingsOpen: open }),
    }),
    {
      name: "agentguard.ui",
      version: 3,
      skipHydration: true,
      storage: createJSONStorage(() => localStorage),
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed, settingsOpen: s.settingsOpen }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<UiPrefs>;
        const bool = (v: unknown, d: boolean) => (typeof v === "boolean" ? v : d);
        return { ...current, sidebarCollapsed: bool(p.sidebarCollapsed, current.sidebarCollapsed), settingsOpen: bool(p.settingsOpen, current.settingsOpen) };
      },
    },
  ),
);
