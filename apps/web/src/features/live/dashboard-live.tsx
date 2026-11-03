"use client";

import { useQueryClient } from "@tanstack/react-query";
import * as React from "react";
import { toast } from "sonner";

import { useSocket, type SocketStatus } from "@/hooks/use-socket";
import { loginUrl } from "@/lib/auth-redirect";
import { dashboardKeysFor, socketUrl, type LiveEvent } from "@/lib/live-events";
import { qk } from "@/lib/query-keys";

interface LiveContextValue {
  status: SocketStatus;
}

const LiveContext = React.createContext<LiveContextValue>({ status: "idle" });

/**
 * One dashboard WebSocket for the whole app (cookie auth, through the /ws rewrite). Each
 * event is an invalidation: the matching React Query keys refetch over REST, so a missed
 * event only delays an update. While the socket is down, live views poll instead (see
 * `useLivePolling`).
 */
export function DashboardLiveProvider({ children }: { children: React.ReactNode }) {
  const client = useQueryClient();
  const [url, setUrl] = React.useState<string | null>(null);
  React.useEffect(() => {
    setUrl(socketUrl("/ws/dashboard", window.location, process.env.NEXT_PUBLIC_WS_URL || null));
  }, []);
  const onEvent = React.useCallback(
    (event: LiveEvent) => {
      for (const key of dashboardKeysFor(event)) void client.invalidateQueries({ queryKey: key });
    },
    [client],
  );
  // 4401: the API refused the session (signed out elsewhere, or the user was disabled).
  const onRefused = React.useCallback(
    (code: number) => {
      if (code !== 4401 || typeof window === "undefined") return;
      const hadSession = !!client.getQueryData<{ user?: unknown }>(qk.me)?.user;
      client.clear();
      if (hadSession) toast.error("Your session ended. Sign in again.", { id: "session-expired" });
      window.location.assign(loginUrl(window.location.pathname, window.location.search, "expired"));
    },
    [client],
  );
  const { status } = useSocket(url, onEvent, onRefused);
  const value = React.useMemo(() => ({ status }), [status]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveContextValue {
  return React.useContext(LiveContext);
}

/** Poll interval for live views: none while the socket is open, 15 s while it is not. */
export function useLivePolling(): number | false {
  const { status } = useLive();
  return status === "open" ? false : 15_000;
}
