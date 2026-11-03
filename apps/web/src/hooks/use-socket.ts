"use client";

import * as React from "react";

import { parseLiveEvent, reconnectDelay, type LiveEvent } from "@/lib/live-events";

export type SocketStatus = "idle" | "connecting" | "open" | "closed";

/**
 * One WebSocket with reconnect and backoff. `url` null means "do not connect". A close
 * code in the 44xx range is the API refusing the credentials or the conversation: there is
 * no point retrying those, so the hook stops and reports `closed`.
 *
 * `onEvent` is read through a ref so a new callback never reopens the socket.
 */
export function useSocket(url: string | null, onEvent: (event: LiveEvent) => void, onRefused?: (code: number) => void) {
  const [status, setStatus] = React.useState<SocketStatus>("idle");
  const handler = React.useRef(onEvent);
  const refused = React.useRef(onRefused);
  React.useEffect(() => {
    refused.current = onRefused;
  }, [onRefused]);
  const socketRef = React.useRef<WebSocket | null>(null);
  React.useEffect(() => {
    handler.current = onEvent;
  }, [onEvent]);

  React.useEffect(() => {
    if (!url || typeof WebSocket === "undefined") {
      setStatus("idle");
      return;
    }
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;

    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch {
        schedule();
        return;
      }
      socketRef.current = ws;
      ws.onopen = () => {
        attempt = 0;
        setStatus("open");
      };
      ws.onmessage = (msg) => {
        const event = parseLiveEvent(msg.data);
        if (event) handler.current(event);
      };
      ws.onclose = (ev) => {
        socketRef.current = null;
        if (stopped) return;
        if (ev.code >= 4400 && ev.code < 4500) {
          setStatus("closed");
          refused.current?.(ev.code);
          return;
        }
        schedule();
      };
    };
    const schedule = () => {
      setStatus("closed");
      if (stopped) return;
      timer = setTimeout(connect, reconnectDelay(attempt++));
    };

    connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [url]);

  const send = React.useCallback((data: unknown) => {
    const ws = socketRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  }, []);

  return { status, send };
}
