"use client";

/**
 * Live scan log stream over `/ws/scan/{scan_id}`.
 *
 * The backend publishes to the Redis channel `scan:{id}:logs` and this socket
 * relays it. On connect the server sends a snapshot, replays recent history,
 * then streams live events until a terminal `end` event, at which point it
 * closes the socket itself.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { scanSocketUrl } from "./api";
import { isTerminalScanStatus } from "./types";
import type { LogLevel, ScanStatus, WsEvent } from "./types";

export interface TerminalLine {
  /** Stable key for React; the API does not give live events an id. */
  key: string;
  timestamp: string;
  level: LogLevel;
  stage: string | null;
  message: string;
}

export type ConnectionState = "idle" | "connecting" | "open" | "closed" | "error";

export interface ScanStreamState {
  lines: TerminalLine[];
  status: ScanStatus | null;
  stage: string | null;
  progress: number;
  assetsDiscovered: number;
  findingsCount: number;
  connection: ConnectionState;
  /** Set when the stream ends for a reason worth showing the user. */
  notice: string | null;
  clear: () => void;
}

/** Cap retained lines. A full-port scan emits thousands; the DOM will not. */
const MAX_LINES = 2_000;

// WebSocket close codes the backend uses (RFC 6455 private range).
const WS_UNAUTHORIZED = 4401;
const WS_NOT_FOUND = 4404;

export function useScanStream(
  scanId: string | null,
  options: { replay?: number; onEnd?: (status: ScanStatus) => void } = {},
): ScanStreamState {
  const { replay = 200, onEnd } = options;

  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [assetsDiscovered, setAssets] = useState(0);
  const [findingsCount, setFindings] = useState(0);
  const [connection, setConnection] = useState<ConnectionState>("idle");
  const [notice, setNotice] = useState<string | null>(null);

  // Kept in a ref so a changing callback identity does not tear down the socket.
  const onEndRef = useRef(onEnd);
  onEndRef.current = onEnd;

  const counter = useRef(0);
  const socketRef = useRef<WebSocket | null>(null);

  const append = useCallback((line: Omit<TerminalLine, "key">) => {
    counter.current += 1;
    const keyed: TerminalLine = { ...line, key: `l${counter.current}` };
    setLines((previous) => {
      const next = previous.length >= MAX_LINES ? previous.slice(-MAX_LINES + 1) : previous;
      return [...next, keyed];
    });
  }, []);

  const clear = useCallback(() => setLines([]), []);

  useEffect(() => {
    if (!scanId) {
      setConnection("idle");
      return;
    }

    setLines([]);
    setNotice(null);
    setConnection("connecting");
    counter.current = 0;

    let socket: WebSocket;
    try {
      socket = new WebSocket(scanSocketUrl(scanId, replay));
    } catch {
      setConnection("error");
      setNotice("Could not open the live stream.");
      return;
    }
    socketRef.current = socket;

    // The server closes deliberately after a terminal event. Distinguishing
    // that from a dropped connection decides whether we show an error.
    let endedCleanly = false;

    socket.onopen = () => setConnection("open");

    socket.onmessage = (raw: MessageEvent<string>) => {
      let event: WsEvent;
      try {
        event = JSON.parse(raw.data) as WsEvent;
      } catch {
        return; // Malformed frame: drop it, keep the stream alive.
      }

      switch (event.type) {
        case "snapshot":
          setStatus(event.status);
          setStage(event.stage);
          setProgress(event.progress);
          setAssets(event.assets_discovered);
          setFindings(event.findings_count);
          break;

        case "log":
          append({
            timestamp: event.timestamp,
            level: event.level,
            stage: event.stage,
            message: event.message,
          });
          break;

        case "status":
          setStatus(event.status);
          setStage(event.stage);
          if (typeof event.progress === "number") setProgress(event.progress);
          break;

        case "result": {
          // Structured mid-scan results also surface as terminal lines so the
          // operator sees discoveries as they land, not only at the end.
          const count = Array.isArray(event.payload)
            ? event.payload.length
            : (event.payload as { ports?: unknown[] })?.ports?.length;
          append({
            timestamp: event.timestamp,
            level: "info",
            stage: null,
            message:
              count === undefined
                ? `→ ${event.kind}`
                : `→ ${event.kind}: ${count} item${count === 1 ? "" : "s"}`,
          });
          break;
        }

        case "end":
          endedCleanly = true;
          setStatus(event.status);
          setProgress(100);
          onEndRef.current?.(event.status);
          break;

        case "error":
          setNotice(event.message);
          break;

        case "ping":
          break; // Keepalive; nothing to render.
      }
    };

    socket.onerror = () => {
      // onerror fires without detail by design (it would otherwise leak
      // cross-origin info). onclose carries the code, so report from there.
      if (!endedCleanly) setConnection("error");
    };

    socket.onclose = (event: CloseEvent) => {
      setConnection("closed");
      if (endedCleanly) return;

      if (event.code === WS_UNAUTHORIZED) {
        setNotice("Your session expired. Sign in again to watch this scan.");
      } else if (event.code === WS_NOT_FOUND) {
        setNotice("That scan no longer exists.");
      } else if (event.code !== 1000 && event.code !== 1001) {
        setNotice("Live stream disconnected. Reload to reconnect.");
      }
    };

    return () => {
      // Detach handlers before closing: a close during unmount would otherwise
      // call setState on an unmounted component.
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close(1000, "navigating away");
      }
      socketRef.current = null;
    };
  }, [scanId, replay, append]);

  return {
    lines,
    status,
    stage,
    progress,
    assetsDiscovered,
    findingsCount,
    connection,
    notice,
    clear,
  };
}

export { isTerminalScanStatus };
