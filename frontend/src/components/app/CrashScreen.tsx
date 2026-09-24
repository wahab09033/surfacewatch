"use client";

/**
 * What the console shows when a page throws.
 *
 * Both page-level boundaries use this, so a crash looks the same whether it took
 * the shell down with it or not. `global-error.tsx` is the third boundary and
 * deliberately does not: it replaces the root layout, so it has to render its
 * own `<html>`, cannot assume the stylesheet loaded, and cannot touch a provider
 * or the design system.
 *
 * Two deliberate choices:
 *
 * * **The error message is not shown.** A production React error is minified
 *   into something like "Minified React error #31"; the raw text is noise to the
 *   reader and can leak internals. What is shown is Next's `digest`, which is
 *   the only thing that ties this screen to a server log line.
 * * **"Go to dashboard" is a full page load**, not a client navigation. If the
 *   tree that crashed is anywhere near the router or a provider, pushing a route
 *   through it is how you get the same crash again. A reload is a clean slate.
 */

import { useEffect } from "react";

import { Button } from "@/components/ui/Button";
import { ErrorState } from "@/components/ui/EmptyState";

import { Logo } from "./icons";

export function CrashScreen({
  error,
  reset,
  full = false,
}: {
  error: Error & { digest?: string };
  reset: () => void;
  /** True outside the app shell, where there is no nav to fall back on. */
  full?: boolean;
}) {
  useEffect(() => {
    // No error-reporting service is wired up, so the browser console and the
    // server's own log line (via `digest`) are the whole record. Logging here
    // rather than only in the server log keeps the client-side message, which is
    // the one that actually names the component that threw.
    console.error("Unhandled error:", error);
  }, [error]);

  return (
    <div className={full ? "flex min-h-dvh flex-col items-center justify-center px-4" : ""}>
      {full ? (
        <div className="mb-4 flex items-center gap-2 text-muted">
          <Logo size={20} />
          <span className="text-sm font-medium text-text">SurfaceWatch</span>
        </div>
      ) : null}

      <div className="w-full max-w-md rounded-lg border border-border bg-bg shadow-panel">
        <ErrorState
          message="Something went wrong rendering this page. Nothing was lost — the data lives on the server, and this view can be rebuilt."
          onRetry={reset}
        />

        <div className="flex flex-col items-center gap-2 border-t border-border px-6 py-3.5">
          <Button onClick={() => window.location.assign("/dashboard")}>Go to dashboard</Button>
          {error.digest ? (
            <p className="text-xs text-muted">
              Reference <span className="font-mono tabular">{error.digest}</span> — it appears in the
              server log next to the cause.
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
