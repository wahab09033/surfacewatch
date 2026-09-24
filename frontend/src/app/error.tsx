"use client";

/**
 * Error boundary for a page and for the authenticated layout itself.
 *
 * Next resolves a thrown error to the nearest boundary *above* the segment that
 * threw, which is why this file and `(app)/error.tsx` both exist:
 *
 *   * a crash inside a page        → `(app)/error.tsx`, shell intact
 *   * a crash inside `(app)/layout`→ this file, no shell
 *   * a crash on /login,/register  → this file
 *
 * It renders inside the root layout, so the theme, toast and auth providers are
 * still mounted around it. If those are what failed, `global-error.tsx` is the
 * next boundary out.
 */

import { CrashScreen } from "@/components/app/CrashScreen";

export default function RootError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return <CrashScreen error={error} reset={reset} full />;
}
