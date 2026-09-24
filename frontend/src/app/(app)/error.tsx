"use client";

/**
 * Error boundary for the authenticated pages.
 *
 * It sits inside `(app)/layout.tsx`, so a crash here replaces only the page: the
 * sidebar and header stay rendered and every other route still works. That is
 * the point of having it separate from the root boundary — one panel throwing
 * should not take the navigation with it.
 *
 * It does not catch errors thrown by the layout itself (AppShell, AuthGuard).
 * Those are caught one level up, by `src/app/error.tsx`.
 */

import { CrashScreen } from "@/components/app/CrashScreen";

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
      <CrashScreen error={error} reset={reset} />
    </div>
  );
}
