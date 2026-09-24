"use client";

/**
 * Client-side route guard.
 *
 * This is convenience, not security. It decides what to *render*; it does not
 * decide what the user can *reach*. Every response on every page comes from the
 * API, which authorises each request against the caller's org independently. A
 * user who edits their way past this guard sees empty panels and 401s.
 */

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "../providers/AuthProvider";
import { ErrorState } from "../ui/EmptyState";
import { SkeletonStat, SkeletonTable } from "../ui/Skeleton";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, loading, sessionError, retrySession } = useAuth();
  const router = useRouter();

  // Not redirected when the session check failed for a reason that says nothing
  // about the session: sending somebody to /login because their wifi dropped
  // tells them they were signed out when they were not. The provider keeps the
  // token in this case, so a retry can silently restore the session.
  useEffect(() => {
    if (!loading && !user && !sessionError) router.replace("/login");
  }, [loading, user, sessionError, router]);

  // While the session check is in flight, show the page's own shape rather than
  // a spinner — the rule is skeletons everywhere, and this is the first thing
  // anyone sees on a cold load.
  if (loading) {
    return (
      <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <SkeletonStat key={i} />
          ))}
        </div>
        <div className="mt-4 rounded-lg border border-border bg-bg">
          <SkeletonTable rows={6} columns={5} />
        </div>
      </div>
    );
  }

  if (!user && sessionError) {
    return (
      <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6">
        <div className="rounded-lg border border-border bg-bg shadow-panel">
          <ErrorState message={sessionError.message} onRetry={retrySession} />
          <p className="border-t border-border px-6 py-3 text-center text-xs leading-relaxed text-muted">
            You are still signed in — this is a problem reaching the API, not with your
            account. Nothing was signed out.
          </p>
        </div>
      </div>
    );
  }

  // The redirect above is already scheduled; rendering nothing avoids a flash
  // of the protected page's chrome on the way out.
  if (!user) return null;

  return <>{children}</>;
}
