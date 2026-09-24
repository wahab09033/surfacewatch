import Link from "next/link";

import { EmptyState } from "@/components/ui/EmptyState";
import { buttonClass } from "@/components/ui/buttonStyles";

/**
 * 404.
 *
 * Sits at the app root rather than inside `(app)` on purpose: it is rendered for
 * *any* unmatched URL, including ones typed by someone who is not signed in, and
 * a route group's boundary cannot be resolved for a path that matched nothing at
 * all. The one action therefore goes to the dashboard, and `AuthGuard` forwards
 * an unauthenticated visitor on to /login from there.
 */
export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-[1400px] flex-col items-center justify-center px-4 py-6 sm:px-6">
      <div className="w-full max-w-md rounded-lg border border-border bg-bg shadow-panel">
        <EmptyState
          title="No such page"
          description="That address does not match anything in the console. It may have been typed wrong, or it may belong to a version of SurfaceWatch that no longer exists."
          action={
            <Link href="/dashboard" className={buttonClass("primary", "sm")}>
              Go to dashboard
            </Link>
          }
        />
      </div>
    </main>
  );
}
