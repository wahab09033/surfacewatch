"use client";

/**
 * Skeleton loaders.
 *
 * Every data fetch in this app shows a skeleton, never a spinner. The shapes
 * mirror the real content's geometry so the layout does not jump when data
 * lands — a skeleton row is the same height as a real row.
 *
 * The shimmer is suppressed under prefers-reduced-motion (see globals.css); the
 * static surface fill still reads as "loading".
 */

import { cn } from "@/lib/format";

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <span
      aria-hidden="true"
      style={style}
      className={cn("relative block overflow-hidden rounded bg-surface", className)}
    >
      <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-black/[0.045] to-transparent motion-safe:animate-shimmer dark:via-white/[0.05]" />
    </span>
  );
}

/** Widths cycle so a stack reads like a paragraph rather than a barcode. */
const TEXT_WIDTHS = ["100%", "92%", "78%", "85%", "64%"];

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-2", className)} role="status" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className="h-3" style={{ width: TEXT_WIDTHS[i % TEXT_WIDTHS.length] }} />
      ))}
    </div>
  );
}

/** Placeholder for one stat card. */
export function SkeletonStat() {
  return (
    <div className="rounded-lg border border-border bg-bg p-4">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="mt-3 h-7 w-16" />
      <Skeleton className="mt-3 h-3 w-32" />
    </div>
  );
}

/**
 * Placeholder rows for a table.
 *
 * `columns` should match the real header count, otherwise the skeleton's column
 * widths differ from the loaded table and everything shifts sideways.
 */
export function SkeletonTable({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div role="status" aria-label="Loading table data">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex h-11 items-center gap-4 border-b border-border px-3 last:border-b-0">
          {Array.from({ length: columns }, (_, c) => (
            <Skeleton key={c} className={cn("h-3", c === 0 ? "w-[28%]" : "flex-1")} />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Placeholder for a stack of finding cards. */
export function SkeletonCards({ count = 4 }: { count?: number }) {
  return (
    <div className="flex flex-col gap-3" role="status" aria-label="Loading">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="rounded-lg border border-border bg-bg p-4">
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-24" />
          </div>
          <Skeleton className="mt-3 h-4 w-[60%]" />
          <Skeleton className="mt-2 h-3 w-[85%]" />
        </div>
      ))}
    </div>
  );
}

/** Placeholder for a list of rows in a panel — active scans, team members. */
export function SkeletonList({ rows = 3 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="h-8 w-8 shrink-0 rounded" />
          <div className="flex-1">
            <Skeleton className="h-3 w-[45%]" />
            <Skeleton className="mt-2 h-3 w-[25%]" />
          </div>
        </div>
      ))}
    </div>
  );
}
