"use client";

/**
 * Empty states.
 *
 * Never a bare "No data". Every empty state gets a geometric illustration, a
 * sentence explaining why the space is empty, and — where there is something to
 * do about it — an action.
 *
 * The illustrations are inline SVG built from the same primitives as the rest of
 * the UI: 1px strokes on `--border`, one optional accent detail. No gradients,
 * no multi-hue icons, no stock art.
 */

import { cn } from "@/lib/format";

interface EmptyStateProps {
  illustration?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  /** Tightens padding for use inside a panel rather than a full page. */
  compact?: boolean;
  className?: string;
}

export function EmptyState({
  illustration,
  title,
  description,
  action,
  compact = false,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center px-6 text-center",
        compact ? "py-8" : "py-16",
        className,
      )}
    >
      {illustration ?? <NoDataArt />}
      <h3 className={cn("font-medium text-text", compact ? "mt-4 text-sm" : "mt-5 text-base")}>{title}</h3>
      {description ? (
        <p className="mt-1.5 max-w-sm text-pretty text-sm leading-relaxed text-muted">{description}</p>
      ) : null}
      {action ? <div className="mt-5 flex items-center gap-2">{action}</div> : null}
    </div>
  );
}

/**
 * Shared frame for the illustrations.
 *
 * Sets `currentColor` to the border colour so every shape inherits it; the one
 * accent detail opts out explicitly with `text-accent`.
 */
function Art({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <svg
      width="88"
      height="88"
      viewBox="0 0 88 88"
      fill="none"
      role="img"
      aria-label={label}
      className="text-border"
    >
      {children}
    </svg>
  );
}

/** Generic: a grid with one cell missing. */
export function NoDataArt() {
  return (
    <Art label="An empty grid">
      {[0, 1, 2].map((row) =>
        [0, 1, 2].map((col) => {
          const isGap = row === 1 && col === 2;
          return (
            <rect
              key={`${row}-${col}`}
              x={12 + col * 22}
              y={12 + row * 22}
              width="18"
              height="18"
              rx="3"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeDasharray={isGap ? "3 3" : undefined}
            />
          );
        }),
      )}
    </Art>
  );
}

/** Assets: nested rings, like a radar sweep with nothing on it. */
export function NoAssetsArt() {
  return (
    <Art label="Concentric rings with no targets">
      <circle cx="44" cy="44" r="30" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="44" cy="44" r="20" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 4" />
      <circle cx="44" cy="44" r="10" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="44" cy="44" r="2.5" fill="currentColor" className="text-accent" />
    </Art>
  );
}

/** Findings: a shield. Here, nothing found is the good outcome. */
export function NoFindingsArt() {
  return (
    <Art label="A shield">
      <path
        d="M44 14l22 8v20c0 14-9.5 25-22 32-12.5-7-22-18-22-32V22l22-8z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M34 43.5l7.5 7.5L56 36"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="text-accent"
      />
    </Art>
  );
}

/** Scans: a terminal window with an empty prompt. */
export function NoScansArt() {
  return (
    <Art label="An empty terminal window">
      <rect x="12" y="18" width="64" height="52" rx="4" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 30h64" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="20" cy="24" r="1.75" fill="currentColor" />
      <circle cx="27" cy="24" r="1.75" fill="currentColor" />
      <path d="M22 42l5 5-5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M34 52h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-accent" />
    </Art>
  );
}

/** Reports: a sheet with ruled lines. */
export function NoReportsArt() {
  return (
    <Art label="A document">
      <rect x="20" y="14" width="44" height="56" rx="4" stroke="currentColor" strokeWidth="1.5" />
      <path d="M30 30h24M30 40h24M30 50h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M50 50h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-accent" />
    </Art>
  );
}

/** A search or filter returned nothing — distinct from "nothing exists yet". */
export function NoResultsArt() {
  return (
    <Art label="A magnifier over an empty field">
      <circle cx="39" cy="39" r="20" stroke="currentColor" strokeWidth="1.5" />
      <path d="M53.5 53.5L68 68" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M31 39h16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-accent" />
    </Art>
  );
}

/** Team: two overlapping figures. */
export function NoMembersArt() {
  return (
    <Art label="Two people">
      <circle cx="34" cy="32" r="9" stroke="currentColor" strokeWidth="1.5" />
      <path d="M18 62c0-8.8 7.2-16 16-16s16 7.2 16 16" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="57" cy="37" r="7" stroke="currentColor" strokeWidth="1.5" className="text-accent" />
      <path d="M46 62c0-6.1 4.9-11 11-11s11 4.9 11 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </Art>
  );
}

/**
 * Something broke.
 *
 * Errors are not empty states, but they occupy the same slot in a panel, so they
 * share the layout. The API's message is passed through verbatim where we have
 * one — a security tool that hides its errors is not trustworthy.
 */
export function ErrorState({
  message,
  onRetry,
  compact = false,
}: {
  message: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  return (
    <EmptyState
      compact={compact}
      illustration={
        <Art label="A warning triangle">
          <path d="M44 18l26 46H18l26-46z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
          <path d="M44 34v14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-accent" />
          <circle cx="44" cy="55" r="1.75" fill="currentColor" className="text-accent" />
        </Art>
      }
      title="Could not load this"
      description={message}
      action={
        onRetry ? (
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex h-8 items-center rounded border border-border bg-bg px-3 text-sm font-medium text-text transition-colors hover:bg-surface"
          >
            Try again
          </button>
        ) : null
      }
    />
  );
}
