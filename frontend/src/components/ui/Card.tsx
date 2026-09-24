"use client";

/** Panels, cards, and page-level layout scaffolding. */

import Link from "next/link";

import { cn } from "@/lib/format";

/** A bordered surface. The base container for everything on a page. */
export function Card({
  children,
  className,
  padded = true,
}: {
  children: React.ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <div className={cn("rounded-lg border border-border bg-bg shadow-panel", padded && "p-4", className)}>
      {children}
    </div>
  );
}

/**
 * A card with a header rail.
 *
 * `action` sits opposite the title — a "View all" link, a filter, a refresh.
 * Body padding is opt-out so tables can sit flush against the card's border.
 */
export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
  bodyClassName,
  flush = false,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  flush?: boolean;
}) {
  return (
    <section className={cn("flex flex-col rounded-lg border border-border bg-bg shadow-panel", className)}>
      <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-medium text-text">{title}</h2>
          {subtitle ? <p className="mt-0.5 truncate text-xs text-muted">{subtitle}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
      </header>
      <div className={cn(!flush && "p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

/**
 * A dashboard stat card.
 *
 * The number is the point, so it is large, tabular, and unadorned. `delta` is
 * the period-over-period note underneath.
 */
export function StatCard({
  label,
  value,
  delta,
  tone = "neutral",
  icon,
  href,
  onClick,
}: {
  label: string;
  value: React.ReactNode;
  delta?: React.ReactNode;
  tone?: "neutral" | "accent" | "ok" | "warn";
  icon?: React.ReactNode;
  href?: string;
  onClick?: () => void;
}) {
  const interactive = Boolean(href || onClick);

  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-muted">{label}</span>
        {icon ? (
          <span className="text-muted" aria-hidden="true">
            {icon}
          </span>
        ) : null}
      </div>
      <div
        className={cn(
          "mt-2 text-2xl font-semibold tabular leading-none",
          tone === "accent" && "text-accent",
          tone === "ok" && "text-ok-fg",
          tone === "warn" && "text-warn-fg",
          tone === "neutral" && "text-text",
        )}
      >
        {value}
      </div>
      {delta ? <div className="mt-2 text-xs text-muted">{delta}</div> : null}
    </>
  );

  const shell = cn(
    "block rounded-lg border border-border bg-bg p-4 text-left shadow-panel transition-colors",
    interactive && "hover:border-border-strong hover:bg-surface",
  );

  if (href) {
    // Link, not a bare <a>: every caller points this at an internal route
    // (/assets, /findings, /scan), and an anchor makes each of those a full
    // document load — the bundle reparsed, the providers remounted, client
    // state thrown away. ESLint's no-html-link-for-pages exists to catch
    // exactly this, but it only inspects literal hrefs and this one is a prop,
    // so nothing flagged it.
    return (
      <Link href={href} className={shell}>
        {body}
      </Link>
    );
  }
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={cn(shell, "w-full")}>
        {body}
      </button>
    );
  }
  return <div className={shell}>{body}</div>;
}

/** Page title, optional description, and right-aligned actions. */
export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-[-0.01em] text-text">{title}</h1>
        {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A labelled value, as used in the asset drawer and settings. */
export function DetailRow({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-baseline justify-between gap-4 py-2", className)}>
      <dt className="shrink-0 text-xs text-muted">{label}</dt>
      <dd className="min-w-0 text-right text-sm text-text">{children}</dd>
    </div>
  );
}

/** A horizontal rule that matches the panel borders. */
export function Divider({ className }: { className?: string }) {
  return <hr className={cn("border-0 border-t border-border", className)} />;
}

/**
 * A stacked bar showing severity distribution.
 *
 * Proportional widths, so a breakdown reads at a glance without needing the
 * numbers. Segments below 2% are floored so a single critical among hundreds of
 * lows is still visible — the whole point of the widget.
 */
export function ProportionBar({
  segments,
  className,
}: {
  segments: { key: string; value: number; className: string; label: string }[];
  className?: string;
}) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  if (total === 0) {
    return <div className={cn("h-1.5 w-full rounded-full bg-surface", className)} aria-hidden="true" />;
  }

  return (
    <div className={cn("flex h-1.5 w-full overflow-hidden rounded-full bg-surface", className)} role="img">
      {segments
        .filter((segment) => segment.value > 0)
        .map((segment) => (
          <div
            key={segment.key}
            className={segment.className}
            style={{ width: `${Math.max((segment.value / total) * 100, 2)}%` }}
            title={`${segment.label}: ${segment.value}`}
          />
        ))}
    </div>
  );
}
