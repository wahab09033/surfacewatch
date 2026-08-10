"use client";

/**
 * Table primitives.
 *
 * Semantic `<table>` markup, so screen readers announce row and column
 * relationships. On narrow viewports the table scrolls horizontally inside its
 * card rather than reflowing into stacked definition lists — an analyst
 * comparing hosts needs the columns to stay columns.
 */

import { cn } from "@/lib/format";

export function TableWrap({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("w-full overflow-x-auto", className)}>
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function THead({ children }: { children: React.ReactNode }) {
  return <thead className="border-b border-border">{children}</thead>;
}

export function TBody({ children }: { children: React.ReactNode }) {
  return <tbody>{children}</tbody>;
}

export type SortDirection = "asc" | "desc";

/**
 * A header cell, optionally a sort control.
 *
 * `aria-sort` is set on the cell so assistive tech announces the current sort
 * without the user having to inspect the arrow glyph.
 */
export function TH({
  children,
  sortable = false,
  active = false,
  direction = "desc",
  onSort,
  align = "left",
  className,
  width,
}: {
  children: React.ReactNode;
  sortable?: boolean;
  active?: boolean;
  direction?: SortDirection;
  onSort?: () => void;
  align?: "left" | "right" | "center";
  className?: string;
  width?: string;
}) {
  return (
    <th
      scope="col"
      style={width ? { width } : undefined}
      aria-sort={sortable ? (active ? (direction === "asc" ? "ascending" : "descending") : "none") : undefined}
      className={cn(
        "whitespace-nowrap px-3 py-2 text-2xs font-medium uppercase tracking-wide text-muted",
        align === "left" && "text-left",
        align === "right" && "text-right",
        align === "center" && "text-center",
        className,
      )}
    >
      {sortable ? (
        <button
          type="button"
          onClick={onSort}
          className={cn(
            "inline-flex items-center gap-1 uppercase tracking-wide transition-colors hover:text-text",
            active && "text-text",
          )}
        >
          {children}
          <SortArrow active={active} direction={direction} />
        </button>
      ) : (
        children
      )}
    </th>
  );
}

function SortArrow({ active, direction }: { active: boolean; direction: SortDirection }) {
  return (
    <svg
      width="8"
      height="8"
      viewBox="0 0 8 8"
      fill="none"
      aria-hidden="true"
      className={cn("transition-opacity", active ? "opacity-100" : "opacity-0")}
    >
      <path
        d={direction === "asc" ? "M1.5 5L4 2.5L6.5 5" : "M1.5 3L4 5.5L6.5 3"}
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function TR({
  children,
  onClick,
  selected = false,
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  selected?: boolean;
  className?: string;
}) {
  return (
    <tr
      onClick={onClick}
      // A clickable row needs to be keyboard-reachable. Rows here always also
      // contain a focusable control (the hostname button), so the row itself
      // stays out of the tab order and Enter is handled by that control.
      className={cn(
        "border-b border-border last:border-b-0",
        onClick && "cursor-pointer",
        selected ? "bg-surface" : onClick && "hover:bg-surface",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function TD({
  children,
  align = "left",
  className,
  colSpan,
}: {
  children: React.ReactNode;
  align?: "left" | "right" | "center";
  className?: string;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cn(
        "px-3 py-2.5 text-text",
        align === "left" && "text-left",
        align === "right" && "text-right",
        align === "center" && "text-center",
        className,
      )}
    >
      {children}
    </td>
  );
}

/**
 * The expanded detail row beneath a table row.
 *
 * Sits in its own `<tr>` spanning every column, tinted to read as attached to
 * the row above rather than as a sibling record.
 */
export function ExpandRow({ colSpan, children }: { colSpan: number; children: React.ReactNode }) {
  return (
    <tr className="border-b border-border last:border-b-0">
      <td colSpan={colSpan} className="bg-surface px-3 py-3">
        <div className="animate-fade-in">{children}</div>
      </td>
    </tr>
  );
}

/** The chevron that opens an expandable row. */
export function ExpandToggle({ expanded, label }: { expanded: boolean; label: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn("inline-flex text-muted transition-transform", expanded && "rotate-90")}
      title={label}
    >
      <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
        <path d="M3.5 1.5L7 5l-3.5 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

/**
 * Offset pagination.
 *
 * Shows the range rather than page numbers: "1–25 of 340" answers "how much is
 * there" directly, which is what matters when triaging a queue.
 */
export function Pagination({
  total,
  limit,
  offset,
  onOffsetChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
}) {
  if (total <= limit) return null;

  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  const canPrevious = offset > 0;
  const canNext = to < total;

  return (
    <div className="flex items-center justify-between gap-3 border-t border-border px-3 py-2.5">
      <p className="text-xs text-muted">
        <span className="tabular">
          {from}–{to}
        </span>{" "}
        of <span className="tabular">{total}</span>
      </p>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          disabled={!canPrevious}
          onClick={() => onOffsetChange(Math.max(offset - limit, 0))}
          className="inline-flex h-7 items-center rounded border border-border bg-bg px-2.5 text-xs font-medium text-text transition-colors hover:bg-surface disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:bg-bg"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={!canNext}
          onClick={() => onOffsetChange(offset + limit)}
          className="inline-flex h-7 items-center rounded border border-border bg-bg px-2.5 text-xs font-medium text-text transition-colors hover:bg-surface disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:bg-bg"
        >
          Next
        </button>
      </div>
    </div>
  );
}
