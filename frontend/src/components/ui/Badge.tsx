"use client";

/**
 * Status and severity badges.
 *
 * All of them are a light tinted fill behind dark text of the same hue — never
 * a saturated "status LED" colour. A findings table with twenty criticals in it
 * has to stay readable, and neon red rows make that impossible.
 */

import { ASSET_STATUS_LABEL, FINDING_STATUS_LABEL, SCAN_STATUS_LABEL, SEVERITY_LABEL, cn, riskBand } from "@/lib/format";
import type { AssetStatus, FindingStatus, ScanStatus, Severity } from "@/lib/types";

const BASE =
  "inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-1.5 py-0.5 text-2xs font-medium leading-4";

const SEVERITY_TINT: Record<Severity, string> = {
  critical: "border-sev-critical-bg bg-sev-critical-bg text-sev-critical-fg",
  high: "border-sev-high-bg bg-sev-high-bg text-sev-high-fg",
  medium: "border-sev-medium-bg bg-sev-medium-bg text-sev-medium-fg",
  low: "border-sev-low-bg bg-sev-low-bg text-sev-low-fg",
  info: "border-sev-info-bg bg-sev-info-bg text-sev-info-fg",
};

export function SeverityBadge({
  severity,
  className,
  showLabel = true,
}: {
  severity: Severity;
  className?: string;
  showLabel?: boolean;
}) {
  return (
    <span className={cn(BASE, SEVERITY_TINT[severity], className)}>
      <Dot />
      {showLabel ? SEVERITY_LABEL[severity] : null}
    </span>
  );
}

/**
 * A small filled circle in the badge's own text colour.
 *
 * Carries the severity for anyone who cannot separate the tints, and keeps the
 * badge legible at a glance when the row is dense.
 */
function Dot() {
  return <span aria-hidden="true" className="h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-70" />;
}

const FINDING_STATUS_TINT: Record<FindingStatus, string> = {
  open: "border-sev-high-bg bg-sev-high-bg text-sev-high-fg",
  triaged: "border-sev-medium-bg bg-sev-medium-bg text-sev-medium-fg",
  confirmed: "border-sev-critical-bg bg-sev-critical-bg text-sev-critical-fg",
  remediated: "border-ok-bg bg-ok-bg text-ok-fg",
  false_positive: "border-border bg-surface text-muted",
  accepted_risk: "border-sev-info-bg bg-sev-info-bg text-sev-info-fg",
};

export function FindingStatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  return <span className={cn(BASE, FINDING_STATUS_TINT[status], className)}>{FINDING_STATUS_LABEL[status]}</span>;
}

const SCAN_STATUS_TINT: Record<ScanStatus, string> = {
  queued: "border-border bg-surface text-muted",
  running: "border-sev-info-bg bg-sev-info-bg text-sev-info-fg",
  completed: "border-ok-bg bg-ok-bg text-ok-fg",
  failed: "border-sev-critical-bg bg-sev-critical-bg text-sev-critical-fg",
  cancelled: "border-border bg-surface text-muted",
};

export function ScanStatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  return (
    <span className={cn(BASE, SCAN_STATUS_TINT[status], className)}>
      {status === "running" ? (
        // The only animated badge in the system: a scan in flight is the one
        // state where "still happening" is the whole message.
        <span
          aria-hidden="true"
          className="h-1.5 w-1.5 shrink-0 rounded-full bg-current motion-safe:animate-pulse"
        />
      ) : (
        <Dot />
      )}
      {SCAN_STATUS_LABEL[status]}
    </span>
  );
}

const ASSET_STATUS_TINT: Record<AssetStatus, string> = {
  active: "border-ok-bg bg-ok-bg text-ok-fg",
  inactive: "border-border bg-surface text-muted",
  new: "border-sev-info-bg bg-sev-info-bg text-sev-info-fg",
  changed: "border-warn-bg bg-warn-bg text-warn-fg",
  decommissioned: "border-border bg-surface text-muted",
};

export function AssetStatusBadge({ status, className }: { status: AssetStatus; className?: string }) {
  return <span className={cn(BASE, ASSET_STATUS_TINT[status], className)}>{ASSET_STATUS_LABEL[status]}</span>;
}

/** Neutral pill for counts, module names, formats — anything without severity. */
export function Chip({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn(BASE, "border-border bg-surface text-muted", className)}>{children}</span>;
}

/**
 * A 0–100 risk score, tinted by the band it falls in.
 *
 * Monospace and tabular because these stack in a sortable column and ragged
 * digits make the column impossible to scan.
 */
export function RiskScore({ score, className }: { score: number; className?: string }) {
  const band = riskBand(score);
  return (
    <span
      className={cn(
        "inline-flex min-w-[2.25rem] justify-center rounded border px-1.5 py-0.5 font-mono text-2xs font-medium tabular",
        SEVERITY_TINT[band],
        className,
      )}
      title={`Risk ${score} of 100 — ${SEVERITY_LABEL[band]} band`}
    >
      {Math.round(score)}
    </span>
  );
}
