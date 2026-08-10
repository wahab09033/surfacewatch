/** Small formatting and presentation helpers shared across pages. */

import type { AssetStatus, FindingStatus, ScanStatus, Severity } from "./types";

/** Conditional class names. Falsy entries drop out. */
export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// --- dates -----------------------------------------------------------------

/**
 * The API serialises UTC timestamps; some are bare (no trailing Z) depending on
 * the column. Assume UTC when no zone is present rather than letting the
 * browser read them as local time, which would shift every "3 minutes ago" by
 * the viewer's offset.
 */
function parseUtc(value: string | null | undefined): Date | null {
  if (!value) return null;
  const normalised = /[zZ]|[+-]\d{2}:?\d{2}$/.test(value) ? value : `${value}Z`;
  const date = new Date(normalised);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatRelative(value: string | null | undefined): string {
  const date = parseUtc(value);
  if (!date) return "Never";

  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return "Just now";
  if (seconds < 45) return "Just now";
  if (seconds < 90) return "1 min ago";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} mins ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} ${days === 1 ? "day" : "days"} ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months} ${months === 1 ? "month" : "months"} ago`;
  return `${Math.round(months / 12)}y ago`;
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parseUtc(value);
  if (!date) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatClock(value: string | null | undefined): string {
  const date = parseUtc(value);
  if (!date) return "--:--:--";
  return date.toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  if (minutes < 60) return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

// --- labels ----------------------------------------------------------------

export function titleCase(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Open",
  triaged: "Triaged",
  confirmed: "Confirmed",
  remediated: "Remediated",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};

export const ASSET_STATUS_LABEL: Record<AssetStatus, string> = {
  active: "Active",
  inactive: "Inactive",
  new: "New",
  changed: "Changed",
  decommissioned: "Decommissioned",
};

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** Findings in these states still need attention. Mirrors the backend. */
export const OPEN_FINDING_STATUSES: FindingStatus[] = ["open", "triaged", "confirmed"];

// --- risk ------------------------------------------------------------------

/** Risk scores are 0-100. Bands match the severity vocabulary used elsewhere. */
export function riskBand(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function pluralise(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}
