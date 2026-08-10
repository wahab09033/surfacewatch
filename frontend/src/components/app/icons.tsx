"use client";

/**
 * Navigation icons.
 *
 * All single-stroke geometry on `currentColor` at 1.5px — no fills, no second
 * hue, no rainbow set. They read as a family because they share a grid and a
 * stroke weight, not because they share a colour ramp.
 */

const props = {
  width: 16,
  height: 16,
  viewBox: "0 0 16 16",
  fill: "none",
  "aria-hidden": true,
  strokeWidth: 1.5,
  stroke: "currentColor",
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

export function DashboardIcon() {
  return (
    <svg {...props}>
      <rect x="2" y="2" width="5" height="5" rx="1" />
      <rect x="9" y="2" width="5" height="5" rx="1" />
      <rect x="2" y="9" width="5" height="5" rx="1" />
      <rect x="9" y="9" width="5" height="5" rx="1" />
    </svg>
  );
}

export function AssetsIcon() {
  return (
    <svg {...props}>
      <rect x="2" y="2.5" width="12" height="4" rx="1" />
      <rect x="2" y="9.5" width="12" height="4" rx="1" />
      <path d="M4.5 4.5h.01M4.5 11.5h.01" />
    </svg>
  );
}

export function ScanIcon() {
  return (
    <svg {...props}>
      <path d="M2 5.5V3a1 1 0 011-1h2.5M14 5.5V3a1 1 0 00-1-1h-2.5M2 10.5V13a1 1 0 001 1h2.5M14 10.5V13a1 1 0 01-1 1h-2.5" />
      <path d="M2 8h12" />
    </svg>
  );
}

export function FindingsIcon() {
  return (
    <svg {...props}>
      <path d="M8 2l5 1.8v4.4c0 3.1-2.1 5.6-5 6.8-2.9-1.2-5-3.7-5-6.8V3.8L8 2z" />
      <path d="M8 6v2.6M8 11h.01" />
    </svg>
  );
}

export function ReportsIcon() {
  return (
    <svg {...props}>
      <path d="M3.5 2h6L13 5.5V14H3.5V2z" />
      <path d="M9.5 2v3.5H13" />
      <path d="M6 9h4M6 11.5h2.5" />
    </svg>
  );
}

export function SettingsIcon() {
  return (
    <svg {...props}>
      <circle cx="8" cy="8" r="2" />
      <path d="M8 1.5v1.7M8 12.8v1.7M2.9 2.9l1.2 1.2M11.9 11.9l1.2 1.2M1.5 8h1.7M12.8 8h1.7M2.9 13.1l1.2-1.2M11.9 4.1l1.2-1.2" />
    </svg>
  );
}

export function CollapseIcon() {
  return (
    <svg {...props}>
      <rect x="2" y="2.5" width="12" height="11" rx="1.5" />
      <path d="M6.5 2.5v11" />
    </svg>
  );
}

export function SunIcon() {
  return (
    <svg {...props}>
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1.5v1.2M8 13.3v1.2M2.9 2.9l.85.85M12.25 12.25l.85.85M1.5 8h1.2M13.3 8h1.2M2.9 13.1l.85-.85M12.25 3.75l.85-.85" />
    </svg>
  );
}

export function MoonIcon() {
  return (
    <svg {...props}>
      <path d="M13.5 9.2A5.8 5.8 0 016.8 2.5a5.8 5.8 0 106.7 6.7z" />
    </svg>
  );
}

export function MenuIcon() {
  return (
    <svg {...props}>
      <path d="M2 4h12M2 8h12M2 12h12" />
    </svg>
  );
}

export function SearchIcon() {
  return (
    <svg {...props} width={14} height={14} viewBox="0 0 14 14">
      <circle cx="6.2" cy="6.2" r="4.2" />
      <path d="M9.4 9.4L12.5 12.5" />
    </svg>
  );
}

export function PlusIcon() {
  return (
    <svg {...props}>
      <path d="M8 3.5v9M3.5 8h9" />
    </svg>
  );
}

export function DownloadIcon() {
  return (
    <svg {...props}>
      <path d="M8 2.5v7.5M5 7.5L8 10.5l3-3" />
      <path d="M2.5 12.5h11" />
    </svg>
  );
}

export function TrashIcon() {
  return (
    <svg {...props}>
      <path d="M2.5 4h11M5.5 4V2.5h5V4M4 4l.6 9.5h6.8L12 4" />
    </svg>
  );
}

export function LogoutIcon() {
  return (
    <svg {...props}>
      <path d="M6 2.5H3.5a1 1 0 00-1 1v9a1 1 0 001 1H6" />
      <path d="M10 11l3-3-3-3M13 8H6" />
    </svg>
  );
}

export function RefreshIcon() {
  return (
    <svg {...props}>
      <path d="M13.5 8a5.5 5.5 0 11-1.7-3.97" />
      <path d="M13.7 2v3.2h-3.2" />
    </svg>
  );
}

export function StopIcon() {
  return (
    <svg {...props}>
      <rect x="3.5" y="3.5" width="9" height="9" rx="1.5" />
    </svg>
  );
}

/**
 * Machine-written text. A four-point star, drawn on the same grid and stroke as
 * the rest of the set — deliberately not the usual gradient sparkle, which
 * would be the only decorated icon in the product.
 */
export function SparkIcon() {
  return (
    <svg {...props} width={12} height={12} viewBox="0 0 12 12">
      <path d="M6 1.5c0 2.2.8 3 3 3-2.2 0-3 .8-3 3 0-2.2-.8-3-3-3 2.2 0 3-.8 3-3Z" />
      <path d="M9.9 8.2c0 1-.4 1.4-1.4 1.4 1 0 1.4.4 1.4 1.4 0-1 .4-1.4 1.4-1.4-1 0-1.4-.4-1.4-1.4Z" />
    </svg>
  );
}

/** An analyst's edit — a pencil, matching the single-stroke family. */
export function PencilIcon() {
  return (
    <svg {...props} width={12} height={12} viewBox="0 0 12 12">
      <path d="M8.4 1.9l1.7 1.7-6 6-2.2.5.5-2.2 6-6Z" />
    </svg>
  );
}

/**
 * Landing-page feature icons.
 *
 * Same grid, same 1.5px single stroke as the navigation set above — the marketing
 * page borrows the product's icon family rather than introducing a second one.
 */

/** Change alerts — a bell. */
export function BellIcon() {
  return (
    <svg {...props}>
      <path d="M4 6.5a4 4 0 0 1 8 0c0 3 1 4 1 4H3s1-1 1-4Z" />
      <path d="M6.5 13a1.6 1.6 0 0 0 3 0" />
    </svg>
  );
}

/** Multi-tenant — two offset panes, one per organisation. */
export function TenantIcon() {
  return (
    <svg {...props}>
      <rect x="2" y="5.5" width="7" height="8" rx="1" />
      <path d="M6 5.5V3a.5.5 0 0 1 .5-.5H13a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-.5.5h-2" />
    </svg>
  );
}

/** REST API — angle brackets. */
export function ApiIcon() {
  return (
    <svg {...props}>
      <path d="M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5" />
    </svg>
  );
}

/** The product mark: a stylised aperture. Monochrome, single stroke. */export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="10" cy="10" r="3.25" stroke="currentColor" strokeWidth="1.5" />
      <path d="M10 2v4.75M10 13.25V18M2 10h4.75M13.25 10H18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}
