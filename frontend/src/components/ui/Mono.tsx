"use client";

/**
 * Monospace text.
 *
 * Reserved for machine-readable values: hostnames, IPs, CVE IDs, ports,
 * hashes, CVSS vectors, terminal output. Never for prose. Every one of these
 * gets `tabular` too, so digits line up when stacked in a column.
 */

import { cn } from "@/lib/format";

interface MonoProps extends React.HTMLAttributes<HTMLSpanElement> {
  children: React.ReactNode;
  /** Dims the value — for secondary detail like a resolved IP under a host. */
  muted?: boolean;
  truncate?: boolean;
}

export function Mono({ children, muted, truncate, className, ...rest }: MonoProps) {
  return (
    <span
      className={cn(
        "font-mono text-[0.8125rem] tabular",
        muted && "text-muted",
        truncate && "block truncate",
        className,
      )}
      {...rest}
    >
      {children}
    </span>
  );
}

/** A hostname. Always monospace, per the design rules. */
export function Hostname({
  value,
  truncate,
  className,
  ...rest
}: { value: string; truncate?: boolean } & React.HTMLAttributes<HTMLSpanElement>) {
  return (
    // break-all and truncate are mutually exclusive: a truncated host has to
    // stay on one line, so only apply the wrapping behaviour when it is not.
    <Mono truncate={truncate} className={cn(!truncate && "break-all", className)} {...rest}>
      {value}
    </Mono>
  );
}

/** An IP address, or an em dash when the host never resolved. */
export function IpAddress({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) {
    return (
      <span className={cn("text-muted", className)} title="Did not resolve">
        —
      </span>
    );
  }
  return <Mono className={className}>{value}</Mono>;
}

/** A CVE identifier, linked to the NVD entry. */
export function CveId({ value, className }: { value: string; className?: string }) {
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(value)}`}
      target="_blank"
      // noreferrer as well as noopener: the NVD does not need to know which of
      // our screens the analyst came from.
      rel="noopener noreferrer"
      className={cn(
        "font-mono text-[0.8125rem] tabular underline decoration-border underline-offset-2 transition-colors hover:decoration-accent",
        className,
      )}
      title={`Look up ${value} on the NVD`}
    >
      {value}
    </a>
  );
}

/** A port, optionally with its detected service. */
export function Port({ port, service }: { port: number; service?: string | null }) {
  return (
    <span className="inline-flex items-baseline gap-1">
      <Mono>{port}</Mono>
      {service ? <span className="text-xs text-muted">{service}</span> : null}
    </span>
  );
}
