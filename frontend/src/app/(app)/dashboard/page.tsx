"use client";

import Link from "next/link";
import { useCallback, useState } from "react";

import { AssetLink } from "@/components/app/AssetDrawer";
import { BlastRadiusMap } from "@/components/app/BlastRadiusMap";
import { AssetsIcon, FindingsIcon, RefreshIcon, ScanIcon } from "@/components/app/icons";
import { RiskScore, ScanStatusBadge, SeverityBadge } from "@/components/ui/Badge";
import { IconButton } from "@/components/ui/Button";
import { PageHeader, Panel, ProportionBar, StatCard } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoAssetsArt, NoFindingsArt, NoScansArt } from "@/components/ui/EmptyState";
import { CveId, Hostname, Mono } from "@/components/ui/Mono";
import { Skeleton, SkeletonList, SkeletonStat, SkeletonTable } from "@/components/ui/Skeleton";
import { TBody, TD, TH, THead, TR, TableWrap } from "@/components/ui/Table";
import { api } from "@/lib/api";
import { SEVERITY_LABEL, formatDateTime, formatRelative, pluralise } from "@/lib/format";
import { usePoll, useQuery } from "@/lib/hooks";
import type { Dashboard, GraphResponse, Paginated, Scan, Severity } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";

/**
 * Bar segment colours.
 *
 * These use the severity *foreground* tokens rather than the badge tints: a
 * 6px bar has too little area for a light wash to register, so the bar takes
 * the saturated end of each pair while the badges keep the tint.
 */
const SEVERITY_BAR: Record<Severity, string> = {
  critical: "bg-sev-critical-fg",
  high: "bg-sev-high-fg",
  medium: "bg-sev-medium-fg",
  low: "bg-sev-low-fg",
  info: "bg-sev-info-fg",
};

export default function DashboardPage() {
  const [showPorts, setShowPorts] = useState(true);

  const dashboard = useQuery<Dashboard>(
    useCallback((signal) => api.reports.dashboard(signal), []),
    [],
  );

  const activeScans = useQuery<Paginated<Scan>>(
    useCallback((signal) => api.scans.list({ status: "running", limit: 5 }, signal), []),
    [],
  );

  const graph = useQuery<GraphResponse>(
    useCallback(
      (signal) => api.assets.graph({ include_ports: showPorts }, signal),
      [showPorts],
    ),
    [showPorts],
  );

  // A running scan changes these numbers underneath the viewer. Poll while one
  // is in flight; stop entirely once the estate is quiet, so an idle dashboard
  // left open overnight makes no requests at all.
  //
  // The graph is deliberately NOT in here. New data means a new node array,
  // which means the force simulation restarts from its seed positions — so
  // polling it would yank the layout out from under anyone reading it, every
  // ten seconds. It refreshes on the explicit Refresh button instead.
  const anyRunning = (dashboard.data?.scans_running ?? 0) > 0;
  usePoll(
    useCallback(() => {
      dashboard.reload();
      activeScans.reload();
    }, [dashboard, activeScans]),
    anyRunning ? 10_000 : null,
  );

  const reloadAll = useCallback(() => {
    dashboard.reload();
    activeScans.reload();
    graph.reload();
  }, [dashboard, activeScans, graph]);

  const header = (
    <PageHeader
      title="Dashboard"
      description="Your organisation's attack surface at a glance."
      actions={
        <IconButton
          aria-label="Refresh"
          onClick={reloadAll}
          // Disabled rather than `busy`: BusyDots would render alongside the
          // icon instead of replacing it.
          disabled={dashboard.refreshing || activeScans.refreshing || graph.refreshing}
        >
          <RefreshIcon />
        </IconButton>
      }
    />
  );

  if (dashboard.loading) {
    return (
      <div className="flex flex-col gap-4">
        {header}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <SkeletonStat key={i} />
          ))}
        </div>
        <Panel title="Blast radius" flush>
          <div className="p-4">
            <Skeleton className="h-[460px] w-full rounded" />
          </div>
        </Panel>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Panel title="Active scans" flush>
            <div className="p-4">
              <SkeletonList rows={2} />
            </div>
          </Panel>
          <Panel title="Findings by severity" flush>
            <SkeletonTable rows={5} columns={3} />
          </Panel>
        </div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Panel title="Highest-risk assets" flush>
            <SkeletonTable rows={5} columns={3} />
          </Panel>
          <Panel title="Recent findings" flush>
            <SkeletonTable rows={5} columns={3} />
          </Panel>
        </div>
      </div>
    );
  }

  if (dashboard.error || !dashboard.data) {
    return (
      <div className="flex flex-col gap-4">
        {header}
        <Panel title="Dashboard" flush>
          <ErrorState
            message={dashboard.error?.message ?? "The dashboard returned no data."}
            onRetry={dashboard.reload}
          />
        </Panel>
      </div>
    );
  }

  const data = dashboard.data;

  const segments = SEVERITIES.map((severity) => ({
    key: severity,
    value: data.findings_by_severity[severity] ?? 0,
    className: SEVERITY_BAR[severity],
    label: SEVERITY_LABEL[severity],
  }));

  const scans = activeScans.data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      {header}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Assets"
          value={data.assets_total.toLocaleString()}
          delta={
            data.assets_new_7d > 0
              ? `${data.assets_new_7d} new in the last 7 days`
              : "No new assets this week"
          }
          icon={<AssetsIcon />}
          href="/assets"
        />
        <StatCard
          label="Open findings"
          value={data.findings_open.toLocaleString()}
          delta={data.findings_open > 0 ? <ProportionBar segments={segments} className="mt-1" /> : "Nothing outstanding"}
          tone={data.findings_open > 0 ? "warn" : "ok"}
          icon={<FindingsIcon />}
          href="/findings"
        />
        <StatCard
          label="Running scans"
          value={data.scans_running.toLocaleString()}
          delta={`${data.scans_last_7d} ${pluralise(data.scans_last_7d, "scan")} in the last 7 days`}
          tone={data.scans_running > 0 ? "accent" : "neutral"}
          icon={<ScanIcon />}
          href="/scan"
        />
        <StatCard
          label="Mean risk score"
          value={data.mean_risk_score.toFixed(1)}
          delta={
            data.assets_total > 0
              ? `Across ${data.assets_total.toLocaleString()} ${pluralise(data.assets_total, "asset")}`
              : "No assets scored yet"
          }
          tone={data.mean_risk_score >= 60 ? "warn" : "neutral"}
        />
      </div>

      <Panel
        title="Blast radius"
        subtitle={
          graph.data
            ? `${graph.data.nodes.length} nodes · ${graph.data.total_assets.toLocaleString()} ${pluralise(graph.data.total_assets, "asset")} in scope`
            : "How your estate connects"
        }
        action={
          <div className="flex items-center gap-2">
            <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted">
              <input
                type="checkbox"
                checked={showPorts}
                onChange={(event) => setShowPorts(event.target.checked)}
                className="h-3.5 w-3.5 cursor-pointer accent-accent"
              />
              Ports
            </label>
            <Link href="/assets" className="text-xs font-medium text-accent hover:underline">
              All assets
            </Link>
          </div>
        }
        flush
      >
        {graph.loading ? (
          <div className="p-4">
            <Skeleton className="h-[460px] w-full rounded" />
          </div>
        ) : graph.error ? (
          <ErrorState message={graph.error.message} onRetry={graph.reload} compact />
        ) : !graph.data || graph.data.nodes.length === 0 ? (
          <EmptyState
            compact
            illustration={<NoAssetsArt />}
            title="Nothing to map yet"
            description="Once a scan has found subdomains and resolved them to hosts, this shows which of your names share infrastructure — and what one compromised host would cost you."
            action={
              <Link
                href="/scan"
                className="inline-flex h-8 items-center rounded border border-accent bg-accent px-3 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
              >
                Run a scan
              </Link>
            }
          />
        ) : (
          <>
            {graph.data.truncated && graph.data.truncated_reason ? (
              // Said out loud rather than silently drawn. Someone reading a
              // partial map as if it were the whole estate would draw exactly
              // the wrong conclusion about their coverage.
              <p className="border-b border-border bg-warn-bg px-4 py-2 text-xs text-warn-fg">
                {graph.data.truncated_reason}
              </p>
            ) : null}
            <BlastRadiusMap data={graph.data} />
          </>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          title="Active scans"
          subtitle={scans.length > 0 ? `${scans.length} in progress` : undefined}
          action={
            <Link href="/scan" className="text-xs font-medium text-accent hover:underline">
              Scan console
            </Link>
          }
          flush
        >
          {activeScans.loading ? (
            <div className="p-4">
              <SkeletonList rows={2} />
            </div>
          ) : activeScans.error ? (
            <ErrorState message={activeScans.error.message} onRetry={activeScans.reload} compact />
          ) : scans.length === 0 ? (
            <EmptyState
              compact
              illustration={<NoScansArt />}
              title="Nothing scanning right now"
              description="Point SurfaceWatch at a domain to start mapping its attack surface."
              action={
                <Link
                  href="/scan"
                  className="inline-flex h-8 items-center rounded border border-accent bg-accent px-3 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
                >
                  Start a scan
                </Link>
              }
            />
          ) : (
            <ul className="divide-y divide-border">
              {scans.map((scan) => (
                <li key={scan.id} className="flex flex-col gap-2 px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <Hostname value={scan.target} truncate />
                    <ScanStatusBadge status={scan.status} />
                  </div>
                  <div className="flex items-center gap-2">
                    {/*
                      A determinate progress bar, not a spinner: the backend
                      publishes a real 0-100 progress value per stage, so we can
                      say how far along the scan is rather than only that it is
                      moving.
                    */}
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface">
                      <div
                        className="h-full rounded-full bg-accent transition-[width] duration-500"
                        style={{ width: `${Math.min(Math.max(scan.progress, 0), 100)}%` }}
                      />
                    </div>
                    <Mono muted className="shrink-0 text-2xs">
                      {Math.round(scan.progress)}%
                    </Mono>
                  </div>
                  <p className="truncate text-xs text-muted">
                    {scan.current_stage ? scan.current_stage : "Queued"}
                    {" · "}
                    {scan.assets_discovered} {pluralise(scan.assets_discovered, "asset")}
                    {" · "}
                    {scan.findings_count} {pluralise(scan.findings_count, "finding")}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Findings by severity"
          subtitle="Open findings only"
          action={
            <Link href="/findings" className="text-xs font-medium text-accent hover:underline">
              View all
            </Link>
          }
          flush
        >
          {data.findings_open === 0 ? (
            <EmptyState
              compact
              illustration={<NoFindingsArt />}
              title="No open findings"
              description="Nothing is currently outstanding against your assets."
            />
          ) : (
            <>
              <TableWrap>
                <THead>
                  <TR>
                    <TH>Severity</TH>
                    <TH align="right">Count</TH>
                    <TH align="right" width="22%">
                      Share
                    </TH>
                  </TR>
                </THead>
                <TBody>
                  {SEVERITIES.map((severity) => {
                    const count = data.findings_by_severity[severity] ?? 0;
                    return (
                      <TR key={severity}>
                        <TD>
                          <SeverityBadge severity={severity} />
                        </TD>
                        <TD align="right">
                          <Mono muted={count === 0}>{count.toLocaleString()}</Mono>
                        </TD>
                        <TD align="right">
                          <Mono muted={count === 0}>
                            {Math.round((count / data.findings_open) * 100)}%
                          </Mono>
                        </TD>
                      </TR>
                    );
                  })}
                </TBody>
              </TableWrap>
              <div className="border-t border-border px-3 py-3">
                <ProportionBar segments={segments} />
              </div>
            </>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          title="Highest-risk assets"
          action={
            <Link href="/assets" className="text-xs font-medium text-accent hover:underline">
              All assets
            </Link>
          }
          flush
        >
          {data.top_risk_assets.length === 0 ? (
            <EmptyState
              compact
              illustration={<NoAssetsArt />}
              title="No assets discovered yet"
              description="Assets appear here once a scan has mapped your estate."
              action={
                <Link
                  href="/scan"
                  className="inline-flex h-8 items-center rounded border border-border bg-bg px-3 text-sm font-medium text-text transition-colors hover:bg-surface"
                >
                  Run a scan
                </Link>
              }
            />
          ) : (
            <TableWrap>
              <THead>
                <TR>
                  <TH>Host</TH>
                  <TH align="right" width="15%">
                    Risk
                  </TH>
                  <TH width="38%">Exposure</TH>
                </TR>
              </THead>
              <TBody>
                {data.top_risk_assets.map((asset) => (
                  <TR key={asset.id}>
                    <TD>
                      <AssetLink assetId={asset.id} hostname={asset.hostname} />
                    </TD>
                    <TD align="right">
                      <RiskScore score={asset.risk_score} />
                    </TD>
                    <TD>
                      <span className="flex flex-col gap-0.5">
                        <Mono muted={asset.open_ports.length === 0} className="text-2xs">
                          {asset.open_ports.length > 0
                            ? `${asset.open_ports.slice(0, 4).join(", ")}${asset.open_ports.length > 4 ? ` +${asset.open_ports.length - 4}` : ""}`
                            : "No open ports"}
                        </Mono>
                        {asset.technologies.length > 0 ? (
                          <Mono muted className="truncate text-2xs">
                            {asset.technologies.slice(0, 3).join(", ")}
                          </Mono>
                        ) : null}
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </TableWrap>
          )}
        </Panel>

        <Panel
          title="Recent findings"
          action={
            <Link href="/findings" className="text-xs font-medium text-accent hover:underline">
              All findings
            </Link>
          }
          flush
        >
          {data.recent_findings.length === 0 ? (
            <EmptyState
              compact
              illustration={<NoFindingsArt />}
              title="No findings yet"
              description="Issues discovered by a scan are listed here newest first."
            />
          ) : (
            <TableWrap>
              <THead>
                <TR>
                  <TH>Finding</TH>
                  <TH width="26%">Host</TH>
                  <TH align="right" width="20%">
                    Seen
                  </TH>
                </TR>
              </THead>
              <TBody>
                {data.recent_findings.map((finding) => (
                  <TR key={finding.id}>
                    <TD>
                      <span className="flex flex-col gap-1">
                        <span className="flex items-center gap-1.5">
                          <SeverityBadge severity={finding.severity} showLabel={false} />
                          <span className="line-clamp-1 text-sm text-text">{finding.title}</span>
                        </span>
                        {finding.cve_id ? (
                          <span className="flex items-center gap-2">
                            <CveId value={finding.cve_id} className="text-2xs" />
                            {finding.cvss_score !== null ? (
                              <Mono muted className="text-2xs">
                                CVSS {finding.cvss_score.toFixed(1)}
                              </Mono>
                            ) : null}
                          </span>
                        ) : null}
                      </span>
                    </TD>
                    <TD>
                      {/*
                        The dashboard projection carries the hostname but not the
                        asset id, so this is plain text rather than an AssetLink.
                        Opening the drawer would need a lookup the payload cannot
                        support — the findings page has the id and links properly.
                      */}
                      {finding.hostname ? (
                        <Hostname value={finding.hostname} truncate className="text-muted" />
                      ) : (
                        <span className="text-xs text-muted">—</span>
                      )}
                    </TD>
                    <TD align="right">
                      <span className="whitespace-nowrap text-xs text-muted" title={formatDateTime(finding.created_at)}>
                        {formatRelative(finding.created_at)}
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </TableWrap>
          )}
        </Panel>
      </div>
    </div>
  );
}
