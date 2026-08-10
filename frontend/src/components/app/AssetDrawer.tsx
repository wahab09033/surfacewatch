"use client";

/**
 * The single asset detail surface.
 *
 * The design rules require that clicking an asset *anywhere* — a dashboard row,
 * a findings card, the assets table — opens this same drawer. So it is mounted
 * once in the app shell and opened by id through this context, rather than each
 * page rendering its own copy with its own subtly different fetch logic.
 *
 * Only the id is passed in. The drawer fetches the full record itself, because
 * callers hold different shapes (AssetSummary on the table, a bare hostname on a
 * finding) and none of them hold everything the drawer shows.
 */

import { createContext, useCallback, useContext, useMemo, useState } from "react";

import { api } from "@/lib/api";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useQuery } from "@/lib/hooks";
import type { Asset, Finding } from "@/lib/types";

import { AssetStatusBadge, Chip, RiskScore, SeverityBadge } from "../ui/Badge";
import { DetailRow } from "../ui/Card";
import { Drawer, DrawerSection } from "../ui/Drawer";
import { EmptyState, ErrorState, NoFindingsArt } from "../ui/EmptyState";
import { CveId, Hostname, IpAddress, Mono } from "../ui/Mono";
import { SkeletonList, SkeletonText } from "../ui/Skeleton";

interface AssetDrawerContextValue {
  /** Open the drawer for an asset id. */
  openAsset: (assetId: string) => void;
  close: () => void;
  openAssetId: string | null;
}

const AssetDrawerContext = createContext<AssetDrawerContextValue | null>(null);

export function AssetDrawerProvider({ children }: { children: React.ReactNode }) {
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);

  const openAsset = useCallback((assetId: string) => setOpenAssetId(assetId), []);
  const close = useCallback(() => setOpenAssetId(null), []);

  const value = useMemo(() => ({ openAsset, close, openAssetId }), [openAsset, close, openAssetId]);

  return (
    <AssetDrawerContext.Provider value={value}>
      {children}
      <AssetDrawer assetId={openAssetId} onClose={close} />
    </AssetDrawerContext.Provider>
  );
}

export function useAssetDrawer(): AssetDrawerContextValue {
  const context = useContext(AssetDrawerContext);
  if (!context) throw new Error("useAssetDrawer must be used inside <AssetDrawerProvider>");
  return context;
}

function AssetDrawer({ assetId, onClose }: { assetId: string | null; onClose: () => void }) {
  // Both fetches are keyed on the id, so switching assets refetches rather than
  // showing the previous asset's ports under the new hostname.
  const asset = useQuery<Asset | null>(
    useCallback((signal) => (assetId ? api.assets.get(assetId, signal) : Promise.resolve(null)), [assetId]),
    [assetId],
  );
  const findings = useQuery<Finding[]>(
    useCallback((signal) => (assetId ? api.assets.findings(assetId, signal) : Promise.resolve([])), [assetId]),
    [assetId],
  );

  const record = asset.data;

  return (
    <Drawer
      open={assetId !== null}
      onClose={onClose}
      width="lg"
      title={record ? <Hostname value={record.hostname} /> : "Asset"}
      subtitle={
        record ? (
          <span className="flex items-center gap-2">
            <IpAddress value={record.ip} />
            <span aria-hidden="true">·</span>
            <span>Risk {Math.round(record.risk_score)}</span>
          </span>
        ) : null
      }
    >
      {asset.error ? (
        <ErrorState message={asset.error.message} onRetry={asset.reload} compact />
      ) : asset.loading || !record ? (
        <div className="flex flex-col gap-6">
          <SkeletonText lines={4} />
          <SkeletonList rows={3} />
        </div>
      ) : (
        <>
          <DrawerSection title="Overview">
            <dl className="divide-y divide-border">
              <DetailRow label="Hostname">
                <Hostname value={record.hostname} />
              </DetailRow>
              <DetailRow label="IP address">
                <IpAddress value={record.ip} />
              </DetailRow>
              <DetailRow label="Status">
                <AssetStatusBadge status={record.status} />
              </DetailRow>
              <DetailRow label="Risk score">
                <RiskScore score={record.risk_score} />
              </DetailRow>
              <DetailRow label="Discovered via">
                {record.discovery_source ? <Mono>{record.discovery_source}</Mono> : <span className="text-muted">Manual</span>}
              </DetailRow>
              <DetailRow label="First seen">
                <span title={formatDateTime(record.first_seen)}>{formatRelative(record.first_seen)}</span>
              </DetailRow>
              <DetailRow label="Last scanned">
                <span title={formatDateTime(record.last_scanned)}>{formatRelative(record.last_scanned)}</span>
              </DetailRow>
            </dl>
          </DrawerSection>

          <DrawerSection
            title={`Open ports${record.ports.length ? ` · ${record.ports.length}` : ""}`}
          >
            {record.ports.length === 0 ? (
              <p className="text-sm text-muted">No open ports recorded on the last scan.</p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {record.ports.map((entry) => (
                  <li
                    key={`${entry.port}/${entry.protocol ?? "tcp"}`}
                    className="flex items-baseline justify-between gap-3 rounded border border-border px-2.5 py-1.5"
                  >
                    <span className="flex items-baseline gap-2">
                      <Mono>
                        {entry.port}/{entry.protocol ?? "tcp"}
                      </Mono>
                      {entry.service ? <span className="text-xs text-text">{entry.service}</span> : null}
                    </span>
                    {entry.banner ? (
                      <Mono muted truncate className="max-w-[55%] text-right">
                        {entry.banner}
                      </Mono>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </DrawerSection>

          <DrawerSection title="Technology">
            {record.tech_stack.length === 0 ? (
              <p className="text-sm text-muted">Nothing fingerprinted yet.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {record.tech_stack.map((tech) => (
                  <Chip key={`${tech.name}@${tech.version ?? "?"}`}>
                    <Mono>
                      {tech.name}
                      {tech.version ? ` ${tech.version}` : ""}
                    </Mono>
                  </Chip>
                ))}
              </div>
            )}
          </DrawerSection>

          <DrawerSection title="Findings">
            {findings.loading ? (
              <SkeletonList rows={2} />
            ) : findings.error ? (
              <ErrorState message={findings.error.message} onRetry={findings.reload} compact />
            ) : (findings.data?.length ?? 0) === 0 ? (
              <EmptyState
                compact
                illustration={<NoFindingsArt />}
                title="No findings on this asset"
                description="Nothing has been reported against this host. That is the good outcome."
              />
            ) : (
              <ul className="flex flex-col gap-2">
                {findings.data?.map((finding) => (
                  <li key={finding.id} className="rounded border border-border p-2.5">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      {finding.cve_id ? <CveId value={finding.cve_id} /> : null}
                    </div>
                    <p className="mt-1.5 text-sm leading-snug text-text">{finding.title}</p>
                  </li>
                ))}
              </ul>
            )}
          </DrawerSection>

          {record.notes ? (
            <DrawerSection title="Notes">
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">{record.notes}</p>
            </DrawerSection>
          ) : null}
        </>
      )}
    </Drawer>
  );
}

/**
 * A hostname that opens the drawer when clicked.
 *
 * This is how every page links to an asset — a plain button, so it is keyboard
 * reachable, with the monospace treatment hostnames always get.
 */
export function AssetLink({
  assetId,
  hostname,
  className,
}: {
  assetId: string;
  hostname: string;
  className?: string;
}) {
  const { openAsset } = useAssetDrawer();
  return (
    <button
      type="button"
      onClick={(event) => {
        // Rows are often clickable too; without this the row handler would fire
        // as well and fight the drawer for control.
        event.stopPropagation();
        openAsset(assetId);
      }}
      className={className}
      title={`Open ${hostname}`}
    >
      <Hostname value={hostname} className="underline decoration-border underline-offset-2 hover:decoration-accent" />
    </button>
  );
}
