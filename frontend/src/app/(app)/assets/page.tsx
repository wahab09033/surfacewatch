"use client";

/**
 * Asset inventory.
 *
 * Filters map one-to-one onto the query parameters routes/assets.py accepts —
 * status, hostname substring, minimum risk, open port, technology — so nothing
 * is filtered client-side over a partial page. Sorting is server-side for the
 * same reason: sorting 25 rows of 4,000 by risk locally would be a lie.
 */

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { AssetLink, useAssetDrawer } from "@/components/app/AssetDrawer";
import { PlusIcon, RefreshIcon, SearchIcon, TrashIcon } from "@/components/app/icons";
import { AssetStatusBadge, Chip, RiskScore } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { PageHeader, Panel } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoAssetsArt, NoResultsArt } from "@/components/ui/EmptyState";
import { Input, Select } from "@/components/ui/Input";
import { ConfirmModal, Modal } from "@/components/ui/Modal";
import { IpAddress, Mono, Port } from "@/components/ui/Mono";
import { useToast } from "@/components/providers/ToastProvider";
import { SkeletonTable } from "@/components/ui/Skeleton";
import {
  ExpandRow,
  ExpandToggle,
  Pagination,
  TBody,
  TD,
  TH,
  THead,
  TR,
  TableWrap,
} from "@/components/ui/Table";
import { ApiError, api } from "@/lib/api";
import { ASSET_STATUS_LABEL, formatDateTime, formatRelative, pluralise } from "@/lib/format";
import { useDebounced, useQuery } from "@/lib/hooks";
import type { Asset, AssetSort, AssetStatus, AssetSummary, Paginated } from "@/lib/types";
import { ASSET_STATUSES } from "@/lib/types";

const PAGE_SIZE = 25;

const STATUS_OPTIONS: { value: AssetStatus | ""; label: string }[] = [
  { value: "", label: "Any status" },
  ...ASSET_STATUSES.map((status) => ({ value: status, label: ASSET_STATUS_LABEL[status] })),
];

const SORT_OPTIONS: { value: AssetSort; label: string }[] = [
  { value: "risk", label: "Highest risk" },
  { value: "hostname", label: "Hostname" },
  { value: "last_scanned", label: "Recently scanned" },
  { value: "created", label: "Newest" },
];

const RISK_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "Any risk" },
  { value: "80", label: "Critical (80+)" },
  { value: "60", label: "High (60+)" },
  { value: "35", label: "Medium (35+)" },
];

export default function AssetsPage() {
  const { toast } = useToast();
  const { openAsset } = useAssetDrawer();

  const [hostname, setHostname] = useState("");
  const [status, setStatus] = useState<AssetStatus | "">("");
  const [minRisk, setMinRisk] = useState("");
  const [port, setPort] = useState("");
  const [technology, setTechnology] = useState("");
  const [sort, setSort] = useState<AssetSort>("risk");
  const [offset, setOffset] = useState(0);

  const [expanded, setExpanded] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<AssetSummary | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Debounced so typing a hostname does not fire a request per keystroke. The
  // numeric filters come from selects and inputs that settle, so they use the
  // same treatment for consistency rather than out of necessity.
  const debouncedHostname = useDebounced(hostname);
  const debouncedPort = useDebounced(port);
  const debouncedTechnology = useDebounced(technology);

  const query = useMemo(
    () => ({
      hostname: debouncedHostname.trim() || undefined,
      status: status || undefined,
      min_risk: minRisk ? Number(minRisk) : undefined,
      // A partially-typed port ("8" on the way to "8080") is a valid number but
      // not the filter the user means yet; the debounce covers the gap.
      port: debouncedPort ? Number(debouncedPort) : undefined,
      technology: debouncedTechnology.trim() || undefined,
      sort,
      limit: PAGE_SIZE,
      offset,
    }),
    [debouncedHostname, status, minRisk, debouncedPort, debouncedTechnology, sort, offset],
  );

  const assets = useQuery<Paginated<AssetSummary>>(
    useCallback((signal) => api.assets.list(query, signal), [query]),
    [query],
  );

  const filtersActive = Boolean(
    debouncedHostname || status || minRisk || debouncedPort || debouncedTechnology,
  );

  /** Any filter change invalidates the current page offset. */
  function changeFilter(apply: () => void) {
    apply();
    setOffset(0);
    setExpanded(null);
  }

  function toggleSort(next: AssetSort) {
    changeFilter(() => setSort(next));
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.assets.remove(pendingDelete.id);
      toast(`${pendingDelete.hostname} removed from inventory`, "success");
      setPendingDelete(null);
      assets.reload();
    } catch (caught) {
      toast(caught instanceof ApiError ? caught.message : "Could not delete that asset", "error");
    } finally {
      setDeleting(false);
    }
  }

  const items = assets.data?.items ?? [];
  const total = assets.data?.total ?? 0;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Assets"
        description="Every host discovered across your estate."
        actions={
          <>
            <IconButton aria-label="Refresh" onClick={assets.reload} disabled={assets.refreshing}>
              <RefreshIcon />
            </IconButton>
            <Button variant="primary" onClick={() => setAddOpen(true)}>
              <PlusIcon />
              Add asset
            </Button>
          </>
        }
      />

      <Panel
        title="Inventory"
        subtitle={
          assets.loading
            ? undefined
            : `${total.toLocaleString()} ${pluralise(total, "asset")}${filtersActive ? " matching" : ""}`
        }
        flush
      >
        <div className="flex flex-wrap items-end gap-2 border-b border-border px-3 py-3">
          <Input
            aria-label="Filter by hostname"
            placeholder="Hostname contains…"
            value={hostname}
            onChange={(event) => changeFilter(() => setHostname(event.target.value))}
            leading={<SearchIcon />}
            mono
            wrapperClassName="min-w-[200px] flex-1"
          />
          <Select
            aria-label="Filter by status"
            value={status}
            options={STATUS_OPTIONS}
            onValueChange={(value) => changeFilter(() => setStatus(value))}
            wrapperClassName="w-[150px]"
          />
          <Select
            aria-label="Filter by minimum risk"
            value={minRisk}
            options={RISK_OPTIONS}
            onValueChange={(value) => changeFilter(() => setMinRisk(value))}
            wrapperClassName="w-[150px]"
          />
          <Input
            aria-label="Filter by open port"
            placeholder="Port"
            value={port}
            inputMode="numeric"
            onChange={(event) =>
              changeFilter(() => setPort(event.target.value.replace(/\D/g, "").slice(0, 5)))
            }
            mono
            wrapperClassName="w-[90px]"
          />
          <Input
            aria-label="Filter by technology"
            placeholder="Technology"
            value={technology}
            onChange={(event) => changeFilter(() => setTechnology(event.target.value))}
            mono
            wrapperClassName="w-[150px]"
          />
          <Select
            aria-label="Sort"
            value={sort}
            options={SORT_OPTIONS}
            onValueChange={(value) => toggleSort(value)}
            wrapperClassName="w-[170px]"
          />
          {filtersActive ? (
            <Button
              variant="ghost"
              onClick={() =>
                changeFilter(() => {
                  setHostname("");
                  setStatus("");
                  setMinRisk("");
                  setPort("");
                  setTechnology("");
                })
              }
            >
              Clear
            </Button>
          ) : null}
        </div>

        {assets.loading ? (
          <SkeletonTable rows={8} columns={6} />
        ) : assets.error ? (
          <ErrorState message={assets.error.message} onRetry={assets.reload} />
        ) : items.length === 0 ? (
          filtersActive ? (
            <EmptyState
              illustration={<NoResultsArt />}
              title="No assets match these filters"
              description="Try widening the risk threshold or clearing the hostname filter."
              action={
                <Button
                  onClick={() =>
                    changeFilter(() => {
                      setHostname("");
                      setStatus("");
                      setMinRisk("");
                      setPort("");
                      setTechnology("");
                    })
                  }
                >
                  Clear filters
                </Button>
              }
            />
          ) : (
            <EmptyState
              illustration={<NoAssetsArt />}
              title="No assets yet"
              description="Run a scan to discover hosts automatically, or add one by hand if you already know it."
              action={
                <>
                  <Button variant="primary" onClick={() => setAddOpen(true)}>
                    Add asset
                  </Button>
                  <Link
                    href="/scan"
                    className="inline-flex h-8 items-center rounded border border-border bg-bg px-3 text-sm font-medium text-text transition-colors hover:bg-surface"
                  >
                    Run a scan
                  </Link>
                </>
              }
            />
          )
        ) : (
          <>
            <TableWrap>
              <THead>
                <TR>
                  <TH width="36px">
                    <span className="sr-only">Expand</span>
                  </TH>
                  <TH
                    sortable
                    active={sort === "hostname"}
                    direction="asc"
                    onSort={() => toggleSort("hostname")}
                  >
                    Host
                  </TH>
                  <TH>IP</TH>
                  <TH align="right" width="90px" sortable active={sort === "risk"} onSort={() => toggleSort("risk")}>
                    Risk
                  </TH>
                  <TH align="right" width="80px">
                    Ports
                  </TH>
                  <TH align="right" width="90px">
                    Findings
                  </TH>
                  <TH>Status</TH>
                  <TH
                    align="right"
                    sortable
                    active={sort === "last_scanned"}
                    onSort={() => toggleSort("last_scanned")}
                  >
                    Last scan
                  </TH>
                  <TH width="40px">
                    <span className="sr-only">Actions</span>
                  </TH>
                </TR>
              </THead>
              <TBody>
                {items.map((asset) => (
                  <AssetRow
                    key={asset.id}
                    asset={asset}
                    expanded={expanded === asset.id}
                    onToggle={() => setExpanded((current) => (current === asset.id ? null : asset.id))}
                    onOpen={() => openAsset(asset.id)}
                    onDelete={() => setPendingDelete(asset)}
                  />
                ))}
              </TBody>
            </TableWrap>
            <Pagination
              total={total}
              limit={PAGE_SIZE}
              offset={offset}
              onOffsetChange={(next) => {
                setOffset(next);
                setExpanded(null);
              }}
            />
          </>
        )}
      </Panel>

      <AddAssetModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={() => {
          setAddOpen(false);
          assets.reload();
        }}
      />

      <ConfirmModal
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={confirmDelete}
        busy={deleting}
        title="Delete this asset?"
        description={
          pendingDelete
            ? `${pendingDelete.hostname} and its findings will be removed from your inventory. A future scan may rediscover it.`
            : ""
        }
        confirmLabel="Delete asset"
      />
    </div>
  );
}

/**
 * One inventory row, plus its expanded detail.
 *
 * The expanded panel fetches the full asset because the list endpoint returns
 * AssetSummary — counts, not the port and technology arrays themselves. It is
 * only fetched once opened, so scrolling a page of 25 costs 25 rows, not 25
 * detail requests.
 */
function AssetRow({
  asset,
  expanded,
  onToggle,
  onOpen,
  onDelete,
}: {
  asset: AssetSummary;
  expanded: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const detail = useQuery<Asset | null>(
    useCallback(
      (signal) => (expanded ? api.assets.get(asset.id, signal) : Promise.resolve(null)),
      [expanded, asset.id],
    ),
    [expanded, asset.id],
  );

  return (
    <>
      <TR selected={expanded}>
        <TD>
          <button type="button" onClick={onToggle} aria-expanded={expanded} aria-label={expanded ? "Collapse" : "Expand"}>
            <ExpandToggle expanded={expanded} label={expanded ? "Collapse" : "Expand"} />
          </button>
        </TD>
        <TD>
          <AssetLink assetId={asset.id} hostname={asset.hostname} />
        </TD>
        <TD>
          <IpAddress value={asset.ip} />
        </TD>
        <TD align="right">
          <RiskScore score={asset.risk_score} />
        </TD>
        <TD align="right">
          <Mono muted={asset.open_port_count === 0}>{asset.open_port_count}</Mono>
        </TD>
        <TD align="right">
          <Mono muted={asset.finding_count === 0}>{asset.finding_count}</Mono>
        </TD>
        <TD>
          <AssetStatusBadge status={asset.status} />
        </TD>
        <TD align="right">
          <span className="whitespace-nowrap text-xs text-muted" title={formatDateTime(asset.last_scanned)}>
            {formatRelative(asset.last_scanned)}
          </span>
        </TD>
        <TD>
          <IconButton aria-label={`Delete ${asset.hostname}`} size="sm" onClick={onDelete}>
            <TrashIcon />
          </IconButton>
        </TD>
      </TR>

      {expanded ? (
        <ExpandRow colSpan={9}>
          {detail.loading || !detail.data ? (
            <SkeletonTable rows={2} columns={3} />
          ) : detail.error ? (
            <ErrorState message={detail.error.message} onRetry={detail.reload} compact />
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <h4 className="text-2xs font-medium uppercase tracking-wide text-muted">Open ports</h4>
                {detail.data.ports.length === 0 ? (
                  <p className="mt-1.5 text-sm text-muted">None recorded.</p>
                ) : (
                  <ul className="mt-1.5 flex flex-wrap gap-1.5">
                    {detail.data.ports.map((entry) => (
                      <li
                        key={`${entry.port}/${entry.protocol ?? "tcp"}`}
                        className="rounded border border-border px-1.5 py-0.5"
                      >
                        <Port port={entry.port} service={entry.service} />
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <h4 className="text-2xs font-medium uppercase tracking-wide text-muted">Technology</h4>
                {detail.data.tech_stack.length === 0 ? (
                  <p className="mt-1.5 text-sm text-muted">Nothing fingerprinted.</p>
                ) : (
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {detail.data.tech_stack.map((tech) => (
                      <Chip key={`${tech.name}@${tech.version ?? "?"}`}>
                        <Mono>
                          {tech.name}
                          {tech.version ? ` ${tech.version}` : ""}
                        </Mono>
                      </Chip>
                    ))}
                  </div>
                )}
              </div>
              <div className="sm:col-span-2">
                <Button size="sm" onClick={onOpen}>
                  Open full detail
                </Button>
              </div>
            </div>
          )}
        </ExpandRow>
      ) : null}
    </>
  );
}

/**
 * Manual asset entry.
 *
 * The backend enforces scope: a hostname outside the org's verified domains is
 * rejected with a 403 unless ALLOW_ARBITRARY_TARGETS is set. That message is
 * surfaced verbatim rather than reworded, because it names the domains in scope.
 */
function AddAssetModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { toast } = useToast();
  const [hostname, setHostname] = useState("");
  const [ip, setIp] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function reset() {
    setHostname("");
    setIp("");
    setNotes("");
    setError(null);
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.assets.create(hostname.trim(), ip.trim() || null, notes.trim() || null);
      toast(`${hostname.trim()} added to inventory`, "success");
      reset();
      onCreated();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not add that asset.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={() => {
        reset();
        onClose();
      }}
      title="Add an asset"
      description="Record a host you already know about. Scans will keep it up to date from here."
      footer={
        <>
          <Button
            onClick={() => {
              reset();
              onClose();
            }}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!hostname.trim()}>
            Add asset
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error ? (
          <p role="alert" className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg">
            {error}
          </p>
        ) : null}
        <Input
          label="Hostname"
          value={hostname}
          onChange={(event) => setHostname(event.target.value)}
          placeholder="api.example.com"
          hint="Must fall within your organisation's verified domains."
          mono
          required
          autoCapitalize="none"
          spellCheck={false}
        />
        <Input
          label="IP address"
          value={ip}
          onChange={(event) => setIp(event.target.value)}
          placeholder="Optional — resolved on the next scan"
          mono
        />
        <Input
          label="Notes"
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
          placeholder="Optional"
        />
      </div>
    </Modal>
  );
}
