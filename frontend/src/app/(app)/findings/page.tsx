"use client";

/**
 * Findings triage queue.
 *
 * Cards rather than a table: a finding is a paragraph of context — title, CVE,
 * affected host, remediation — and a row of cells forces all of that into
 * truncation. Filters map onto routes/findings.py query parameters, including
 * repeated `severity` and `status` keys for multi-select.
 */

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { AssetLink } from "@/components/app/AssetDrawer";
import { RefreshIcon, SearchIcon } from "@/components/app/icons";
import {
  RemediationProvenanceNote,
  RemediationSourceChip,
} from "@/components/app/RemediationProvenance";
import { Chip, FindingStatusBadge, SeverityBadge } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { PageHeader, Panel, ProportionBar, StatCard } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoFindingsArt, NoResultsArt } from "@/components/ui/EmptyState";
import { Checkbox, Input, Select, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { CveId, Mono } from "@/components/ui/Mono";
import { useToast } from "@/components/providers/ToastProvider";
import { SkeletonCards, SkeletonStat } from "@/components/ui/Skeleton";
import { Pagination } from "@/components/ui/Table";
import { ApiError, api } from "@/lib/api";
import {
  FINDING_STATUS_LABEL,
  SEVERITY_LABEL,
  cn,
  formatDateTime,
  formatRelative,
  pluralise,
} from "@/lib/format";
import { useDebounced, useQuery } from "@/lib/hooks";
import type {
  Finding,
  FindingSort,
  FindingStats,
  FindingStatus,
  Paginated,
  Severity,
} from "@/lib/types";
import { FINDING_STATUSES, SEVERITIES, isAiRemediation, readRemediationProvenance } from "@/lib/types";

const PAGE_SIZE = 20;

const SORT_OPTIONS: { value: FindingSort; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "cvss", label: "CVSS score" },
  { value: "created", label: "Newest" },
  { value: "last_seen", label: "Recently seen" },
];

const SEVERITY_BAR: Record<Severity, string> = {
  critical: "bg-sev-critical-fg",
  high: "bg-sev-high-fg",
  medium: "bg-sev-medium-fg",
  low: "bg-sev-low-fg",
  info: "bg-sev-info-fg",
};

export default function FindingsPage() {
  const [severity, setSeverity] = useState<Severity[]>([]);
  const [statuses, setStatuses] = useState<FindingStatus[]>([]);
  const [openOnly, setOpenOnly] = useState(true);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<FindingSort>("severity");
  const [offset, setOffset] = useState(0);
  const [triaging, setTriaging] = useState<Finding | null>(null);

  const debouncedSearch = useDebounced(search);

  const query = useMemo(
    () => ({
      severity: severity.length > 0 ? severity : undefined,
      status: statuses.length > 0 ? statuses : undefined,
      // The backend treats open_only as an additional AND, so sending both it
      // and an explicit status list would silently drop closed selections.
      open_only: statuses.length === 0 && openOnly ? true : undefined,
      search: debouncedSearch.trim() || undefined,
      sort,
      limit: PAGE_SIZE,
      offset,
    }),
    [severity, statuses, openOnly, debouncedSearch, sort, offset],
  );

  const findings = useQuery<Paginated<Finding>>(
    useCallback((signal) => api.findings.list(query, signal), [query]),
    [query],
  );

  const stats = useQuery<FindingStats>(
    useCallback((signal) => api.findings.stats(signal), []),
    [],
  );

  function changeFilter(apply: () => void) {
    apply();
    setOffset(0);
  }

  function toggleSeverity(value: Severity) {
    changeFilter(() =>
      setSeverity((previous) =>
        previous.includes(value) ? previous.filter((s) => s !== value) : [...previous, value],
      ),
    );
  }

  function toggleStatus(value: FindingStatus) {
    changeFilter(() =>
      setStatuses((previous) =>
        previous.includes(value) ? previous.filter((s) => s !== value) : [...previous, value],
      ),
    );
  }

  const filtersActive =
    severity.length > 0 || statuses.length > 0 || Boolean(debouncedSearch.trim()) || !openOnly;

  function clearFilters() {
    changeFilter(() => {
      setSeverity([]);
      setStatuses([]);
      setSearch("");
      setOpenOnly(true);
    });
  }

  function reloadAll() {
    findings.reload();
    stats.reload();
  }

  const items = findings.data?.items ?? [];
  const total = findings.data?.total ?? 0;

  const segments = SEVERITIES.map((s) => ({
    key: s,
    value: stats.data?.by_severity[s] ?? 0,
    className: SEVERITY_BAR[s],
    label: SEVERITY_LABEL[s],
  }));

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Findings"
        description="Everything discovered across your estate, ranked by what matters."
        actions={
          <IconButton
            aria-label="Refresh"
            onClick={reloadAll}
            disabled={findings.refreshing || stats.refreshing}
          >
            <RefreshIcon />
          </IconButton>
        }
      />

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.loading ? (
          Array.from({ length: 4 }, (_, i) => <SkeletonStat key={i} />)
        ) : stats.data ? (
          <>
            <StatCard label="Total findings" value={stats.data.total.toLocaleString()} />
            <StatCard
              label="Open"
              value={stats.data.open.toLocaleString()}
              tone={stats.data.open > 0 ? "warn" : "ok"}
              delta={stats.data.total > 0 ? <ProportionBar segments={segments} className="mt-1" /> : undefined}
            />
            <StatCard
              label="Critical"
              value={(stats.data.by_severity.critical ?? 0).toLocaleString()}
              tone={(stats.data.by_severity.critical ?? 0) > 0 ? "warn" : "neutral"}
              onClick={() => changeFilter(() => setSeverity(["critical"]))}
            />
            <StatCard
              label="Mean CVSS"
              value={stats.data.mean_cvss !== null ? stats.data.mean_cvss.toFixed(1) : "—"}
              delta={
                stats.data.top_cves.length > 0
                  ? `Most frequent: ${stats.data.top_cves[0]?.cve_id ?? "—"}`
                  : "No scored findings"
              }
            />
          </>
        ) : null}
      </div>

      <Panel
        title="Triage queue"
        subtitle={
          findings.loading ? undefined : `${total.toLocaleString()} ${pluralise(total, "finding")}`
        }
        flush
      >
        <div className="flex flex-col gap-3 border-b border-border px-3 py-3">
          <div className="flex flex-wrap items-end gap-2">
            <Input
              aria-label="Search findings"
              placeholder="Search title or description…"
              value={search}
              onChange={(event) => changeFilter(() => setSearch(event.target.value))}
              leading={<SearchIcon />}
              wrapperClassName="min-w-[220px] flex-1"
            />
            <Select
              aria-label="Sort findings"
              value={sort}
              options={SORT_OPTIONS}
              onValueChange={(value) => changeFilter(() => setSort(value))}
              wrapperClassName="w-[170px]"
            />
            {filtersActive ? (
              <Button variant="ghost" onClick={clearFilters}>
                Clear
              </Button>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {SEVERITIES.map((value) => {
              const active = severity.includes(value);
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => toggleSeverity(value)}
                  aria-pressed={active}
                  className={cn("rounded transition-opacity", !active && "opacity-55 hover:opacity-100")}
                >
                  <SeverityBadge severity={value} />
                </button>
              );
            })}

            <span className="mx-1 h-4 w-px bg-border" aria-hidden="true" />

            {FINDING_STATUSES.map((value) => {
              const active = statuses.includes(value);
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => toggleStatus(value)}
                  aria-pressed={active}
                  className={cn("rounded transition-opacity", !active && "opacity-55 hover:opacity-100")}
                >
                  <FindingStatusBadge status={value} />
                </button>
              );
            })}

            {statuses.length === 0 ? (
              <div className="ml-auto">
                <Checkbox
                  checked={openOnly}
                  onChange={(checked) => changeFilter(() => setOpenOnly(checked))}
                  label="Open only"
                />
              </div>
            ) : null}
          </div>
        </div>

        {findings.loading ? (
          <div className="p-4">
            <SkeletonCards count={5} />
          </div>
        ) : findings.error ? (
          <ErrorState message={findings.error.message} onRetry={findings.reload} />
        ) : items.length === 0 ? (
          filtersActive ? (
            <EmptyState
              illustration={<NoResultsArt />}
              title="No findings match these filters"
              description="Try widening the severity selection or clearing the search."
              action={<Button onClick={clearFilters}>Clear filters</Button>}
            />
          ) : (
            <EmptyState
              illustration={<NoFindingsArt />}
              title="No findings"
              description="Nothing has been reported against your assets. Run a scan to check again."
              action={
                <Link
                  href="/scan"
                  className="inline-flex h-8 items-center rounded border border-border bg-bg px-3 text-sm font-medium text-text transition-colors hover:bg-surface"
                >
                  Run a scan
                </Link>
              }
            />
          )
        ) : (
          <>
            <ul className="flex flex-col gap-3 p-3">
              {items.map((finding) => (
                <li key={finding.id}>
                  <FindingCard finding={finding} onTriage={() => setTriaging(finding)} />
                </li>
              ))}
            </ul>
            <Pagination
              total={total}
              limit={PAGE_SIZE}
              offset={offset}
              onOffsetChange={setOffset}
            />
          </>
        )}
      </Panel>

      <TriageModal
        finding={triaging}
        onClose={() => setTriaging(null)}
        onSaved={() => {
          setTriaging(null);
          reloadAll();
        }}
      />
    </div>
  );
}

/**
 * One finding.
 *
 * The severity badge and CVE lead, because that is what an analyst scans down
 * the page for. Description is clamped — the full text is in the triage modal,
 * and a 40-line description would push every other finding off the screen.
 */
function FindingCard({ finding, onTriage }: { finding: Finding; onTriage: () => void }) {
  // Only meaningful when there is remediation text for it to describe: a
  // provenance record with nothing to attribute is noise.
  const provenance = finding.remediation ? readRemediationProvenance(finding.evidence) : null;

  return (
    <article className="rounded-lg border border-border bg-bg p-4 transition-colors hover:border-border-strong">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <FindingStatusBadge status={finding.status} />
        {finding.cve_id ? <CveId value={finding.cve_id} /> : null}
        {finding.cvss_score !== null ? (
          <Mono muted className="text-2xs">
            CVSS {finding.cvss_score.toFixed(1)}
          </Mono>
        ) : null}
        {finding.source ? <Chip>{finding.source}</Chip> : null}
        {provenance ? <RemediationSourceChip provenance={provenance} /> : null}
        <span
          className="ml-auto whitespace-nowrap text-xs text-muted"
          title={formatDateTime(finding.created_at)}
        >
          {formatRelative(finding.created_at)}
        </span>
      </div>

      <h3 className="mt-2.5 text-sm font-medium leading-snug text-text">{finding.title}</h3>

      {finding.description ? (
        <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-muted">{finding.description}</p>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
        {finding.asset_id && finding.asset_hostname ? (
          <AssetLink assetId={finding.asset_id} hostname={finding.asset_hostname} />
        ) : finding.asset_hostname ? (
          <Mono muted>{finding.asset_hostname}</Mono>
        ) : (
          <span className="text-xs text-muted">Not tied to an asset</span>
        )}

        <div className="ml-auto flex items-center gap-2">
          {finding.references.length > 0 ? (
            <Mono muted className="text-2xs">
              {finding.references.length} {pluralise(finding.references.length, "reference")}
            </Mono>
          ) : null}
          <Button size="sm" onClick={onTriage}>
            Triage
          </Button>
        </div>
      </div>
    </article>
  );
}

const STATUS_OPTIONS = FINDING_STATUSES.map((status) => ({
  value: status,
  label: FINDING_STATUS_LABEL[status],
}));

const SEVERITY_OPTIONS = SEVERITIES.map((severity) => ({
  value: severity,
  label: SEVERITY_LABEL[severity],
}));

/**
 * Triage a finding.
 *
 * Status, severity override, remediation and analyst notes all go up in one
 * PATCH — the backend accepts them together and stamps `resolved_at` itself when
 * the status leaves the open set.
 */
function TriageModal({
  finding,
  onClose,
  onSaved,
}: {
  finding: Finding | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const [status, setStatus] = useState<FindingStatus>("open");
  const [severity, setSeverity] = useState<Severity>("info");
  const [remediation, setRemediation] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Re-seed the form whenever a different finding is opened. Keyed on id so
  // reopening the same one does not clobber an in-progress edit.
  const provenance = finding?.remediation ? readRemediationProvenance(finding.evidence) : null;

  const [seededId, setSeededId] = useState<string | null>(null);
  if (finding && finding.id !== seededId) {
    setSeededId(finding.id);
    setStatus(finding.status);
    setSeverity(finding.severity);
    setRemediation(finding.remediation ?? "");
    setNotes(typeof finding.evidence?.analyst_notes === "string" ? finding.evidence.analyst_notes : "");
    setError(null);
  }

  async function save() {
    if (!finding) return;
    setBusy(true);
    setError(null);
    try {
      await api.findings.update(finding.id, {
        status,
        severity,
        remediation: remediation.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      toast("Finding updated", "success");
      onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not update that finding.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={finding !== null}
      onClose={onClose}
      title="Triage finding"
      description={finding?.title}
      size="lg"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void save()} busy={busy}>
            Save
          </Button>
        </>
      }
    >
      {finding ? (
        <div className="flex flex-col gap-4">
          {error ? (
            <p
              role="alert"
              className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
            >
              {error}
            </p>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            {finding.cve_id ? <CveId value={finding.cve_id} /> : null}
            {finding.cvss_score !== null ? (
              <Mono muted className="text-2xs">
                CVSS {finding.cvss_score.toFixed(1)}
              </Mono>
            ) : null}
            {finding.cvss_vector ? (
              <Mono muted truncate className="text-2xs">
                {finding.cvss_vector}
              </Mono>
            ) : null}
          </div>

          {finding.description ? (
            <div>
              <h4 className="text-2xs font-medium uppercase tracking-wide text-muted">Description</h4>
              <p className="mt-1.5 max-h-40 overflow-y-auto whitespace-pre-wrap text-sm leading-relaxed text-text">
                {finding.description}
              </p>
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Select
              label="Status"
              value={status}
              options={STATUS_OPTIONS}
              onValueChange={setStatus}
            />
            <Select
              label="Severity"
              value={severity}
              options={SEVERITY_OPTIONS}
              onValueChange={setSeverity}
              hint={
                severity !== finding.severity
                  ? `Overriding the scanner's ${SEVERITY_LABEL[finding.severity].toLowerCase()} rating`
                  : undefined
              }
            />
          </div>

          <div className="flex flex-col gap-2">
            {provenance ? <RemediationProvenanceNote provenance={provenance} /> : null}
            <Textarea
              label="Remediation"
              value={remediation}
              onChange={(event) => setRemediation(event.target.value)}
              rows={provenance ? 8 : 3}
              placeholder="How this should be fixed"
              hint={
                provenance && isAiRemediation(provenance.source)
                  ? "Editing this replaces the generated text, and the finding is re-attributed to you."
                  : undefined
              }
            />
          </div>

          <Textarea
            label="Analyst notes"
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            rows={3}
            placeholder="Context for whoever picks this up next"
            hint="Stored on the finding's evidence record."
          />

          {finding.references.length > 0 ? (
            <div>
              <h4 className="text-2xs font-medium uppercase tracking-wide text-muted">References</h4>
              <ul className="mt-1.5 flex flex-col gap-1">
                {finding.references.map((reference) => (
                  <li key={reference}>
                    <a
                      href={reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="break-all font-mono text-2xs text-muted underline decoration-border underline-offset-2 hover:text-text hover:decoration-accent"
                    >
                      {reference}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}
