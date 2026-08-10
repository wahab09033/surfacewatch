"use client";

/**
 * Scan console.
 *
 * The live terminal is the point of this page. It reads from the WebSocket at
 * `/ws/scan/{id}`, which relays the Redis channel the Celery workers publish to,
 * so lines appear as the scan produces them rather than on a poll interval.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { RefreshIcon, ScanIcon, StopIcon, TrashIcon } from "@/components/app/icons";
import { Chip, ScanStatusBadge } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { PageHeader, Panel } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoScansArt } from "@/components/ui/EmptyState";
import { Checkbox, Input, Select, Toggle } from "@/components/ui/Input";
import { ConfirmModal } from "@/components/ui/Modal";
import { Hostname, Mono } from "@/components/ui/Mono";
import { useToast } from "@/components/providers/ToastProvider";
import { SkeletonList } from "@/components/ui/Skeleton";
import { ApiError, api } from "@/lib/api";
import { cn, formatClock, formatDateTime, formatDuration, formatRelative, pluralise, titleCase } from "@/lib/format";
import { usePoll, useQuery } from "@/lib/hooks";
import { useScanStream } from "@/lib/useScanStream";
import type { LogLevel, Paginated, PortProfile, Scan, ScanModule, ScanStatus } from "@/lib/types";
import { MODULE_META, PORT_PROFILES, SCAN_MODULES, isTerminalScanStatus } from "@/lib/types";

const PORT_PROFILE_LABEL: Record<PortProfile, string> = {
  "top-100": "Top 100 ports",
  "top-1000": "Top 1000 ports",
  web: "Web ports only",
  full: "All 65535 ports",
  custom: "Custom list",
};

const PROFILE_OPTIONS = PORT_PROFILES.map((profile) => ({
  value: profile,
  label: PORT_PROFILE_LABEL[profile],
}));

export default function ScanPage() {
  const { toast } = useToast();

  const [target, setTarget] = useState("");
  const [modules, setModules] = useState<ScanModule[]>([...SCAN_MODULES]);
  const [portProfile, setPortProfile] = useState<PortProfile>("top-1000");
  const [customPorts, setCustomPorts] = useState("");
  const [passiveOnly, setPassiveOnly] = useState(false);
  const [includeWildcards, setIncludeWildcards] = useState(false);
  const [maxSubdomains, setMaxSubdomains] = useState("500");

  const [starting, setStarting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  /** The scan whose stream is on screen. Set on launch, or by clicking history. */
  const [watchedId, setWatchedId] = useState<string | null>(null);
  const [pendingCancel, setPendingCancel] = useState<Scan | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Scan | null>(null);
  const [busyAction, setBusyAction] = useState(false);

  const history = useQuery<Paginated<Scan>>(
    useCallback((signal) => api.scans.list({ limit: 20 }, signal), []),
    [],
  );

  // Memoised because `?? []` would mint a fresh array on every render while the
  // query is still loading, which would defeat the `watched` lookup below.
  const items = useMemo(() => history.data?.items ?? [], [history.data]);
  const anyActive = items.some((scan) => !isTerminalScanStatus(scan.status));

  // History rows carry counts and durations the socket does not, so they need
  // their own refresh — but only while something is actually in flight.
  usePoll(history.reload, anyActive ? 8_000 : null);

  const stream = useScanStream(watchedId, {
    onEnd: useCallback(
      (status: ScanStatus) => {
        toast(`Scan ${status}`, status === "completed" ? "success" : status === "failed" ? "error" : "info");
        history.reload();
      },
      [toast, history],
    ),
  });

  const watched = useMemo(
    () => items.find((scan) => scan.id === watchedId) ?? null,
    [items, watchedId],
  );

  // Passive mode is the backend's own constraint: it skips anything that sends
  // traffic. Reflecting that here keeps the toggles honest rather than letting
  // someone select a port scan that will be silently skipped.
  const moduleDisabled = useCallback(
    (module: ScanModule) => passiveOnly && !MODULE_META[module].passiveSafe,
    [passiveOnly],
  );

  const effectiveModules = useMemo(
    () => modules.filter((module) => !moduleDisabled(module)),
    [modules, moduleDisabled],
  );

  const portScanSelected = effectiveModules.includes("port_scanner");

  async function launch() {
    setFormError(null);

    if (effectiveModules.length === 0) {
      setFormError("Select at least one module. Passive mode disables the active ones.");
      return;
    }

    const ports = customPorts
      .split(/[\s,]+/)
      .map((part) => Number(part))
      .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);

    if (portProfile === "custom" && ports.length === 0 && portScanSelected) {
      setFormError("A custom profile needs at least one valid port between 1 and 65535.");
      return;
    }

    setStarting(true);
    try {
      const scan = await api.scans.create(target.trim(), {
        modules: effectiveModules,
        port_profile: portProfile,
        ports,
        passive_only: passiveOnly,
        include_wildcards: includeWildcards,
        max_subdomains: Math.min(Math.max(Number(maxSubdomains) || 500, 1), 10_000),
      });
      setWatchedId(scan.id);
      toast(`Scan queued for ${scan.target}`, "success");
      history.reload();
    } catch (caught) {
      setFormError(
        caught instanceof ApiError ? caught.message : "Could not start that scan.",
      );
    } finally {
      setStarting(false);
    }
  }

  async function confirmCancel() {
    if (!pendingCancel) return;
    setBusyAction(true);
    try {
      await api.scans.cancel(pendingCancel.id);
      toast("Scan cancelled", "info");
      setPendingCancel(null);
      history.reload();
    } catch (caught) {
      toast(caught instanceof ApiError ? caught.message : "Could not cancel that scan", "error");
    } finally {
      setBusyAction(false);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setBusyAction(true);
    try {
      await api.scans.remove(pendingDelete.id);
      toast("Scan deleted", "info");
      if (watchedId === pendingDelete.id) setWatchedId(null);
      setPendingDelete(null);
      history.reload();
    } catch (caught) {
      toast(caught instanceof ApiError ? caught.message : "Could not delete that scan", "error");
    } finally {
      setBusyAction(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Scan"
        description="Launch a scan and watch it run. Output streams live from the workers."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4">
          <Panel title="New scan">
            <div className="flex flex-col gap-4">
              <Input
                label="Target"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="example.com"
                hint="A domain or host within your organisation's scope."
                mono
                required
                autoCapitalize="none"
                spellCheck={false}
                inputMode="url"
              />

              <div>
                <p className="text-xs font-medium text-text">Modules</p>
                <div className="mt-2.5 flex flex-col gap-3">
                  {SCAN_MODULES.map((module) => {
                    const meta = MODULE_META[module];
                    const disabled = moduleDisabled(module);
                    return (
                      <Toggle
                        key={module}
                        checked={modules.includes(module) && !disabled}
                        disabled={disabled}
                        onChange={(checked) =>
                          setModules((previous) =>
                            checked
                              ? [...previous, module]
                              : previous.filter((entry) => entry !== module),
                          )
                        }
                        label={meta.label}
                        description={
                          disabled ? `${meta.description} — sends traffic, so passive mode skips it` : meta.description
                        }
                      />
                    );
                  })}
                </div>
              </div>

              {portScanSelected ? (
                <>
                  <Select
                    label="Port profile"
                    value={portProfile}
                    options={PROFILE_OPTIONS}
                    onValueChange={setPortProfile}
                    hint={
                      portProfile === "full"
                        ? "All 65535 ports is slow and noisy. Expect it to take a while."
                        : undefined
                    }
                  />
                  {portProfile === "custom" ? (
                    <Input
                      label="Ports"
                      value={customPorts}
                      onChange={(event) => setCustomPorts(event.target.value)}
                      placeholder="80, 443, 8080-…"
                      hint="Comma or space separated."
                      mono
                    />
                  ) : null}
                </>
              ) : null}

              <Input
                label="Subdomain cap"
                value={maxSubdomains}
                onChange={(event) => setMaxSubdomains(event.target.value.replace(/\D/g, "").slice(0, 5))}
                mono
                inputMode="numeric"
                hint="Stops enumeration running away on a large estate."
              />

              <div className="flex flex-col gap-2.5 border-t border-border pt-4">
                <Checkbox
                  checked={passiveOnly}
                  onChange={setPassiveOnly}
                  label="Passive only — no traffic to the target"
                />
                <Checkbox
                  checked={includeWildcards}
                  onChange={setIncludeWildcards}
                  label="Include wildcard DNS records"
                />
              </div>

              {formError ? (
                <p
                  role="alert"
                  className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
                >
                  {formError}
                </p>
              ) : null}

              <Button
                variant="primary"
                size="lg"
                fullWidth
                busy={starting}
                disabled={target.trim().length < 3}
                onClick={() => void launch()}
              >
                <ScanIcon />
                Start scan
              </Button>
            </div>
          </Panel>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <LiveTerminal
            scan={watched}
            watchedId={watchedId}
            stream={stream}
            onCancel={() => watched && setPendingCancel(watched)}
          />

          <Panel
            title="Scan history"
            subtitle={history.data ? `${history.data.total.toLocaleString()} ${pluralise(history.data.total, "scan")}` : undefined}
            action={
              <IconButton aria-label="Refresh history" size="sm" onClick={history.reload} disabled={history.refreshing}>
                <RefreshIcon />
              </IconButton>
            }
            flush
          >
            {history.loading ? (
              <div className="p-4">
                <SkeletonList rows={4} />
              </div>
            ) : history.error ? (
              <ErrorState message={history.error.message} onRetry={history.reload} compact />
            ) : items.length === 0 ? (
              <EmptyState
                compact
                illustration={<NoScansArt />}
                title="No scans yet"
                description="Your scan history will build up here as you run them."
              />
            ) : (
              <ul className="divide-y divide-border">
                {items.map((scan) => {
                  const active = !isTerminalScanStatus(scan.status);
                  return (
                    <li
                      key={scan.id}
                      className={cn(
                        "flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3 transition-colors",
                        watchedId === scan.id && "bg-surface",
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => setWatchedId(scan.id)}
                        className="min-w-0 flex-1 text-left"
                        title={active ? "Watch this scan" : "Replay this scan's log"}
                      >
                        <Hostname
                          value={scan.target}
                          truncate
                          className="underline decoration-border underline-offset-2 hover:decoration-accent"
                        />
                        <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                          <span title={formatDateTime(scan.created_at)}>{formatRelative(scan.created_at)}</span>
                          <span aria-hidden="true">·</span>
                          <Mono muted className="text-2xs">
                            {scan.assets_discovered} {pluralise(scan.assets_discovered, "asset")}
                          </Mono>
                          <span aria-hidden="true">·</span>
                          <Mono muted className="text-2xs">
                            {scan.findings_count} {pluralise(scan.findings_count, "finding")}
                          </Mono>
                          {scan.duration_seconds !== null ? (
                            <>
                              <span aria-hidden="true">·</span>
                              <Mono muted className="text-2xs">
                                {formatDuration(scan.duration_seconds)}
                              </Mono>
                            </>
                          ) : null}
                        </span>
                        {scan.error ? (
                          <span className="mt-1 block text-xs text-accent">{scan.error}</span>
                        ) : null}
                      </button>

                      <div className="flex shrink-0 items-center gap-1.5">
                        <ScanStatusBadge status={scan.status} />
                        {active ? (
                          <IconButton
                            aria-label={`Cancel scan of ${scan.target}`}
                            size="sm"
                            onClick={() => setPendingCancel(scan)}
                          >
                            <StopIcon />
                          </IconButton>
                        ) : (
                          <IconButton
                            aria-label={`Delete scan of ${scan.target}`}
                            size="sm"
                            onClick={() => setPendingDelete(scan)}
                          >
                            <TrashIcon />
                          </IconButton>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <ConfirmModal
        open={pendingCancel !== null}
        onClose={() => setPendingCancel(null)}
        onConfirm={confirmCancel}
        busy={busyAction}
        title="Cancel this scan?"
        description={
          pendingCancel
            ? `The scan of ${pendingCancel.target} will stop. Assets and findings already discovered are kept.`
            : ""
        }
        confirmLabel="Cancel scan"
        cancelLabel="Keep running"
      />

      <ConfirmModal
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={confirmDelete}
        busy={busyAction}
        title="Delete this scan?"
        description={
          pendingDelete
            ? `The scan record and its logs for ${pendingDelete.target} will be removed. Discovered assets stay in your inventory.`
            : ""
        }
        confirmLabel="Delete scan"
      />
    </div>
  );
}

const LEVEL_CLASS: Record<LogLevel, string> = {
  debug: "text-muted",
  info: "text-text",
  warning: "text-warn-fg",
  error: "text-sev-critical-fg",
};

/**
 * The live log terminal.
 *
 * Monospace throughout — this is machine output, which is exactly what the mono
 * stack is reserved for. Autoscroll follows the tail but yields the moment the
 * operator scrolls up, because yanking someone back to the bottom while they are
 * reading a stack trace is worse than not following at all.
 */
function LiveTerminal({
  scan,
  watchedId,
  stream,
  onCancel,
}: {
  scan: Scan | null;
  watchedId: string | null;
  stream: ReturnType<typeof useScanStream>;
  onCancel: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);

  useEffect(() => {
    if (!follow) return;
    const node = scrollRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [stream.lines, follow]);

  function onScroll() {
    const node = scrollRef.current;
    if (!node) return;
    // 24px of slack: "at the bottom" should survive sub-pixel rounding and the
    // last line arriving mid-scroll.
    const atBottom = node.scrollHeight - node.scrollTop - node.clientHeight < 24;
    setFollow(atBottom);
  }

  const status = stream.status ?? scan?.status ?? null;
  const active = status !== null && !isTerminalScanStatus(status);

  return (
    <Panel
      title="Live output"
      subtitle={
        watchedId
          ? scan
            ? scan.target
            : "Streaming"
          : "Start a scan, or pick one from the history below"
      }
      action={
        watchedId ? (
          <div className="flex items-center gap-2">
            {status ? <ScanStatusBadge status={status} /> : null}
            {active ? (
              <Button size="sm" variant="danger" onClick={onCancel}>
                <StopIcon />
                Stop
              </Button>
            ) : null}
          </div>
        ) : null
      }
      flush
    >
      {!watchedId ? (
        <EmptyState
          illustration={<NoScansArt />}
          title="Nothing streaming"
          description="Launch a scan to watch its output arrive line by line, or select a past scan to replay its log."
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-border px-4 py-2.5">
            <div className="flex min-w-[140px] flex-1 items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface">
                <div
                  className="h-full rounded-full bg-accent transition-[width] duration-500"
                  style={{ width: `${Math.min(Math.max(stream.progress, 0), 100)}%` }}
                />
              </div>
              <Mono muted className="shrink-0 text-2xs">
                {Math.round(stream.progress)}%
              </Mono>
            </div>
            <Chip>{stream.stage ? titleCase(stream.stage) : "—"}</Chip>
            <Mono muted className="text-2xs">
              {stream.assetsDiscovered} {pluralise(stream.assetsDiscovered, "asset")}
            </Mono>
            <Mono muted className="text-2xs">
              {stream.findingsCount} {pluralise(stream.findingsCount, "finding")}
            </Mono>
            <ConnectionDot state={stream.connection} />
          </div>

          {stream.notice ? (
            <p role="alert" className="border-b border-border bg-sev-critical-bg px-4 py-2 text-xs text-sev-critical-fg">
              {stream.notice}
            </p>
          ) : null}

          <div
            ref={scrollRef}
            onScroll={onScroll}
            className="h-[380px] overflow-y-auto bg-surface px-3 py-2.5"
            // A log region: announced as such, but not live — thousands of
            // streamed lines read aloud would be unusable.
            role="log"
            aria-label="Scan output"
          >
            {stream.lines.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted">
                {stream.connection === "connecting"
                  ? "Connecting to the stream…"
                  : "Waiting for the first line…"}
              </p>
            ) : (
              <ol className="flex flex-col gap-0.5">
                {stream.lines.map((line) => (
                  <li key={line.key} className="flex gap-2.5 font-mono text-[0.75rem] leading-relaxed">
                    <span className="shrink-0 tabular text-muted">{formatClock(line.timestamp)}</span>
                    {line.stage ? (
                      <span className="hidden shrink-0 text-muted sm:inline">[{line.stage}]</span>
                    ) : null}
                    <span className={cn("min-w-0 whitespace-pre-wrap break-words", LEVEL_CLASS[line.level])}>
                      {line.message}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-border px-3 py-2">
            <Mono muted className="text-2xs">
              {stream.lines.length} {pluralise(stream.lines.length, "line")}
            </Mono>
            <div className="flex items-center gap-2">
              {!follow ? (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setFollow(true);
                    const node = scrollRef.current;
                    if (node) node.scrollTop = node.scrollHeight;
                  }}
                >
                  Jump to latest
                </Button>
              ) : null}
              <Button size="sm" variant="ghost" onClick={stream.clear} disabled={stream.lines.length === 0}>
                Clear
              </Button>
            </div>
          </div>
        </>
      )}
    </Panel>
  );
}

/** Connection state as a dot plus a word. Colour alone would not carry it. */
function ConnectionDot({ state }: { state: ReturnType<typeof useScanStream>["connection"] }) {
  const label =
    state === "open" ? "Live" : state === "connecting" ? "Connecting" : state === "error" ? "Disconnected" : state === "closed" ? "Ended" : "Idle";

  return (
    <span className="flex items-center gap-1.5 text-2xs text-muted">
      <span
        aria-hidden="true"
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          state === "open" && "bg-ok-fg motion-safe:animate-pulse",
          state === "connecting" && "bg-warn-fg",
          state === "error" && "bg-accent",
          (state === "closed" || state === "idle") && "bg-muted",
        )}
      />
      {label}
    </span>
  );
}
