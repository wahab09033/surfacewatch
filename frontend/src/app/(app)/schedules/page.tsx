"use client";

/**
 * Recurring scans.
 *
 * A schedule is a **standing authorisation to scan**: it commits the
 * organisation to network traffic against a host indefinitely, with nobody
 * watching. That is a different decision from running one scan, which is why
 * writes here are admin-gated while "run now" is not — starting a single scan
 * is an analyst's job, committing to a recurring one is not.
 *
 * Two server-side behaviours shape this page:
 *
 * * The **target cannot be edited**. Changing it would silently repoint a
 *   recurring scan at a host whose authorisation was never checked, so the
 *   backend refuses it and the UI does not offer it. To retarget, delete and
 *   recreate.
 * * A schedule can **disable itself**. After `SCHEDULE_MAX_CONSECUTIVE_FAILURES`
 *   broker failures the dispatcher switches it off and writes `disabled_reason`,
 *   which is shown verbatim — an autodisabled schedule with no explanation reads
 *   as a bug rather than as an outage that has passed.
 *
 * Schedules only fire while the `beat` service is running. Nothing available to
 * the browser can tell whether it is, so the page says so once rather than
 * showing a green light it cannot back up.
 */

import { useCallback, useState } from "react";

import {
  PauseIcon,
  PlayIcon,
  PlusIcon,
  RefreshIcon,
  ScanIcon,
  ScheduleIcon,
  TrashIcon,
} from "@/components/app/icons";
import { useAuth } from "@/components/providers/AuthProvider";
import { useToast } from "@/components/providers/ToastProvider";
import { Chip } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { PageHeader, Panel } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoScansArt } from "@/components/ui/EmptyState";
import { Checkbox, Input, Select, Toggle } from "@/components/ui/Input";
import { ConfirmModal, Modal } from "@/components/ui/Modal";
import { Hostname, Mono } from "@/components/ui/Mono";
import { SkeletonList } from "@/components/ui/Skeleton";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, formatRelative, formatUntil, pluralise, titleCase } from "@/lib/format";
import { useQuery } from "@/lib/hooks";
import type {
  PortProfile,
  ScanCadence,
  ScanConfig,
  ScanModule,
  Schedule,
  ScheduleList,
  ScheduleUpdate,
} from "@/lib/types";
import { CADENCE_LABEL, MODULE_META, PROFILE_OPTIONS, SCAN_CADENCES, SCAN_MODULES, WEEKDAY_NAMES } from "@/lib/types";

const CADENCE_OPTIONS = SCAN_CADENCES.map((cadence) => ({
  value: cadence,
  label: CADENCE_LABEL[cadence],
}));

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, hour) => ({
  value: String(hour),
  label: `${String(hour).padStart(2, "0")}:00 UTC`,
}));

const WEEKDAY_OPTIONS = WEEKDAY_NAMES.map((name, index) => ({
  value: String(index),
  label: name,
}));

export default function SchedulesPage() {
  const { hasRole } = useAuth();

  // Split rather than gating inside the body: the body's `useQuery` fires on
  // mount, and `GET /api/schedules` is analyst+, so a viewer would issue a
  // request that 403s every time they opened this page and then be shown a
  // failure where an explanation belongs. `hasRole` is safe to call here — the
  // guard above has already resolved the session.
  if (!hasRole("analyst")) {
    return (
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Scheduled scans"
          description="Recurring scans that run on their own and file their findings like any other."
        />
        <Panel title="Schedules">
          <EmptyState
            compact
            illustration={<NoScansArt />}
            title="Not available for your role"
            description="Schedules are visible to analysts and above. An admin can also change them; ask someone with that role if you need one set up."
          />
        </Panel>
      </div>
    );
  }

  return <SchedulesPageBody />;
}

function SchedulesPageBody() {
  const { hasRole } = useAuth();
  const { toast } = useToast();

  const canManage = hasRole("admin");
  const canRun = hasRole("analyst");

  const schedules = useQuery<ScheduleList>(
    useCallback((signal) => api.schedules.list(signal), []),
    [],
  );

  /** null = closed. `undefined` is not used, so "no schedule" is unambiguous. */
  const [formTarget, setFormTarget] = useState<Schedule | "new" | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Schedule | null>(null);
  /** Id of the row with an action in flight, so only that row shows busy. */
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const items = schedules.data?.items ?? [];

  const patch = useCallback(
    async (schedule: Schedule, changes: ScheduleUpdate, note: string) => {
      setBusyId(schedule.id);
      try {
        await api.schedules.update(schedule.id, changes);
        schedules.reload();
        toast(note, "success");
      } catch (caught) {
        toast(caught instanceof ApiError ? caught.message : "Could not update that schedule", "error");
      } finally {
        setBusyId(null);
      }
    },
    [schedules, toast],
  );

  const runNow = useCallback(
    async (schedule: Schedule) => {
      setBusyId(schedule.id);
      try {
        await api.schedules.runNow(schedule.id);
        schedules.reload();
        toast(`Scan of ${schedule.target} queued`, "success");
      } catch (caught) {
        // 429 when the org is at its concurrency cap, 403 when the domain has
        // since been revoked. Both explain themselves, so they are passed on.
        toast(caught instanceof ApiError ? caught.message : "Could not start that scan", "error");
      } finally {
        setBusyId(null);
      }
    },
    [schedules, toast],
  );

  const remove = useCallback(async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.schedules.remove(pendingDelete.id);
      setPendingDelete(null);
      schedules.reload();
      toast("Schedule deleted", "success");
    } catch (caught) {
      toast(caught instanceof ApiError ? caught.message : "Could not delete that schedule", "error");
    } finally {
      setDeleting(false);
    }
  }, [pendingDelete, schedules, toast]);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Scheduled scans"
        description="Recurring scans that run on their own and file their findings like any other."
      />

      <Panel
        title="Schedules"
        subtitle={
          schedules.loading
            ? undefined
            : `${items.filter((s) => s.is_enabled).length} of ${items.length} ${pluralise(items.length, "schedule")} enabled`
        }
        action={
          <div className="flex items-center gap-1">
            <IconButton
              aria-label="Refresh schedules"
              size="sm"
              onClick={schedules.reload}
              disabled={schedules.refreshing}
            >
              <RefreshIcon />
            </IconButton>
            {canManage ? (
              <Button variant="primary" size="sm" onClick={() => setFormTarget("new")}>
                <PlusIcon />
                New schedule
              </Button>
            ) : null}
          </div>
        }
      >
        {schedules.loading ? (
          <SkeletonList rows={3} />
        ) : schedules.error ? (
          <ErrorState message={schedules.error.message} onRetry={schedules.reload} compact />
        ) : items.length === 0 ? (
          <EmptyState
            compact
            illustration={<NoScansArt />}
            title="No scheduled scans"
            description={
              canManage
                ? "A schedule runs a scan on a cadence you choose and stores the results, so drift shows up without anyone remembering to look."
                : "Nothing is scheduled yet. An admin or owner can set one up."
            }
            action={
              canManage ? (
                <Button variant="primary" onClick={() => setFormTarget("new")}>
                  <PlusIcon />
                  New schedule
                </Button>
              ) : undefined
            }
          />
        ) : (
          <ul className="flex flex-col gap-3">
            {items.map((schedule) => (
              <ScheduleRow
                key={schedule.id}
                schedule={schedule}
                canManage={canManage}
                canRun={canRun}
                busy={busyId === schedule.id}
                onRun={() => void runNow(schedule)}
                onToggle={() =>
                  void patch(
                    schedule,
                    { is_enabled: !schedule.is_enabled },
                    schedule.is_enabled
                      ? `${schedule.name} paused`
                      : `${schedule.name} resumed`,
                  )
                }
                onEdit={() => setFormTarget(schedule)}
                onDelete={() => setPendingDelete(schedule)}
              />
            ))}
          </ul>
        )}

        <p className="mt-4 border-t border-border pt-3 text-xs leading-relaxed text-muted">
          Schedules fire from the Celery beat service. If beat is not running they stay listed here
          as enabled and never fire, so a schedule that has not run when it should is worth checking
          there first.
        </p>
      </Panel>

      <ScheduleModal
        // Remounting on a different target resets the form's state, which is
        // what makes "New schedule" after "Edit" start blank.
        key={formTarget === "new" ? "new" : (formTarget?.id ?? "closed")}
        open={formTarget !== null}
        schedule={formTarget === "new" ? null : formTarget}
        onClose={() => setFormTarget(null)}
        onSaved={() => {
          setFormTarget(null);
          schedules.reload();
        }}
      />

      <ConfirmModal
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={remove}
        busy={deleting}
        title="Delete this schedule?"
        description={
          pendingDelete
            ? `${pendingDelete.name} will stop running. Scans it has already produced are kept — they are ordinary scan records, and their findings stay in your inventory.`
            : ""
        }
        confirmLabel="Delete schedule"
      />
    </div>
  );
}

/** One schedule: what it is, when it next runs, and what can be done to it. */
function ScheduleRow({
  schedule,
  canManage,
  canRun,
  busy,
  onRun,
  onToggle,
  onEdit,
  onDelete,
}: {
  schedule: Schedule;
  canManage: boolean;
  canRun: boolean;
  busy: boolean;
  onRun: () => void;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const paused = !schedule.is_enabled;

  return (
    <li className="rounded border border-border bg-surface px-3 py-3">
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <div className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium text-text">{schedule.name}</span>
            {paused ? (
              <Chip className={schedule.disabled_reason ? "border-warn-fg/25 bg-warn-bg text-warn-fg" : undefined}>
                {schedule.disabled_reason ? "Disabled automatically" : "Paused"}
              </Chip>
            ) : (
              <Chip className="border-ok-fg/25 bg-ok-bg text-ok-fg">Enabled</Chip>
            )}
          </span>

          <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
            <Hostname value={schedule.target} truncate />
          </span>

          <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
            <span className="flex items-center gap-1">
              <ScheduleIcon />
              {schedule.schedule_text ?? titleCase(schedule.cadence)}
            </span>
            <span aria-hidden="true">·</span>
            {paused ? (
              <span>Not scheduled</span>
            ) : (
              // formatUntil, not formatRelative: next_run_at is in the future and
              // formatRelative renders every future timestamp as "Just now".
              <span title={formatDateTime(schedule.next_run_at)}>
                Next {formatUntil(schedule.next_run_at)}
              </span>
            )}
            <span aria-hidden="true">·</span>
            <span title={formatDateTime(schedule.last_run_at)}>
              Last ran {schedule.last_run_at ? formatRelative(schedule.last_run_at) : "never"}
            </span>
          </span>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {canRun ? (
            <Button size="sm" onClick={onRun} busy={busy} disabled={busy}>
              <ScanIcon />
              Run now
            </Button>
          ) : null}
          {canManage ? (
            <>
              <Button size="sm" onClick={onToggle} disabled={busy}>
                {paused ? <PlayIcon /> : <PauseIcon />}
                {paused ? "Resume" : "Pause"}
              </Button>
              <Button size="sm" onClick={onEdit} disabled={busy}>
                Edit
              </Button>
              <IconButton
                aria-label={`Delete ${schedule.name}`}
                size="sm"
                onClick={onDelete}
                disabled={busy}
              >
                <TrashIcon />
              </IconButton>
            </>
          ) : null}
        </div>
      </div>

      {schedule.disabled_reason ? (
        // Verbatim. The alternative is a paused schedule whose reason nobody can
        // see, which is indistinguishable from one somebody paused on purpose.
        <p className="mt-2 rounded border border-warn-fg/25 bg-warn-bg px-2.5 py-2 text-xs leading-relaxed text-warn-fg">
          {schedule.disabled_reason}
        </p>
      ) : null}

      {/*
        Shown only while enabled: consecutive_failures is reset on re-enable, and
        a paused schedule's count is history rather than a warning.
      */}
      {schedule.is_enabled && schedule.consecutive_failures > 0 ? (
        <p className="mt-2 text-xs text-warn-fg">
          {schedule.consecutive_failures} consecutive dispatch{" "}
          {pluralise(schedule.consecutive_failures, "failure")}. It disables itself after several in
          a row.
        </p>
      ) : null}
    </li>
  );
}

/**
 * Create or edit a schedule.
 *
 * Editing cannot change the target — the backend refuses it, because repointing
 * a recurring scan would carry its authorisation to a host nobody checked. The
 * field is rendered read-only with the reason rather than omitted, so the
 * absence reads as a decision instead of an oversight.
 */
function ScheduleModal({
  open,
  schedule,
  onClose,
  onSaved,
}: {
  open: boolean;
  schedule: Schedule | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { toast } = useToast();
  const editing = schedule !== null;

  const [name, setName] = useState(schedule?.name ?? "");
  const [target, setTarget] = useState(schedule?.target ?? "");
  const [cadence, setCadence] = useState<ScanCadence>(schedule?.cadence ?? "daily");
  const [hour, setHour] = useState(String(schedule?.hour_utc ?? 3));
  const [weekday, setWeekday] = useState(String(schedule?.weekday ?? 0));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The scan profile. Seeded from the schedule being edited, or from the
  // backend's own ScanConfig defaults for a new one — the same values a scan
  // launched from /scan would start with.
  //
  // Annotated rather than inferred: `schedule?.config ?? {}` widens to
  // `… | {}`, and `{}` has no `modules`, so every read below would be an error.
  // The schedule's config is `Partial<ScanConfig> & Record<string, unknown>` —
  // the index signature is there because the column is free-form JSONB — so
  // narrowing to `Partial<ScanConfig>` is what makes the fields readable.
  const stored: Partial<ScanConfig> = schedule?.config ?? {};

  const [modules, setModules] = useState<ScanModule[]>(stored.modules ?? [...SCAN_MODULES]);
  const [portProfile, setPortProfile] = useState<PortProfile>(stored.port_profile ?? "top-1000");
  const [customPorts, setCustomPorts] = useState((stored.ports ?? []).join(", "));
  const [maxSubdomains, setMaxSubdomains] = useState(String(stored.max_subdomains ?? 500));
  const [passiveOnly, setPassiveOnly] = useState(Boolean(stored.passive_only));
  const [includeWildcards, setIncludeWildcards] = useState(Boolean(stored.include_wildcards));

  // Mirrors the scan page and the backend: passive mode skips anything that
  // sends traffic, so the toggles say so rather than letting someone configure
  // a port scan that will be silently skipped.
  const moduleDisabled = (module: ScanModule) => passiveOnly && !MODULE_META[module].passiveSafe;
  const effectiveModules = modules.filter((module) => !moduleDisabled(module));
  const portScanSelected = effectiveModules.includes("port_scanner");

  async function submit() {
    setError(null);

    if (effectiveModules.length === 0) {
      setError("Select at least one module. Passive mode disables the active ones.");
      return;
    }

    const ports = customPorts
      .split(/[\s,]+/)
      .map((part) => Number(part))
      .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);

    if (portProfile === "custom" && ports.length === 0 && portScanSelected) {
      setError("A custom profile needs at least one valid port between 1 and 65535.");
      return;
    }

    const config = {
      modules: effectiveModules,
      port_profile: portProfile,
      ports,
      max_subdomains: Math.min(Math.max(Number(maxSubdomains) || 500, 1), 10_000),
      passive_only: passiveOnly,
      include_wildcards: includeWildcards,
    };

    setBusy(true);
    try {
      if (schedule) {
        await api.schedules.update(schedule.id, {
          name: name.trim(),
          cadence,
          hour_utc: Number(hour),
          // Cleared for non-weekly cadences, matching ScheduleUpdate: leaving a
          // stale day behind would make a later switch back to weekly silently
          // inherit one the user never chose.
          weekday: cadence === "weekly" ? Number(weekday) : null,
          config,
        });
        toast(`${name.trim()} updated`, "success");
      } else {
        await api.schedules.create({
          name: name.trim(),
          target: target.trim(),
          cadence,
          hour_utc: Number(hour),
          weekday: cadence === "weekly" ? Number(weekday) : null,
          config,
        });
        toast(`${name.trim()} scheduled`, "success");
      }
      onSaved();
    } catch (caught) {
      // A 403 here is the scope check — the target is not in the verified list,
      // or was revoked. Its message names the domain, so it is passed through.
      setError(
        caught instanceof ApiError
          ? (caught.fieldErrors.name ??
              caught.fieldErrors.target ??
              caught.fieldErrors.weekday ??
              caught.message)
          : "Could not save that schedule.",
      );
    } finally {
      setBusy(false);
    }
  }

  const valid = name.trim().length > 0 && (editing || target.trim().length >= 3);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={editing ? "Edit schedule" : "New schedule"}
      description={
        editing
          ? "Changes take effect at the next run. The time is recomputed from now, so an edited schedule does not fire once at its old time first."
          : "Saving does not start a scan. The first run happens at the next time this cadence matches."
      }
      size="lg"
      dismissible={!busy}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!valid}>
            {editing ? "Save changes" : "Create schedule"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error ? (
          <p
            role="alert"
            className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
          >
            {error}
          </p>
        ) : null}

        <Input
          label="Name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Nightly baseline"
          hint="What this schedule is for, so a list of them stays readable."
          required
        />

        {schedule ? (
          <div className="flex flex-col gap-1.5">
            <span className="text-xs font-medium text-text">Target</span>
            <div className="flex h-9 items-center rounded border border-border bg-surface px-2.5">
              <Mono muted>{schedule.target}</Mono>
            </div>
            <p className="text-xs leading-snug text-muted">
              The target cannot be changed — repointing a recurring scan would carry its
              authorisation to a host that was never checked. Delete this schedule and create a new
              one instead.
            </p>
          </div>
        ) : (
          <Input
            label="Target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="example.com"
            hint="Must be a domain this organisation has verified. Every subdomain beneath it is in scope."
            mono
            required
            autoCapitalize="none"
            spellCheck={false}
            inputMode="url"
          />
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Select
            label="Cadence"
            value={cadence}
            options={CADENCE_OPTIONS}
            onValueChange={setCadence}
          />
          {cadence === "hourly" ? (
            // Hour and weekday are meaningless for an hourly schedule, so they
            // are replaced by the thing that actually determines when it fires.
            <div className="flex flex-col gap-1.5 sm:col-span-2">
              <span className="text-xs font-medium text-text">Schedule</span>
              <div className="flex h-9 items-center rounded border border-border bg-surface px-2.5 text-sm text-muted">
                On the hour, every hour
              </div>
            </div>
          ) : (
            <>
              <Select
                label="Time"
                value={hour}
                options={HOUR_OPTIONS}
                onValueChange={setHour}
                hint="UTC, not your local time."
              />
              {cadence === "weekly" ? (
                <Select
                  label="Day"
                  value={weekday}
                  options={WEEKDAY_OPTIONS}
                  onValueChange={setWeekday}
                />
              ) : null}
            </>
          )}
        </div>

        <div className="border-t border-border pt-4">
          <p className="text-xs font-medium text-text">Scan profile</p>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            What every run of this schedule does. It is worth setting deliberately — a recurring
            scan runs unattended, so a profile that is heavier than you intended keeps costing
            until somebody notices.
          </p>

          <div className="mt-3 flex flex-col gap-3">
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
                      checked ? [...previous, module] : previous.filter((entry) => entry !== module),
                    )
                  }
                  label={meta.label}
                  description={
                    disabled
                      ? `${meta.description} — sends traffic, so passive mode skips it`
                      : meta.description
                  }
                />
              );
            })}
          </div>

          {portScanSelected ? (
            <div className="mt-3">
              <Select
                label="Port profile"
                value={portProfile}
                options={PROFILE_OPTIONS}
                onValueChange={setPortProfile}
                hint={
                  portProfile === "full"
                    ? "All 65535 ports, on this cadence, forever. Expect it to be slow and loud."
                    : undefined
                }
              />
              {portProfile === "custom" ? (
                <Input
                  label="Ports"
                  value={customPorts}
                  onChange={(event) => setCustomPorts(event.target.value)}
                  placeholder="80, 443, 8080"
                  hint="Comma or space separated."
                  mono
                  wrapperClassName="mt-3"
                />
              ) : null}
            </div>
          ) : null}

          <div className="mt-3 flex flex-col gap-3">
            <Input
              label="Subdomain cap"
              value={maxSubdomains}
              onChange={(event) => setMaxSubdomains(event.target.value.replace(/\D/g, "").slice(0, 5))}
              mono
              inputMode="numeric"
              hint="Stops enumeration running away on a large estate, on every run."
              wrapperClassName="max-w-[200px]"
            />
            <div className="flex flex-col gap-2.5">
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
          </div>
        </div>
      </div>
    </Modal>
  );
}
