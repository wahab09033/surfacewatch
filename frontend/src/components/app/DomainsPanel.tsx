"use client";

/**
 * The organisation's scanning scope: claim a domain, prove it with DNS, revoke it.
 *
 * This is a **safety control, not a preference**. Scanning authority comes only
 * from `Organisation.verified_domains`, and the only way into that list is a
 * claim here reaching VERIFIED by publishing a TXT record. With registration
 * open to the public, without this gate every account could scan any domain it
 * typed into the signup form.
 *
 * Which is why the panel does the work rather than showing a disabled input: the
 * challenge format is computed server-side (`record_name`, `record_value`, and
 * the apex fallback), so nothing here has to know that the record lives under
 * `_surfacewatch-challenge`. The user publishes what is on screen and presses
 * Verify.
 *
 * Roles: analyst+ to read (a pending claim carries its challenge token), admin+
 * to write. Both are enforced server-side; this only mirrors the gate so a
 * viewer is told why rather than shown buttons that 403.
 */

import { useCallback, useState } from "react";

import { CheckIcon, CopyIcon, PlusIcon, RefreshIcon, TrashIcon } from "@/components/app/icons";
import { useAuth } from "@/components/providers/AuthProvider";
import { useToast } from "@/components/providers/ToastProvider";
import { Chip, DomainStatusBadge } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { DetailRow, Panel } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoDataArt } from "@/components/ui/EmptyState";
import { Input } from "@/components/ui/Input";
import { ConfirmModal } from "@/components/ui/Modal";
import { Mono } from "@/components/ui/Mono";
import { SkeletonList } from "@/components/ui/Skeleton";
import { ApiError, api } from "@/lib/api";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useQuery } from "@/lib/hooks";
import type { DomainClaim, DomainClaimList } from "@/lib/types";

export function DomainsPanel() {
  const { hasRole } = useAuth();

  // Split rather than an early return inside one component: the body uses
  // hooks, and a viewer must not run them at all — the list endpoint is
  // analyst+ and would 403 on every mount.
  if (!hasRole("analyst")) {
    return (
      <Panel title="Scanning scope" subtitle="The domains this organisation is authorised to scan.">
        <p className="text-xs leading-relaxed text-muted">
          Domain claims carry their DNS challenge token, so only analysts and above can see them.
          The verified list is summarised on the Organisation panel above.
        </p>
      </Panel>
    );
  }

  return <DomainsPanelBody />;
}

function DomainsPanelBody() {
  const { hasRole, refreshUser } = useAuth();
  const { toast } = useToast();
  const canWrite = hasRole("admin");

  const claims = useQuery<DomainClaimList>(
    useCallback((signal) => api.auth.domains.list(signal), []),
    [],
  );

  const [domain, setDomain] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  /** Id of the claim currently being checked, so only its own button spins. */
  const [verifying, setVerifying] = useState<string | null>(null);
  const [pendingRemove, setPendingRemove] = useState<DomainClaim | null>(null);
  const [removing, setRemoving] = useState(false);

  const items = claims.data?.items ?? [];
  const limit = claims.data?.limit ?? null;
  const atCap = limit !== null && items.length >= limit;

  const add = useCallback(async () => {
    const value = domain.trim();
    if (!value) {
      setAddError("Enter the domain you want to scan.");
      return;
    }
    setAdding(true);
    setAddError(null);
    try {
      // Re-adding an existing domain returns the original claim and token
      // rather than erroring, so this succeeds on a retry as well as a first
      // attempt. See routes.domains.add_domain.
      const claim = await api.auth.domains.add(value);
      setDomain("");
      claims.reload();
      toast(`${claim.domain} claimed — publish the DNS record below, then verify`, "success");
    } catch (caught) {
      setAddError(
        caught instanceof ApiError
          ? (caught.fieldErrors.domain ?? caught.message)
          : "Could not add that domain.",
      );
    } finally {
      setAdding(false);
    }
  }, [domain, claims, toast]);

  const verify = useCallback(
    async (claim: DomainClaim) => {
      setVerifying(claim.id);
      try {
        const result = await api.auth.domains.verify(claim.id);
        if (result.verified) {
          // The org's granted scope just changed, and the Organisation panel
          // renders it from the cached auth context. Without this the summary
          // keeps showing the old list until the next full page load.
          await refreshUser();
          toast(`${result.verification.domain} is verified and now in scope`, "success");
        } else {
          // "no record", "wrong value" and "lookup timed out" send the user to
          // three different places, so the server's own wording is passed
          // through rather than collapsed into "verification failed".
          toast(result.detail ?? "The DNS record was not found.", "error");
        }
        claims.reload();
      } catch (caught) {
        toast(
          caught instanceof ApiError ? caught.message : "Could not run that check.",
          "error",
        );
      } finally {
        setVerifying(null);
      }
    },
    [claims, refreshUser, toast],
  );

  const remove = useCallback(async () => {
    if (!pendingRemove) return;
    setRemoving(true);
    try {
      const message = await api.auth.domains.remove(pendingRemove.id);
      setPendingRemove(null);
      await refreshUser();
      claims.reload();
      toast(message.detail, "success");
    } catch (caught) {
      toast(
        caught instanceof ApiError ? caught.message : "Could not remove that domain.",
        "error",
      );
    } finally {
      setRemoving(false);
    }
  }, [pendingRemove, claims, refreshUser, toast]);

  return (
    <Panel
      title="Scanning scope"
      subtitle="Proof of ownership, checked in DNS. A scan is refused against anything not listed here."
      action={
        <IconButton
          aria-label="Refresh domain claims"
          size="sm"
          onClick={claims.reload}
          disabled={claims.refreshing}
        >
          <RefreshIcon />
        </IconButton>
      }
    >
      {canWrite ? (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-end gap-2">
            <Input
              label="Add a domain"
              value={domain}
              onChange={(event) => {
                setDomain(event.target.value);
                setAddError(null);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !adding && !atCap) void add();
              }}
              placeholder="example.com"
              hint="Every subdomain beneath a verified domain is in scope too."
              error={addError ?? undefined}
              mono
              autoCapitalize="none"
              spellCheck={false}
              inputMode="url"
              disabled={atCap}
              wrapperClassName="min-w-[220px] flex-1"
            />
            <Button
              variant="primary"
              onClick={() => void add()}
              busy={adding}
              disabled={atCap || domain.trim().length < 3}
            >
              <PlusIcon />
              Add
            </Button>
          </div>
          {atCap ? (
            <p className="text-xs leading-relaxed text-warn-fg">
              This organisation holds {items.length} of {limit} domains, the maximum. Remove one
              before claiming another.
            </p>
          ) : null}
        </div>
      ) : (
        <p className="text-xs leading-relaxed text-muted">
          A verified domain is scanning authorisation, so claiming and revoking one is restricted to
          admins and owners. You can see the current scope below.
        </p>
      )}

      <div className="mt-4 border-t border-border pt-4">
        {claims.loading ? (
          <SkeletonList rows={2} />
        ) : claims.error ? (
          <ErrorState message={claims.error.message} onRetry={claims.reload} compact />
        ) : items.length === 0 ? (
          <EmptyState
            compact
            illustration={<NoDataArt />}
            title="No domains claimed"
            description={
              canWrite
                ? "Until a domain is verified, every scan is refused — including on the domain this organisation registered with."
                : "Nothing has been claimed yet. An admin or owner can add one above."
            }
          />
        ) : (
          <ul className="flex flex-col gap-3">
            {items.map((claim) => (
              <ClaimRow
                key={claim.id}
                claim={claim}
                canWrite={canWrite}
                verifying={verifying === claim.id}
                onVerify={() => void verify(claim)}
                onRemove={() => setPendingRemove(claim)}
              />
            ))}
          </ul>
        )}
      </div>

      {limit !== null && items.length > 0 ? (
        <p className="mt-3 border-t border-border pt-3 text-xs text-muted">
          {items.length} of {limit} domains claimed.
        </p>
      ) : null}

      <ConfirmModal
        open={pendingRemove !== null}
        onClose={() => setPendingRemove(null)}
        onConfirm={remove}
        busy={removing}
        title="Remove this domain?"
        description={
          pendingRemove
            ? `${pendingRemove.domain} will be taken out of scope immediately. Scans already running will finish, but no new scan of it can be started, and the DNS record can be deleted from your provider.`
            : ""
        }
        confirmLabel="Remove domain"
      />
    </Panel>
  );
}

/** One claim: its state, the record still to publish, and what to do next. */
function ClaimRow({
  claim,
  canWrite,
  verifying,
  onVerify,
  onRemove,
}: {
  claim: DomainClaim;
  canWrite: boolean;
  verifying: boolean;
  onVerify: () => void;
  onRemove: () => void;
}) {
  const verified = claim.status === "verified";

  return (
    <li className="rounded border border-border bg-surface px-3 py-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2">
          <Mono className="truncate text-sm">{claim.domain}</Mono>
          <DomainStatusBadge status={claim.status} />
        </span>
        {canWrite ? (
          <span className="flex shrink-0 items-center gap-1.5">
            {verified ? null : (
              <Button size="sm" onClick={onVerify} busy={verifying}>
                <RefreshIcon />
                Check DNS
              </Button>
            )}
            <IconButton
              aria-label={`Remove ${claim.domain}`}
              size="sm"
              onClick={onRemove}
            >
              <TrashIcon />
            </IconButton>
          </span>
        ) : null}
      </div>

      {verified ? (
        <p className="mt-1.5 text-xs text-muted">
          Verified {formatDateTime(claim.verified_at)}
          {claim.last_checked_at ? ` · last checked ${formatRelative(claim.last_checked_at)}` : ""}
        </p>
      ) : (
        <>
          {/*
            The apex record is offered alongside the dedicated one because
            several DNS panels make underscore-prefixed labels awkward. Both are
            accepted; publishing either one is enough, so the copy says so
            rather than implying both are required.
          */}
          <p className="mt-2 text-xs leading-relaxed text-muted">
            Publish <span className="font-medium text-text">either</span> of these TXT records at
            your DNS provider, then press Check DNS. Propagation is usually quick but can take
            longer than the TTL suggests.
          </p>
          <dl className="mt-1.5 divide-y divide-border">
            <RecordRow
              label="Record"
              name={claim.record_name}
              value={claim.record_value}
              hint="Under our own label, so the bare value is enough."
            />
            <RecordRow
              label="Or on the apex"
              name={claim.apex_record_name}
              value={claim.apex_record_value}
              hint="For providers that will not create underscore labels."
            />
          </dl>
        </>
      )}

      {claim.last_error ? (
        <p className="mt-2 border-t border-border pt-2 text-xs leading-relaxed text-sev-critical-fg">
          {claim.last_error}
        </p>
      ) : null}

      {!verified && claim.last_checked_at ? (
        <p className="mt-1.5 text-xs text-muted">
          Last checked {formatRelative(claim.last_checked_at)}
        </p>
      ) : null}
    </li>
  );
}

/**
 * One DNS record, with the value copyable.
 *
 * The token is 43 URL-safe characters that have to be pasted into a DNS panel
 * exactly. Transcribing that by hand is the single most likely way to fail a
 * check that would otherwise have passed, so the copy button is not a nicety.
 */
function RecordRow({
  label,
  name,
  value,
  hint,
}: {
  label: string;
  name: string | null;
  value: string | null;
  hint: string;
}) {
  if (!name || !value) return null;

  return (
    <div className="py-2">
      <DetailRow label={label}>
        <span className="flex flex-col items-end gap-1">
          <span className="flex items-center gap-1.5">
            <Chip>TXT</Chip>
            <Mono className="break-all text-2xs">{name}</Mono>
          </span>
          <span className="flex items-center gap-1.5">
            <Mono muted className="break-all text-2xs">
              {value}
            </Mono>
            <CopyButton value={value} />
          </span>
          <span className="text-2xs text-muted">{hint}</span>
        </span>
      </DetailRow>
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      // Not available on an insecure origin — a LAN deployment served over
      // plain http, which is a supported way to run this. The fallback keeps
      // the button doing its job there instead of failing silently.
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        legacyCopy(value);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      // Denied permission, or no clipboard at all. The value is on screen and
      // selectable, so this is not worth an error message.
    }
  }

  return (
    <IconButton
      aria-label={copied ? "Copied" : "Copy value"}
      size="sm"
      onClick={() => void copy()}
      title={copied ? "Copied" : "Copy value"}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </IconButton>
  );
}

/** execCommand fallback for non-secure origins. Deprecated, not yet removed. */
function legacyCopy(value: string): void {
  const field = document.createElement("textarea");
  field.value = value;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.opacity = "0";
  document.body.appendChild(field);
  field.select();
  document.execCommand("copy");
  field.remove();
}
