"use client";

/**
 * Settings: organisation, team, appearance, account.
 *
 * Every section here is bounded by what routes/auth.py actually exposes. The
 * organisation record is read-only because there is no PATCH for it, roles
 * cannot be edited after invite for the same reason, and the API-keys section
 * says so plainly rather than shipping a generator that posts nowhere.
 */

import { useCallback, useState } from "react";

import { PlusIcon, RefreshIcon, TrashIcon } from "@/components/app/icons";
import { DomainsPanel } from "@/components/app/DomainsPanel";
import { Chip } from "@/components/ui/Badge";
import { Button, IconButton } from "@/components/ui/Button";
import { DetailRow, PageHeader, Panel } from "@/components/ui/Card";
import { EmptyState, ErrorState, NoMembersArt } from "@/components/ui/EmptyState";
import { Input, Select } from "@/components/ui/Input";
import { ConfirmModal, Modal } from "@/components/ui/Modal";
import { Mono } from "@/components/ui/Mono";
import { useAuth } from "@/components/providers/AuthProvider";
import { useTheme } from "@/components/providers/ThemeProvider";
import type { ThemePreference } from "@/components/providers/ThemeProvider";
import { useToast } from "@/components/providers/ToastProvider";
import { SkeletonList } from "@/components/ui/Skeleton";
import { TBody, TD, TH, THead, TR, TableWrap } from "@/components/ui/Table";
import { ApiError, api } from "@/lib/api";
import { cn, formatDateTime, formatRelative, pluralise, titleCase } from "@/lib/format";
import { useQuery } from "@/lib/hooks";
import type { User, UserRole } from "@/lib/types";
import { USER_ROLES } from "@/lib/types";

/** Mirrors schemas/auth.py::_PASSWORD_MIN. */
const PASSWORD_MIN = 12;

const THEME_OPTIONS: { value: ThemePreference; label: string }[] = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const ROLE_DESCRIPTION: Record<UserRole, string> = {
  owner: "Full control, including billing and other owners.",
  admin: "Manages the team and every scan.",
  analyst: "Runs scans and triages findings.",
  viewer: "Read-only access to assets and findings.",
};

export default function SettingsPage() {
  const { user, organisation } = useAuth();

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Settings"
        description="Your organisation, your team, and how this console behaves."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Organisation" subtitle="Scope and identity for every scan you run.">
          {!organisation ? (
            <SkeletonList rows={3} />
          ) : (
            <dl className="divide-y divide-border">
              <DetailRow label="Name">{organisation.name}</DetailRow>
              <DetailRow label="Primary domain">
                <Mono>{organisation.domain}</Mono>
              </DetailRow>
              <DetailRow label="Verified domains">
                {organisation.verified_domains.length === 0 ? (
                  <span className="text-muted">None</span>
                ) : (
                  <span className="flex flex-wrap justify-end gap-1">
                    {organisation.verified_domains.map((domain) => (
                      <Chip key={domain}>
                        <Mono>{domain}</Mono>
                      </Chip>
                    ))}
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Created">
                <span title={formatDateTime(organisation.created_at)}>
                  {formatDateTime(organisation.created_at)}
                </span>
              </DetailRow>
            </dl>
          )}
          {/*
            Scope is a safety control, not a preference: it is what stops a scan
            being pointed at a host the org has no authorisation to touch. It is
            self-service — the workflow lives in the Scanning scope panel below —
            but the gate is a DNS record, not a form field, so this says what the
            list on screen means and where it is changed.
          */}
          <p className="mt-3 border-t border-border pt-3 text-xs leading-relaxed text-muted">
            Scans are refused against hosts outside these domains, and every subdomain beneath a
            verified domain is in scope too. The list is managed under{" "}
            <span className="font-medium text-text">Scanning scope</span> below, where a domain is
            granted only after you prove ownership by publishing a DNS record.
          </p>
        </Panel>

        <Panel title="Account" subtitle="You, on this organisation.">
          {!user ? (
            <SkeletonList rows={3} />
          ) : (
            <>
              <dl className="divide-y divide-border">
                <DetailRow label="Name">{user.full_name ?? "—"}</DetailRow>
                <DetailRow label="Email">
                  <Mono>{user.email}</Mono>
                </DetailRow>
                <DetailRow label="Role">
                  <span className="flex flex-col items-end gap-0.5">
                    <RoleChip role={user.role} />
                    <span className="text-xs text-muted">{ROLE_DESCRIPTION[user.role]}</span>
                  </span>
                </DetailRow>
                <DetailRow label="Last sign-in">
                  <span title={formatDateTime(user.last_login_at)}>
                    {formatRelative(user.last_login_at)}
                  </span>
                </DetailRow>
              </dl>
              <div className="mt-3 border-t border-border pt-3">
                <PasswordSection />
              </div>
            </>
          )}
        </Panel>

        <Panel title="Appearance" subtitle="Stored in this browser only.">
          <ThemeSection />
        </Panel>

        <SlackPanel />

        <ApiKeysPanel />
      </div>

      {/*
        Full width, outside the two-column grid: the DNS records a claim has to
        show are long monospace strings, and a half-width column breaks them
        across three lines each.
      */}
      <DomainsPanel />

      <TeamPanel />
    </div>
  );
}

/**
 * Slack alerting.
 *
 * Two things shape this section. The API never returns the stored URL — it is a
 * bearer credential for the customer's channel — so there is no "edit" state to
 * populate: you either see a redacted hint or you paste a new URL. And a webhook
 * revoked inside Slack still looks configured here, which is why the test button
 * exists: the alternative way to discover that is missing a real critical alert.
 */
function SlackPanel() {
  const { organisation, refreshUser, hasRole } = useAuth();
  const { toast } = useToast();

  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [removing, setRemoving] = useState(false);

  // Admin+ to match the backend gate. A viewer being able to redirect security
  // alerts to a channel they control is a plausible way to hide an intrusion.
  const canEdit = hasRole("admin");
  const configured = organisation?.slack_webhook_configured ?? false;

  const save = useCallback(async () => {
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Paste the webhook URL Slack gave you.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await api.auth.setSlackWebhook(trimmed);
      await refreshUser();
      setUrl("");
      toast("Slack connected — critical findings will be posted to that channel", "success");
    } catch (err) {
      const message =
        err instanceof ApiError
          ? (err.fieldErrors.webhook_url ?? err.message)
          : "Could not save the webhook.";
      setError(message);
    } finally {
      setSaving(false);
    }
  }, [url, refreshUser, toast]);

  const test = useCallback(async () => {
    setTesting(true);
    try {
      await api.auth.testSlackWebhook();
      toast("Test message sent — check the channel", "success");
    } catch (err) {
      // The reason matters: a revoked webhook and a deleted channel need
      // different fixes, and both look identical from here otherwise.
      toast(err instanceof ApiError ? err.message : "The webhook could not be reached.", "error");
    } finally {
      setTesting(false);
    }
  }, [toast]);

  const remove = useCallback(async () => {
    setRemoving(true);
    try {
      await api.auth.setSlackWebhook(null);
      await refreshUser();
      setConfirmRemove(false);
      toast("Slack disconnected — critical findings will no longer be posted", "success");
    } catch (err) {
      toast(err instanceof ApiError ? err.message : "Could not disconnect Slack.", "error");
    } finally {
      setRemoving(false);
    }
  }, [refreshUser, toast]);

  return (
    <Panel title="Slack alerts" subtitle="Where critical findings get announced.">
      {!organisation ? (
        <SkeletonList rows={2} />
      ) : (
        <>
          <dl className="divide-y divide-border">
            <DetailRow label="Status">
              {configured ? (
                <Chip className="border-ok-fg/25 bg-ok-bg text-ok-fg">Connected</Chip>
              ) : (
                <span className="text-muted">Not configured</span>
              )}
            </DetailRow>
            {configured && organisation.slack_webhook_hint ? (
              <DetailRow label="Webhook">
                {/*
                  A redacted hint, not the URL. The API deliberately never sends
                  the secret back, so there is nothing here to copy or leak —
                  this is only enough of the path to recognise which integration
                  it is.
                */}
                <Mono className="text-2xs">{organisation.slack_webhook_hint}</Mono>
              </DetailRow>
            ) : null}
          </dl>

          {canEdit ? (
            <div className="mt-3 flex flex-col gap-2 border-t border-border pt-3">
              <Input
                label={configured ? "Replace webhook URL" : "Webhook URL"}
                mono
                type="url"
                inputMode="url"
                autoComplete="off"
                placeholder="https://hooks.slack.com/services/T00/B00/xxxx"
                value={url}
                error={error ?? undefined}
                hint="Slack → Apps → Incoming Webhooks → Add to Slack. Only hooks.slack.com URLs are accepted."
                onChange={(event) => {
                  setUrl(event.target.value);
                  setError(null);
                }}
              />
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="primary" size="sm" onClick={() => void save()} busy={saving}>
                  {configured ? "Replace" : "Connect"}
                </Button>
                {configured ? (
                  <>
                    <Button size="sm" onClick={() => void test()} busy={testing}>
                      Send test
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setConfirmRemove(true)}
                      disabled={removing}
                    >
                      Disconnect
                    </Button>
                  </>
                ) : null}
              </div>
            </div>
          ) : (
            <p className="mt-3 border-t border-border pt-3 text-xs leading-relaxed text-muted">
              The webhook URL is a credential for a channel the whole team reads, so only admins and
              owners can change it.
            </p>
          )}

          <p className="mt-3 text-xs leading-relaxed text-muted">
            A message is posted when a scan raises a critical finding, with the title, affected host,
            CVE ID and CVSS score. Findings below critical are not announced.
          </p>
        </>
      )}

      <ConfirmModal
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        onConfirm={remove}
        title="Disconnect Slack?"
        description="Critical findings will stop being announced. Nothing else changes, and you can reconnect with a new webhook URL at any time."
        confirmLabel="Disconnect"
        busy={removing}
      />
    </Panel>
  );
}

function RoleChip({ role }: { role: UserRole }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded border px-1.5 text-2xs font-medium",
        // Owner is the only role with an irreversible blast radius, so it is the
        // only one that gets the accent. The rest stay neutral.
        role === "owner"
          ? "border-accent-subtle bg-accent-subtle text-accent"
          : "border-border bg-surface text-muted",
      )}
    >
      {titleCase(role)}
    </span>
  );
}

function ThemeSection() {
  const { preference, resolved, setPreference } = useTheme();

  return (
    <div className="flex flex-col gap-3">
      <Select
        label="Theme"
        value={preference}
        options={THEME_OPTIONS}
        onValueChange={setPreference}
        hint={
          preference === "system"
            ? `Following your system setting — currently ${resolved}.`
            : undefined
        }
        wrapperClassName="max-w-[240px]"
      />
      <div className="flex items-center gap-2 text-xs text-muted">
        <span className="inline-block h-4 w-4 rounded border border-border bg-bg" aria-hidden="true" />
        <span className="inline-block h-4 w-4 rounded border border-border bg-surface" aria-hidden="true" />
        <span className="inline-block h-4 w-4 rounded border border-border bg-accent" aria-hidden="true" />
        <span>Background, surface, accent.</span>
      </div>
    </div>
  );
}

/**
 * API keys.
 *
 * The backend has no key-issuing endpoint — nothing in routes/ mints, lists or
 * revokes one. Rendering a generator here would produce a button that posts to
 * a 404, so this states the position instead. Bearer tokens from /auth/login
 * are the supported programmatic path today.
 */
function ApiKeysPanel() {
  return (
    <Panel title="API keys" subtitle="For scripting against SurfaceWatch.">
      <div className="rounded border border-dashed border-border bg-surface px-3 py-3">
        <p className="text-sm text-text">Not available yet</p>
        <p className="mt-1 text-xs leading-relaxed text-muted">
          This deployment has no key-issuing endpoint, so there is nothing to generate or revoke
          here. Until one exists, authenticate scripts with a bearer token from{" "}
          <Mono className="text-2xs">POST /api/auth/login</Mono> and rotate it with{" "}
          <Mono className="text-2xs">POST /api/auth/refresh</Mono>.
        </p>
      </div>
    </Panel>
  );
}

/**
 * Password change.
 *
 * The backend bumps `token_version` on success, which invalidates every issued
 * token — including the one this browser is holding. So a success here has to
 * sign the user out rather than leave them on a page whose next request will
 * 401.
 */
function PasswordSection() {
  const { toast } = useToast();
  const { logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setCurrent("");
    setNext("");
    setConfirm("");
    setError(null);
  }

  const mismatch = confirm.length > 0 && next !== confirm;
  const valid = current.length > 0 && next.length >= PASSWORD_MIN && next === confirm;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.auth.changePassword(current, next);
      toast("Password updated. Sign in again with your new password.", "success");
      reset();
      setOpen(false);
      logout();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not change your password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm text-text">Password</p>
          <p className="text-xs text-muted">
            Changing it signs out every other session on this account.
          </p>
        </div>
        <Button onClick={() => setOpen(true)}>Change</Button>
      </div>

      <Modal
        open={open}
        onClose={() => {
          reset();
          setOpen(false);
        }}
        title="Change your password"
        description="You will be signed out and asked to sign in again."
        footer={
          <>
            <Button
              onClick={() => {
                reset();
                setOpen(false);
              }}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!valid}>
              Change password
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          {error ? (
            <p
              role="alert"
              className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
            >
              {error}
            </p>
          ) : null}
          <Input
            label="Current password"
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            autoComplete="current-password"
            required
          />
          <Input
            label="New password"
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            autoComplete="new-password"
            hint={`At least ${PASSWORD_MIN} characters, with a letter and a digit.`}
            required
          />
          <Input
            label="Confirm new password"
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            autoComplete="new-password"
            error={mismatch ? "These do not match." : undefined}
            required
          />
        </div>
      </Modal>
    </>
  );
}

/**
 * Team.
 *
 * Invite and deactivate only — there is no role-update endpoint, so a member's
 * role is fixed at invite time. Removal is a soft deactivate on the backend
 * (is_active false, token_version bumped), and the copy says so rather than
 * implying the record is deleted.
 */
function TeamPanel() {
  const { user, hasRole } = useAuth();
  const { toast } = useToast();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [pendingRemove, setPendingRemove] = useState<User | null>(null);
  const [removing, setRemoving] = useState(false);

  const members = useQuery<User[]>(
    useCallback((signal) => api.auth.users(signal), []),
    [],
  );

  const canManage = hasRole("admin");
  const items = members.data ?? [];
  const active = items.filter((member) => member.is_active).length;

  async function confirmRemove() {
    if (!pendingRemove) return;
    setRemoving(true);
    try {
      await api.auth.removeUser(pendingRemove.id);
      toast(`${pendingRemove.email} deactivated`, "success");
      setPendingRemove(null);
      members.reload();
    } catch (caught) {
      toast(
        caught instanceof ApiError ? caught.message : "Could not deactivate that member",
        "error",
      );
    } finally {
      setRemoving(false);
    }
  }

  return (
    <Panel
      title="Team"
      subtitle={
        members.loading
          ? undefined
          : `${active} active ${pluralise(active, "member")}${items.length > active ? ` · ${items.length - active} deactivated` : ""}`
      }
      action={
        <div className="flex items-center gap-1">
          <IconButton aria-label="Refresh team" onClick={members.reload} disabled={members.refreshing}>
            <RefreshIcon />
          </IconButton>
          {canManage ? (
            <Button variant="primary" size="sm" onClick={() => setInviteOpen(true)}>
              <PlusIcon />
              Add member
            </Button>
          ) : null}
        </div>
      }
      flush
    >
      {members.loading ? (
        <div className="p-4">
          <SkeletonList rows={3} />
        </div>
      ) : members.error ? (
        <ErrorState message={members.error.message} onRetry={members.reload} />
      ) : items.length === 0 ? (
        <EmptyState
          illustration={<NoMembersArt />}
          title="No team members"
          description="Add the people who need access to this organisation's attack surface."
          action={
            canManage ? (
              <Button variant="primary" onClick={() => setInviteOpen(true)}>
                Add member
              </Button>
            ) : undefined
          }
        />
      ) : (
        <TableWrap>
          <THead>
            <TR>
              <TH>Member</TH>
              <TH width="110px">Role</TH>
              <TH width="110px">State</TH>
              <TH align="right" width="140px">
                Last sign-in
              </TH>
              {canManage ? (
                <TH width="48px">
                  <span className="sr-only">Actions</span>
                </TH>
              ) : null}
            </TR>
          </THead>
          <TBody>
            {items.map((member) => (
              <TR key={member.id}>
                <TD>
                  <span className="flex flex-col gap-0.5">
                    <span className="text-sm text-text">
                      {member.full_name ?? "—"}
                      {member.id === user?.id ? (
                        <span className="ml-1.5 text-xs text-muted">(you)</span>
                      ) : null}
                    </span>
                    <Mono muted className="text-2xs">
                      {member.email}
                    </Mono>
                  </span>
                </TD>
                <TD>
                  <RoleChip role={member.role} />
                </TD>
                <TD>
                  {member.is_active ? (
                    <span className="text-sm text-text">Active</span>
                  ) : (
                    <span className="text-sm text-muted">Deactivated</span>
                  )}
                </TD>
                <TD align="right">
                  <span
                    className="whitespace-nowrap text-xs text-muted"
                    title={formatDateTime(member.last_login_at)}
                  >
                    {member.last_login_at ? formatRelative(member.last_login_at) : "Never"}
                  </span>
                </TD>
                {canManage ? (
                  <TD>
                    {/*
                      The backend rejects deactivating yourself with a 400, and
                      an already-deactivated member has nothing to deactivate.
                      Both are hidden rather than shown failing.
                    */}
                    {member.id !== user?.id && member.is_active ? (
                      <IconButton
                        aria-label={`Deactivate ${member.email}`}
                        size="sm"
                        onClick={() => setPendingRemove(member)}
                      >
                        <TrashIcon />
                      </IconButton>
                    ) : null}
                  </TD>
                ) : null}
              </TR>
            ))}
          </TBody>
        </TableWrap>
      )}

      <InviteModal
        open={inviteOpen}
        onClose={() => setInviteOpen(false)}
        onInvited={() => {
          setInviteOpen(false);
          members.reload();
        }}
      />

      <ConfirmModal
        open={pendingRemove !== null}
        onClose={() => setPendingRemove(null)}
        onConfirm={confirmRemove}
        busy={removing}
        title="Deactivate this member?"
        description={
          pendingRemove
            ? `${pendingRemove.email} will be signed out immediately and will no longer be able to sign in. Their record and past activity are kept.`
            : ""
        }
        confirmLabel="Deactivate"
      />
    </Panel>
  );
}

/**
 * Add a member.
 *
 * The endpoint takes a password rather than sending an invitation email — this
 * deployment has no mailer — so the form sets an initial password the new
 * member changes on first sign-in. The copy is explicit about that rather than
 * calling it an "invite" and leaving them waiting for a mail that never arrives.
 */
function InviteModal({
  open,
  onClose,
  onInvited,
}: {
  open: boolean;
  onClose: () => void;
  onInvited: () => void;
}) {
  const { toast } = useToast();
  const { user } = useAuth();
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("analyst");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Only an owner may mint another owner; the backend 403s otherwise.
  const roleOptions = USER_ROLES.filter((value) => value !== "owner" || user?.role === "owner").map(
    (value) => ({ value, label: titleCase(value) }),
  );

  function reset() {
    setEmail("");
    setFullName("");
    setPassword("");
    setRole("analyst");
    setError(null);
  }

  const valid = email.includes("@") && password.length >= PASSWORD_MIN;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.auth.invite({
        email: email.trim().toLowerCase(),
        password,
        role,
        full_name: fullName.trim() || null,
      });
      toast(`${email.trim().toLowerCase()} added to the team`, "success");
      reset();
      onInvited();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not add that member.");
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
      title="Add a team member"
      description="Creates the account directly. Share the initial password with them over a channel you trust."
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
          <Button variant="primary" onClick={() => void submit()} busy={busy} disabled={!valid}>
            Add member
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {error ? (
          <p
            role="alert"
            className="rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
          >
            {error}
          </p>
        ) : null}
        <Input
          label="Email"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          placeholder="analyst@example.com"
          mono
          autoCapitalize="none"
          spellCheck={false}
          required
        />
        <Input
          label="Full name"
          value={fullName}
          onChange={(event) => setFullName(event.target.value)}
          placeholder="Optional"
        />
        <Input
          label="Initial password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="new-password"
          hint={`At least ${PASSWORD_MIN} characters, with a letter and a digit. They can change it under Settings.`}
          required
        />
        <Select
          label="Role"
          value={role}
          options={roleOptions}
          onValueChange={setRole}
          hint={ROLE_DESCRIPTION[role]}
        />
        {/*
          There is no endpoint to change a role after the fact, so this is a
          one-way decision. Worth saying before the button is pressed rather
          than after.
        */}
        <p className="text-xs leading-relaxed text-muted">
          Roles cannot be changed after the account is created. To move someone between roles,
          deactivate them and add them again.
        </p>
      </div>
    </Modal>
  );
}
