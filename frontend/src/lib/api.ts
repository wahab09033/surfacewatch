/**
 * API client.
 *
 * One place that knows about base URLs, bearer tokens and error shapes, so no
 * component ever calls fetch directly.
 */

import type {
  Asset,
  AssetQuery,
  AssetStats,
  AssetSummary,
  Dashboard,
  Finding,
  FindingQuery,
  FindingStats,
  FindingUpdate,
  GraphQuery,
  GraphResponse,
  InvitePayload,
  Message,
  Organisation,
  Paginated,
  RegisterPayload,
  Report,
  ReportRequest,
  Scan,
  ScanConfig,
  ScanLog,
  ScanStats,
  TokenPair,
  User,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

const ACCESS_KEY = "sw.access_token";
const REFRESH_KEY = "sw.refresh_token";

// --- token storage ---------------------------------------------------------

/**
 * Tokens live in localStorage. That is a deliberate, documented trade-off: it
 * exposes them to XSS in exchange for surviving a page reload without a
 * cookie-issuing session endpoint, which this API does not have (it is a pure
 * bearer-token API, also consumed by CLI tooling). The mitigation that matters
 * is not shipping an XSS, hence no `dangerouslySetInnerHTML` anywhere in this
 * app. If the backend later grows httpOnly refresh cookies, this module is the
 * only file that needs to change.
 */
export const tokens = {
  access(): string | null {
    if (typeof window === "undefined") return null;
    return window.localStorage.getItem(ACCESS_KEY);
  },
  refresh(): string | null {
    if (typeof window === "undefined") return null;
    return window.localStorage.getItem(REFRESH_KEY);
  },
  set(pair: TokenPair): void {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(ACCESS_KEY, pair.access_token);
    window.localStorage.setItem(REFRESH_KEY, pair.refresh_token);
  },
  clear(): void {
    if (typeof window === "undefined") return;
    window.localStorage.removeItem(ACCESS_KEY);
    window.localStorage.removeItem(REFRESH_KEY);
  },
};

// --- errors ----------------------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  /** Per-field messages from FastAPI's 422 validation envelope. */
  readonly fieldErrors: Record<string, string>;

  constructor(status: number, message: string, fieldErrors: Record<string, string> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.fieldErrors = fieldErrors;
  }

  get isAuth(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

interface FastApiValidationItem {
  loc?: (string | number)[];
  msg?: string;
}

/**
 * FastAPI returns `{detail: string}` for HTTPException and
 * `{detail: [{loc, msg}]}` for validation failures. Flatten both into a
 * message plus a field map the forms can render inline.
 */
async function toApiError(response: Response): Promise<ApiError> {
  let detail: unknown;
  try {
    detail = (await response.json())?.detail;
  } catch {
    detail = null;
  }

  if (typeof detail === "string") {
    return new ApiError(response.status, detail);
  }

  if (Array.isArray(detail)) {
    const fieldErrors: Record<string, string> = {};
    for (const item of detail as FastApiValidationItem[]) {
      // loc is like ["body", "password"]; the last string segment is the field.
      const path = (item.loc ?? []).filter((p): p is string => typeof p === "string");
      const field = path[path.length - 1];
      if (field && item.msg && !fieldErrors[field]) {
        // Pydantic v2 prefixes messages with "Value error, ".
        fieldErrors[field] = item.msg.replace(/^Value error,\s*/, "");
      }
    }
    const first = Object.values(fieldErrors)[0];
    return new ApiError(
      response.status,
      first ?? "The details you entered were not accepted.",
      fieldErrors,
    );
  }

  return new ApiError(
    response.status,
    response.status >= 500
      ? "The server could not complete that request."
      : `Request failed (${response.status})`,
  );
}

// --- refresh coordination --------------------------------------------------

/**
 * A single in-flight refresh shared by every caller.
 *
 * A page that mounts four widgets issues four requests at once. If the access
 * token has expired they all get a 401 together, and each would independently
 * POST /auth/refresh. The backend rotates refresh tokens, so the first call
 * invalidates the token the other three are holding — they'd fail and log the
 * user out mid-session. Collapsing them onto one promise avoids that.
 */
let refreshInFlight: Promise<boolean> | null = null;

/** Set by the auth provider so a dead session can bounce to /login. */
let onSessionExpired: (() => void) | null = null;

export function setSessionExpiredHandler(handler: (() => void) | null): void {
  onSessionExpired = handler;
}

async function refreshAccessToken(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    const refresh = tokens.refresh();
    if (!refresh) return false;
    try {
      const response = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!response.ok) return false;
      tokens.set((await response.json()) as TokenPair);
      return true;
    } catch {
      return false;
    } finally {
      // Cleared in a microtask so callers awaiting this promise all observe the
      // same result before the next 401 can start a fresh attempt.
      queueMicrotask(() => {
        refreshInFlight = null;
      });
    }
  })();

  return refreshInFlight;
}

// --- core request ----------------------------------------------------------

type Query = Record<
  string,
  string | number | boolean | undefined | null | (string | number)[]
>;

export function buildQuery(params: Query = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      // FastAPI reads repeated keys as a list: ?severity=high&severity=critical
      for (const item of value) search.append(key, String(item));
    } else {
      search.append(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Skip the bearer header — used by login/register/refresh. */
  anonymous?: boolean;
  signal?: AbortSignal;
  /** Internal: prevents a refresh loop. */
  _retried?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, anonymous = false, signal, _retried = false } = options;

  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (!anonymous) {
    const token = tokens.access();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (error) {
    // An aborted request is the caller's own doing (unmount, superseded
    // keystroke) — let it through untouched so callers can ignore it.
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "Could not reach the API. Is the backend running?");
  }

  if (response.status === 401 && !anonymous && !_retried) {
    if (await refreshAccessToken()) {
      return request<T>(path, { ...options, _retried: true });
    }
    tokens.clear();
    onSessionExpired?.();
    throw new ApiError(401, "Your session has expired. Please sign in again.");
  }

  if (!response.ok) throw await toApiError(response);

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

// --- endpoints -------------------------------------------------------------

export const api = {
  auth: {
    login(email: string, password: string) {
      return request<TokenPair>("/api/auth/login", {
        method: "POST",
        body: { email, password },
        anonymous: true,
      });
    },
    register(payload: RegisterPayload) {
      return request<TokenPair>("/api/auth/register", {
        method: "POST",
        body: payload,
        anonymous: true,
      });
    },
    me(signal?: AbortSignal) {
      return request<User>("/api/auth/me", { signal });
    },
    organisation(signal?: AbortSignal) {
      return request<Organisation>("/api/auth/organisation", { signal });
    },
    changePassword(current_password: string, new_password: string) {
      return request<Message>("/api/auth/password", {
        method: "POST",
        body: { current_password, new_password },
      });
    },
    /**
     * Revoke a refresh session server-side. Called before the client clears
     * its own copies, so a stolen token cannot be replayed after sign-out.
     * Anonymous: the access token may already be dead, and the endpoint
     * authenticates by the refresh token itself.
     */
    logout(refresh_token: string) {
      return request<Message>("/api/auth/logout", {
        method: "POST",
        body: { refresh_token },
        anonymous: true,
      });
    },
    users(signal?: AbortSignal) {
      return request<User[]>("/api/auth/users", { signal });
    },
    invite(payload: InvitePayload) {
      return request<User>("/api/auth/users", { method: "POST", body: payload });
    },
    removeUser(userId: string) {
      return request<Message>(`/api/auth/users/${userId}`, { method: "DELETE" });
    },
    /** Pass null to remove the integration. Admin+ only, server-side. */
    setSlackWebhook(webhook_url: string | null) {
      return request<Organisation>("/api/auth/organisation/slack-webhook", {
        method: "PUT",
        body: { webhook_url },
      });
    },
    testSlackWebhook() {
      return request<Message>("/api/auth/organisation/slack-webhook/test", {
        method: "POST",
      });
    },
  },

  assets: {
    list(query: AssetQuery = {}, signal?: AbortSignal) {
      return request<Paginated<AssetSummary>>(`/api/assets${buildQuery(query)}`, { signal });
    },
    get(id: string, signal?: AbortSignal) {
      return request<Asset>(`/api/assets/${id}`, { signal });
    },
    findings(id: string, signal?: AbortSignal) {
      return request<Finding[]>(`/api/assets/${id}/findings`, { signal });
    },
    stats(signal?: AbortSignal) {
      return request<AssetStats>("/api/assets/stats", { signal });
    },
    graph(query: GraphQuery = {}, signal?: AbortSignal) {
      return request<GraphResponse>(`/api/assets/graph${buildQuery(query)}`, { signal });
    },
    create(hostname: string, ip?: string | null, notes?: string | null) {
      return request<Asset>("/api/assets", {
        method: "POST",
        body: { hostname, ip: ip ?? null, notes: notes ?? null },
      });
    },
    update(id: string, patch: { ip?: string | null; status?: string; notes?: string | null }) {
      return request<Asset>(`/api/assets/${id}`, { method: "PATCH", body: patch });
    },
    remove(id: string) {
      return request<Message>(`/api/assets/${id}`, { method: "DELETE" });
    },
  },

  findings: {
    list(query: FindingQuery = {}, signal?: AbortSignal) {
      return request<Paginated<Finding>>(
        `/api/findings${buildQuery(query as Query)}`,
        { signal },
      );
    },
    get(id: string, signal?: AbortSignal) {
      return request<Finding>(`/api/findings/${id}`, { signal });
    },
    stats(signal?: AbortSignal) {
      return request<FindingStats>("/api/findings/stats", { signal });
    },
    update(id: string, patch: FindingUpdate) {
      return request<Finding>(`/api/findings/${id}`, { method: "PATCH", body: patch });
    },
    remove(id: string) {
      return request<Message>(`/api/findings/${id}`, { method: "DELETE" });
    },
  },

  scans: {
    list(
      query: { status?: string; target?: string; limit?: number; offset?: number } = {},
      signal?: AbortSignal,
    ) {
      return request<Paginated<Scan>>(`/api/scans${buildQuery(query)}`, { signal });
    },
    get(id: string, signal?: AbortSignal) {
      return request<Scan>(`/api/scans/${id}`, { signal });
    },
    /** Persisted lines, ordered oldest first. No level filter server-side. */
    logs(
      id: string,
      query: { limit?: number; offset?: number } = {},
      signal?: AbortSignal,
    ) {
      return request<Paginated<ScanLog>>(`/api/scans/${id}/logs${buildQuery(query)}`, { signal });
    },
    stats(signal?: AbortSignal) {
      return request<ScanStats>("/api/scans/stats", { signal });
    },
    create(target: string, config: Partial<ScanConfig>) {
      return request<Scan>("/api/scans", { method: "POST", body: { target, config } });
    },
    cancel(id: string) {
      return request<Scan>(`/api/scans/${id}/cancel`, { method: "POST" });
    },
    remove(id: string) {
      return request<Message>(`/api/scans/${id}`, { method: "DELETE" });
    },
  },

  reports: {
    dashboard(signal?: AbortSignal) {
      return request<Dashboard>("/api/reports/dashboard", { signal });
    },
    list(query: { limit?: number; offset?: number } = {}, signal?: AbortSignal) {
      return request<Paginated<Report>>(`/api/reports${buildQuery(query)}`, { signal });
    },
    get(id: string, signal?: AbortSignal) {
      return request<Report>(`/api/reports/${id}`, { signal });
    },
    create(payload: ReportRequest) {
      return request<Report>("/api/reports", { method: "POST", body: payload });
    },
    remove(id: string) {
      return request<Message>(`/api/reports/${id}`, { method: "DELETE" });
    },
    /**
     * Downloads via fetch rather than a plain link: the endpoint needs an
     * Authorization header, which an <a href> cannot send.
     */
    async download(report: Report): Promise<void> {
      const response = await fetch(`${API_BASE}/api/reports/${report.id}/download`, {
        headers: { Authorization: `Bearer ${tokens.access() ?? ""}` },
      });
      if (!response.ok) throw await toApiError(response);

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      const stem = (report.title ?? "surfacewatch-report").replace(/[^\w.-]+/g, "-");
      anchor.download = `${stem}.${report.format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      // Revoked on the next tick; revoking synchronously can cancel the
      // download in Safari before it starts.
      setTimeout(() => URL.revokeObjectURL(url), 1_000);
    },
  },
};

/** WebSocket URL for a scan's live log stream. */
export function scanSocketUrl(scanId: string, replay = 200): string {
  const base = API_BASE.replace(/^http/, "ws");
  const token = tokens.access() ?? "";
  // The token goes in the query string because the browser WebSocket API has no
  // way to set headers. The backend accepts it there for exactly this reason.
  return `${base}/ws/scan/${scanId}?token=${encodeURIComponent(token)}&replay=${replay}`;
}
