/**
 * Wire types for the SurfaceWatch API.
 *
 * These mirror backend/schemas/*.py field for field. When the API changes,
 * change these — do not paper over a mismatch in a component, or the drift
 * turns into a runtime `undefined` somewhere far from the cause.
 */

// --- enums (backend/models/base.py) ----------------------------------------

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = [
  "open",
  "triaged",
  "confirmed",
  "remediated",
  "false_positive",
  "accepted_risk",
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const ASSET_STATUSES = [
  "active",
  "inactive",
  "new",
  "changed",
  "decommissioned",
] as const;
export type AssetStatus = (typeof ASSET_STATUSES)[number];

export const SCAN_STATUSES = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const USER_ROLES = ["owner", "admin", "analyst", "viewer"] as const;
export type UserRole = (typeof USER_ROLES)[number];

export type LogLevel = "debug" | "info" | "warning" | "error";

/** Terminal scan states — nothing further will be published for these. */
export const TERMINAL_SCAN_STATUSES: readonly ScanStatus[] = [
  "completed",
  "failed",
  "cancelled",
];

export function isTerminalScanStatus(status: ScanStatus): boolean {
  return TERMINAL_SCAN_STATUSES.includes(status);
}

// --- scan modules (backend/schemas/scan.py) --------------------------------

export const SCAN_MODULES = [
  "subdomain_enum",
  "port_scanner",
  "fingerprinter",
  "cve_correlator",
  "change_detector",
] as const;
export type ScanModule = (typeof SCAN_MODULES)[number];

export const PORT_PROFILES = ["top-100", "top-1000", "web", "full", "custom"] as const;
export type PortProfile = (typeof PORT_PROFILES)[number];

/** Presentation metadata for the module toggles on /scan. */
export const MODULE_META: Record<
  ScanModule,
  { label: string; description: string; passiveSafe: boolean }
> = {
  subdomain_enum: {
    label: "Subdomain enumeration",
    description: "Certificate transparency logs and DNS resolution",
    passiveSafe: true,
  },
  port_scanner: {
    label: "Port scanner",
    description: "TCP connect scan with service banner capture",
    passiveSafe: false,
  },
  fingerprinter: {
    label: "Fingerprinter",
    description: "HTTP technology and version detection",
    passiveSafe: false,
  },
  cve_correlator: {
    label: "CVE correlation",
    description: "Match detected versions against the NVD",
    passiveSafe: true,
  },
  change_detector: {
    label: "Change detection",
    description: "Diff the estate against the previous scan",
    passiveSafe: true,
  },
};

// --- envelopes -------------------------------------------------------------

export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Message {
  detail: string;
}

// --- auth ------------------------------------------------------------------

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface User {
  id: string;
  org_id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Organisation {
  id: string;
  name: string;
  domain: string;
  verified_domains: string[];
  created_at: string;

  // The webhook URL itself is deliberately not part of this type, because the
  // API deliberately never sends it — it is a credential for the customer's
  // Slack channel. These are the two derived fields the settings UI needs:
  // whether it is on, and enough of the path to tell which integration it is.
  slack_webhook_configured: boolean;
  slack_webhook_hint: string | null;
}

export interface RegisterPayload {
  org_name: string;
  domain: string;
  email: string;
  password: string;
  full_name?: string | null;
}

export interface InvitePayload {
  email: string;
  password: string;
  role: UserRole;
  full_name?: string | null;
}

// --- assets ----------------------------------------------------------------

export interface PortEntry {
  port: number;
  protocol?: string;
  state?: string;
  service?: string | null;
  banner?: string | null;
}

export interface TechEntry {
  name: string;
  version?: string | null;
  categories?: string[];
  confidence?: number;
  cpe?: string | null;
}

export interface Asset {
  id: string;
  org_id: string;
  hostname: string;
  ip: string | null;
  /** JSONB — shape is PortEntry but the API types it loosely. */
  ports: PortEntry[];
  tech_stack: TechEntry[];
  risk_score: number;
  last_scanned: string | null;
  status: AssetStatus;
  discovery_source: string | null;
  first_seen: string | null;
  notes: string | null;
  created_at: string;
}

export interface AssetSummary {
  id: string;
  hostname: string;
  ip: string | null;
  risk_score: number;
  status: AssetStatus;
  last_scanned: string | null;
  open_port_count: number;
  finding_count: number;
}

export interface AssetStats {
  total: number;
  by_status: Record<string, number>;
  highest_risk: AssetSummary[];
  newly_discovered_7d: number;
}

export type AssetSort = "risk" | "hostname" | "last_scanned" | "created";

// --- blast radius graph ----------------------------------------------------

export type GraphNodeKind = "domain" | "subdomain" | "ip" | "port";

/**
 * One node of the blast radius map, as the API sends it.
 *
 * `risk_score` is 0-100 on every kind including the structural ones, so the
 * client has a single colour path through `riskBand()` — the same function the
 * asset table uses. A node coloured differently from the same asset's row would
 * be worse than either colour being slightly off.
 */
export interface GraphNode {
  id: string;
  label: string;
  kind: GraphNodeKind;
  risk_score: number;
  /** Set only on `subdomain` nodes — the id to open the AssetDrawer with. */
  asset_id: string | null;
  finding_count: number;
  open_port_count: number;
  /** On an `ip` node: how many subdomains resolve here. */
  shared_by: number;
  service: string | null;
}

export interface GraphLink {
  source: string;
  target: string;
}

export interface GraphResponse {
  nodes: GraphNode[];
  links: GraphLink[];
  total_assets: number;
  truncated: boolean;
  truncated_reason: string | null;
}

export type GraphQuery = {
  include_ports?: boolean;
  max_assets?: number;
};

/**
 * Declared as a type alias rather than an interface on purpose: TypeScript
 * gives object type aliases an implicit index signature, so they satisfy the
 * api client's `Query` record. An interface does not, and every call to
 * buildQuery would need a cast.
 */
export type AssetQuery = {
  status?: AssetStatus;
  hostname?: string;
  min_risk?: number;
  port?: number;
  technology?: string;
  sort?: AssetSort;
  limit?: number;
  offset?: number;
};

// --- findings --------------------------------------------------------------

export interface Finding {
  id: string;
  org_id: string;
  asset_id: string | null;
  scan_id: string | null;
  title: string;
  cve_id: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity;
  description: string | null;
  remediation: string | null;
  status: FindingStatus;
  source: string | null;
  evidence: Record<string, unknown>;
  references: string[];
  first_seen: string | null;
  last_seen: string | null;
  resolved_at: string | null;
  created_at: string;
  asset_hostname: string | null;
}

export interface FindingStats {
  total: number;
  open: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  top_cves: { cve_id: string; count: number; [k: string]: unknown }[];
  mean_cvss: number | null;
}

export type FindingSort = "severity" | "cvss" | "created" | "last_seen";

export interface FindingQuery {
  severity?: Severity[];
  status?: FindingStatus[];
  asset_id?: string;
  scan_id?: string;
  cve_id?: string;
  search?: string;
  open_only?: boolean;
  sort?: FindingSort;
  limit?: number;
  offset?: number;
}

export interface FindingUpdate {
  status?: FindingStatus;
  severity?: Severity;
  remediation?: string;
  notes?: string;
}

// --- remediation provenance ------------------------------------------------

/**
 * Who wrote the text in `finding.remediation`.
 *
 * `claude` and `claude-cached` are written by backend/workers/ai_remediation.py
 * (the cached variant is the same model output, reused for an identical
 * CVE-plus-stack combination rather than paid for twice). `analyst` is stamped
 * by the PATCH route when a human edits the text. `template` is the built-in
 * advice — the worker does not record it, so it appears only if a finding was
 * written with it explicitly.
 */
export const REMEDIATION_SOURCES = ["claude", "claude-cached", "analyst", "template"] as const;
export type RemediationSource = (typeof REMEDIATION_SOURCES)[number];

export type RemediationConfidence = "high" | "medium" | "low";

export interface RemediationProvenance {
  source: RemediationSource;
  /** Only set for AI text, and only until a human edits it. */
  model: string | null;
  confidence: RemediationConfidence | null;
  /** What the model said it could not determine from the facts it was given. */
  uncertain: string[];
}

/** True for the two sources that mean a model wrote the current text. */
export function isAiRemediation(source: RemediationSource): boolean {
  return source === "claude" || source === "claude-cached";
}

/**
 * Read the `remediation_*` keys out of a finding's evidence blob.
 *
 * `evidence` is `Record<string, unknown>` because the backend column is
 * free-form JSONB — several writers put unrelated things in there. Everything
 * is therefore checked at runtime rather than cast: an unrecognised source is
 * dropped instead of rendered, because a badge claiming "AI" over text of
 * unknown origin is worse than no badge.
 */
export function readRemediationProvenance(
  evidence: Record<string, unknown> | null | undefined,
): RemediationProvenance | null {
  const raw = evidence?.remediation_source;
  if (typeof raw !== "string") return null;
  const source = REMEDIATION_SOURCES.find((candidate) => candidate === raw);
  if (!source) return null;

  const model = evidence?.remediation_model;
  const confidence = evidence?.remediation_confidence;
  const uncertain = evidence?.remediation_uncertain;

  return {
    source,
    model: typeof model === "string" && model ? model : null,
    confidence:
      confidence === "high" || confidence === "medium" || confidence === "low"
        ? confidence
        : null,
    uncertain: Array.isArray(uncertain)
      ? uncertain.filter((item): item is string => typeof item === "string" && item.length > 0)
      : [],
  };
}

// --- scans -----------------------------------------------------------------

export interface ScanConfig {
  modules: ScanModule[];
  port_profile: PortProfile;
  ports: number[];
  max_subdomains: number;
  passive_only: boolean;
  connect_timeout: number;
  rate_limit: number;
  include_wildcards: boolean;
}

export interface Scan {
  id: string;
  org_id: string;
  target: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  config: Partial<ScanConfig> & Record<string, unknown>;
  current_stage: string | null;
  progress: number;
  assets_discovered: number;
  findings_count: number;
  error: string | null;
  created_at: string;
  duration_seconds: number | null;
}

export interface ScanLog {
  id: string;
  scan_id: string;
  timestamp: string;
  message: string;
  level: LogLevel;
  stage: string | null;
}

/** GET /api/scans/stats. Returns a bare dict, not a Pydantic model. */
export interface ScanStats {
  total: number;
  by_status: Record<string, number>;
  /** queued + running. */
  active: number;
  last_7d: number;
}

// --- reports ---------------------------------------------------------------

export type ReportFormat = "pdf" | "json" | "csv";

export interface Report {
  id: string;
  org_id: string;
  title: string | null;
  format: string;
  status: string;
  file_path: string;
  size_bytes: number | null;
  summary: Record<string, unknown>;
  generated_at: string;
  created_at: string;
}

export interface ReportRequest {
  title?: string | null;
  format: ReportFormat;
  scan_id?: string | null;
  min_severity: Severity;
  include_info: boolean;
  include_remediated: boolean;
}

/**
 * The dashboard's two lists are assembled as bare dicts in
 * routes/reports.py::dashboard rather than serialised from a model, so these
 * shapes are transcribed from that construction, not from a Pydantic schema.
 */
export interface DashboardAsset {
  id: string;
  hostname: string;
  risk_score: number;
  open_ports: number[];
  technologies: string[];
}

export interface DashboardFinding {
  id: string;
  title: string;
  severity: Severity;
  cve_id: string | null;
  cvss_score: number | null;
  /** Null when the finding is not tied to an asset. */
  hostname: string | null;
  created_at: string;
}

export interface Dashboard {
  assets_total: number;
  assets_new_7d: number;
  findings_open: number;
  findings_by_severity: Record<string, number>;
  scans_running: number;
  scans_last_7d: number;
  mean_risk_score: number;
  top_risk_assets: DashboardAsset[];
  recent_findings: DashboardFinding[];
}

// --- websocket events (backend/core/events.py) -----------------------------

export interface WsSnapshot {
  type: "snapshot";
  scan_id: string;
  status: ScanStatus;
  target: string;
  stage: string | null;
  progress: number;
  assets_discovered: number;
  findings_count: number;
}

export interface WsLog {
  type: "log";
  scan_id: string;
  timestamp: string;
  level: LogLevel;
  stage: string | null;
  message: string;
}

export interface WsStatus {
  type: "status";
  scan_id: string;
  timestamp: string;
  status: ScanStatus;
  stage: string | null;
  progress: number | null;
  [extra: string]: unknown;
}

export interface WsResult {
  type: "result";
  scan_id: string;
  timestamp: string;
  kind: string;
  payload: unknown;
}

export interface WsEnd {
  type: "end";
  scan_id: string;
  timestamp: string;
  status: ScanStatus;
  [extra: string]: unknown;
}

export interface WsPing {
  type: "ping";
}

export interface WsError {
  type: "error";
  message: string;
}

export type WsEvent =
  | WsSnapshot
  | WsLog
  | WsStatus
  | WsResult
  | WsEnd
  | WsPing
  | WsError;
