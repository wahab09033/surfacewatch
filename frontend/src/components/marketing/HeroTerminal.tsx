/**
 * The hero's scan terminal.
 *
 * Deliberately a Server Component with no state. The "live" feel is a pure-CSS
 * staged reveal — each line carries an animation-delay and `fill-mode: backwards`
 * so it sits invisible until its turn. A JS typewriter would render an empty box
 * on the server, pop in on hydration, and risk a mismatch; this renders complete
 * in the HTML, degrades to a finished scan with JS disabled, and is flattened to
 * an instant reveal by the reduced-motion rules in globals.css.
 *
 * The hostnames are all under the reserved `.example` TLD and the addresses are
 * in 203.0.113.0/24 (RFC 5737, documentation-only). Both are unregistrable, so
 * this page cannot advertise unpatched criticals against infrastructure that
 * belongs to somebody — which a plausible-looking real domain would.
 *
 * Every CVE below is real and its score is the published CVSS v3.1 base score.
 * Marketing copy that invents a CVE or misstates a severity is the one mistake
 * this audience will certainly catch.
 */

import { cn } from "@/lib/format";

type Severity = "critical" | "high" | "medium";

type Line =
  | { kind: "cmd"; text: string }
  | { kind: "log"; time: string; stage: string; text: string; tone?: "muted" | "ok" }
  | { kind: "finding"; time: string; cve: string; severity: Severity; score: string; text: string }
  | { kind: "done"; time: string; text: string };

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
};

const LINES: Line[] = [
  { kind: "cmd", text: "surfacewatch scan --target acme-corp.example --deep" },
  { kind: "log", time: "09:24:01", stage: "subdomain", text: "enumerating acme-corp.example", tone: "muted" },
  { kind: "log", time: "09:24:07", stage: "subdomain", text: "47 subdomains, 23 resolving" },
  { kind: "log", time: "09:24:09", stage: "ports", text: "api.acme-corp.example → 203.0.113.24" },
  { kind: "log", time: "09:24:11", stage: "ports", text: "22/tcp ssh · 443/tcp https · 8080/tcp http-alt" },
  { kind: "log", time: "09:24:14", stage: "stack", text: "nginx 1.24.0 · OpenSSH 9.6p1 · Spring Boot 2.6.3" },
  {
    kind: "finding",
    time: "09:24:18",
    cve: "CVE-2024-6387",
    severity: "high",
    score: "8.1",
    text: "regreSSHion — unauth RCE in OpenSSH 9.6p1",
  },
  { kind: "log", time: "09:24:20", stage: "ports", text: "vpn.acme-corp.example → 203.0.113.61" },
  {
    kind: "finding",
    time: "09:24:23",
    cve: "CVE-2023-4966",
    severity: "critical",
    score: "9.4",
    text: "CitrixBleed — session token disclosure",
  },
  {
    kind: "finding",
    time: "09:24:26",
    cve: "CVE-2022-22965",
    severity: "critical",
    score: "9.8",
    text: "Spring4Shell — RCE via data binding",
  },
  {
    kind: "finding",
    time: "09:24:29",
    cve: "CVE-2023-44487",
    severity: "high",
    score: "7.5",
    text: "HTTP/2 Rapid Reset — DoS on 8080/tcp",
  },
  { kind: "log", time: "09:24:31", stage: "diff", text: "staging.acme-corp.example is new since Tue", tone: "muted" },
  { kind: "done", time: "09:24:33", text: "4 findings · 2 critical · 23 assets · 32s" },
];

/** 180ms cadence: fast enough not to feel staged, slow enough to read. */
const STEP_MS = 180;

export function HeroTerminal() {
  return (
    // `dark` forces the dark token set inside this subtree regardless of the
    // page theme. Because the whole palette is CSS custom properties, that is
    // all it takes — severity tints included — and it beats hard-coding hex,
    // which would leave the badges reading as light-mode chips on a dark panel.
    <div className="dark w-full overflow-hidden rounded-lg border border-border bg-bg">
      <div className="flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
        <span className="flex gap-1.5" aria-hidden="true">
          {/* Monochrome, not macOS traffic lights: three saturated dots would be
              the only rainbow element in the product. */}
          <span className="h-2 w-2 rounded-full bg-border-strong" />
          <span className="h-2 w-2 rounded-full bg-border-strong" />
          <span className="h-2 w-2 rounded-full bg-border-strong" />
        </span>
        <span className="ml-1 truncate font-mono text-2xs text-muted">
          scan · acme-corp.example
        </span>
        <span className="ml-auto flex items-center gap-1.5">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full rounded-full bg-ok-fg opacity-60 motion-safe:animate-ping" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-ok-fg" />
          </span>
          <span className="font-mono text-2xs text-muted">live</span>
        </span>
      </div>

      <div className="px-3 py-3 sm:px-4">
        <ol className="flex flex-col gap-1">
          {LINES.map((line, i) => (
            <li
              key={i}
              className="animate-fade-in font-mono text-[0.7rem] leading-relaxed sm:text-[0.75rem]"
              style={{ animationDelay: `${i * STEP_MS}ms`, animationFillMode: "backwards" }}
            >
              <TerminalLine line={line} />
            </li>
          ))}
        </ol>

        <div
          className="mt-1 flex items-center gap-2 font-mono text-[0.7rem] sm:text-[0.75rem]"
          style={{ animationDelay: `${LINES.length * STEP_MS}ms`, animationFillMode: "backwards" }}
        >
          <span className="text-accent">›</span>
          <span className="inline-block h-3.5 w-1.5 bg-muted motion-safe:animate-pulse" aria-hidden="true" />
        </div>
      </div>
    </div>
  );
}

function TerminalLine({ line }: { line: Line }) {
  if (line.kind === "cmd") {
    return (
      <span className="flex gap-2">
        <span className="shrink-0 text-accent">$</span>
        <span className="min-w-0 break-words text-text">{line.text}</span>
      </span>
    );
  }

  if (line.kind === "done") {
    return (
      <span className="flex gap-2.5">
        <Time value={line.time} />
        <span className="min-w-0 break-words font-medium text-ok-fg">✓ {line.text}</span>
      </span>
    );
  }

  if (line.kind === "finding") {
    return (
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Time value={line.time} />
        <span className="shrink-0 text-text">{line.cve}</span>
        <span
          className={cn(
            "shrink-0 rounded px-1.5 py-0.5 text-[0.6rem] font-medium uppercase tracking-wide",
            SEVERITY_CLASS[line.severity],
          )}
        >
          {line.severity} {line.score}
        </span>
        <span className="min-w-0 break-words text-muted">{line.text}</span>
      </span>
    );
  }

  return (
    <span className="flex gap-2.5">
      <Time value={line.time} />
      <span className="hidden shrink-0 text-muted sm:inline">[{line.stage}]</span>
      <span className={cn("min-w-0 break-words", line.tone === "muted" ? "text-muted" : "text-text")}>
        {line.text}
      </span>
    </span>
  );
}

function Time({ value }: { value: string }) {
  return <span className="tabular shrink-0 text-muted">{value}</span>;
}
