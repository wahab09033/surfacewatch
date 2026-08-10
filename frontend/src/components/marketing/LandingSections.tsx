/**
 * Landing page sections.
 *
 * All Server Components — there is no state or interactivity below, so none of
 * this needs to ship as JavaScript. Only LandingNav is a client island.
 *
 * Design constraints carried over from the console: 1px borders instead of
 * shadows, no gradient fills, no illustrations, monospace reserved for machine
 * values. The features grid is a ruled table of cells rather than six floating
 * cards, which is the single biggest difference between this and the default
 * SaaS landing page look.
 */

import Link from "next/link";

import {
  ApiIcon,
  AssetsIcon,
  BellIcon,
  FindingsIcon,
  Logo,
  ReportsIcon,
  TenantIcon,
} from "@/components/app/icons";
import { buttonClass } from "@/components/ui/buttonStyles";
import { cn } from "@/lib/format";

import { HeroTerminal } from "./HeroTerminal";

/* -------------------------------------------------------------------------- */
/* Hero                                                                        */
/* -------------------------------------------------------------------------- */

export function LandingHero() {
  return (
    <section className="mx-auto w-full max-w-6xl px-4 pb-16 pt-12 sm:px-6 sm:pb-24 sm:pt-20">
      <div className="grid items-center gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)] lg:gap-16">
        <div className="flex flex-col items-start">
          <p className="inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1 text-xs text-muted">
            <span className="relative flex h-1.5 w-1.5" aria-hidden="true">
              <span className="absolute inline-flex h-full w-full rounded-full bg-ok-fg opacity-60 motion-safe:animate-ping" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-ok-fg" />
            </span>
            Scanning 12,000+ targets daily
          </p>

          {/* -0.02em: at 48px+ the default sans tracking reads loose. Tightened
              on the heading only — body copy at 16px needs the space. */}
          <h1 className="mt-5 text-4xl font-semibold leading-[1.08] tracking-[-0.02em] text-text sm:text-5xl">
            Your attack surface,
            <br />
            fully mapped.
          </h1>

          <p className="mt-5 max-w-lg text-base leading-relaxed text-muted">
            SurfaceWatch continuously discovers everything you expose to the internet,
            correlates it against live CVE data, and tells you what changed — with fix
            steps written for the stack actually running on the host.
          </p>

          <div className="mt-7 flex flex-wrap items-center gap-3">
            <Link href="/register" className={buttonClass("primary", "lg")}>
              Start free scan
            </Link>
            <Link href="#demo" className={buttonClass("secondary", "lg")}>
              View demo
            </Link>
          </div>

          <div className="mt-9 flex items-center gap-3">
            <AvatarStack />
            <p className="text-xs text-muted">
              Trusted by <span className="font-medium text-text">400+</span> security engineers
            </p>
          </div>
        </div>

        {/* The anchor target for "View demo". On a wide screen the terminal is
            already beside the copy; on a phone it sits below the fold, which is
            what makes the button worth having. */}
        <div id="demo" className="scroll-section">
          <HeroTerminal />
        </div>
      </div>
    </section>
  );
}

/**
 * Initials, not photographs.
 *
 * A stock avatar stack is a stock illustration wearing a circle — and inventing
 * faces for customers who have not agreed to appear on the page is worse than
 * abstract. Monogram discs in the existing surface tokens carry the same "these
 * are people" signal without either problem.
 */
function AvatarStack() {
  const initials = ["RK", "AM", "JT", "SN", "DL"];
  return (
    <div className="flex items-center" aria-hidden="true">
      {initials.map((label, i) => (
        <span
          key={label}
          className={cn(
            "flex h-7 w-7 items-center justify-center rounded-full border border-border bg-surface text-[0.6rem] font-medium text-muted",
            // ring-bg fills the gap the overlap would otherwise cut out of the
            // disc beneath, so the stack reads as layered rather than clipped.
            "ring-2 ring-bg",
            i > 0 && "-ml-2.5",
          )}
        >
          {label}
        </span>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Stats                                                                       */
/* -------------------------------------------------------------------------- */

const STATS = [
  { value: "2.4M+", label: "assets tracked" },
  { value: "98k+", label: "CVEs correlated" },
  { value: "<4min", label: "avg time to first finding" },
];

export function LandingStats() {
  return (
    <section className="border-y border-border bg-surface">
      <dl className="mx-auto grid w-full max-w-6xl grid-cols-1 divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        {STATS.map((stat) => (
          <div key={stat.label} className="flex flex-col items-center gap-1 px-4 py-8 text-center">
            {/* tabular so the three figures share a baseline grid and do not
                jitter against each other at large sizes. */}
            <dt className="tabular text-3xl font-semibold tracking-tight text-text">{stat.value}</dt>
            <dd className="text-xs text-muted">{stat.label}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Features                                                                    */
/* -------------------------------------------------------------------------- */

const FEATURES = [
  {
    icon: AssetsIcon,
    title: "Asset Discovery",
    body: "Passive sources and active enumeration find the subdomains, hosts and open ports nobody wrote down. Re-run nightly to catch what shipped since.",
  },
  {
    icon: FindingsIcon,
    title: "CVE Correlation",
    body: "Fingerprinted software versions are matched against NVD, scored by CVSS, and ranked by whether the affected port is actually reachable.",
  },
  {
    icon: BellIcon,
    title: "Change Alerts",
    body: "Every scan is diffed against the last one. A new host, a newly opened port or an expiring certificate reaches Slack the same day it appears.",
  },
  {
    icon: TenantIcon,
    title: "Multi-tenant",
    body: "Every query is scoped to an organisation at the database layer. Run separate client engagements in one deployment with no path between them.",
  },
  {
    icon: ReportsIcon,
    title: "PDF Reports",
    body: "Generate a dated PDF, CSV or JSON export from the same records the console shows — for the client, the auditor, or the ticket queue.",
  },
  {
    icon: ApiIcon,
    title: "REST API",
    body: "Every action in the console is an authenticated endpoint. Trigger scans from CI, pull findings into your own tooling, stream logs over WebSocket.",
  },
];

export function LandingFeatures() {
  return (
    <section id="product" className="scroll-section mx-auto w-full max-w-6xl px-4 py-16 sm:px-6 sm:py-24">
      <div className="max-w-xl">
        <h2 className="text-2xl font-semibold tracking-tight text-text sm:text-3xl">
          Everything the console does, on every asset you own.
        </h2>
        <p className="mt-3 text-sm leading-relaxed text-muted">
          Six modules, one pipeline. Each stage streams its output live and writes
          findings the moment it has them.
        </p>
      </div>

      {/*
        A ruled grid, not six cards. The container draws the top and left rules
        and each cell draws its own right and bottom, so interior lines are
        shared and the outer edge closes exactly once — no doubled 2px seams and
        no shadow anywhere. Collapsing to one column on mobile keeps working
        because each cell still owns its bottom rule.
      */}
      <div className="mt-10 grid grid-cols-1 border-l border-t border-border sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((feature) => {
          const Icon = feature.icon;
          return (
            <div
              key={feature.title}
              className="group border-b border-r border-border p-6 transition-colors hover:bg-surface"
            >
              <span className="flex h-8 w-8 items-center justify-center rounded border border-border bg-surface text-muted transition-colors group-hover:border-accent group-hover:text-accent">
                <Icon />
              </span>
              <h3 className="mt-4 text-sm font-semibold text-text">{feature.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{feature.body}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* CTA banner                                                                  */
/* -------------------------------------------------------------------------- */

export function LandingCta() {
  return (
    // Same `dark` trick as the hero terminal: this section is #111113 in both
    // themes, and forcing the token set rather than hard-coding hex means the
    // border and muted text come along correctly instead of being hand-picked.
    <section className="dark border-y border-border bg-bg">
      <div className="mx-auto flex w-full max-w-6xl flex-col items-center gap-6 px-4 py-16 text-center sm:px-6 sm:py-20">
        <h2 className="max-w-2xl text-2xl font-semibold tracking-tight text-text sm:text-4xl">
          Start finding your exposure today.
        </h2>
        <p className="max-w-lg text-sm leading-relaxed text-muted">
          Point it at a domain you own and the first findings land in under four minutes.
          No agent to install, no credit card.
        </p>
        <Link href="/register" className={buttonClass("primary", "lg")}>
          Get started free
        </Link>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Footer                                                                      */
/* -------------------------------------------------------------------------- */

const FOOTER_LINKS = [
  { label: "Product", href: "#product" },
  { label: "Docs", href: "/docs" },
  { label: "Pricing", href: "/pricing" },
  { label: "Blog", href: "/blog" },
];

export function LandingFooter() {
  // Evaluated when the page is prerendered, not per request — this page is
  // static, so the year is fixed at build time. Correct for any deploy inside
  // the same year, and a rebuild is what fixes it in January.
  const year = new Date().getFullYear();

  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-4 px-4 py-6 sm:flex-row sm:px-6">
        <Link href="/" className="flex items-center gap-2 text-text transition-colors hover:text-accent">
          <Logo size={16} />
          <span className="text-xs font-semibold tracking-tight">SurfaceWatch</span>
        </Link>

        <ul className="flex items-center gap-5">
          {FOOTER_LINKS.map((link) => (
            <li key={link.label}>
              <Link href={link.href} className="text-xs text-muted transition-colors hover:text-text">
                {link.label}
              </Link>
            </li>
          ))}
        </ul>

        <p className="text-xs text-muted">© {year} SurfaceWatch</p>
      </div>
    </footer>
  );
}
