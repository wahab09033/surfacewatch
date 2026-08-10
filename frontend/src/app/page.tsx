import type { Metadata } from "next";

import { LandingNav } from "@/components/marketing/LandingNav";
import {
  LandingCta,
  LandingFeatures,
  LandingFooter,
  LandingHero,
  LandingStats,
} from "@/components/marketing/LandingSections";

/**
 * Public marketing page.
 *
 * This route used to be a client-side redirect to /dashboard or /login. It is
 * now the page an unauthenticated visitor lands on, and it is a Server
 * Component: nothing here depends on session state, so none of it needs to ship
 * as JavaScript or wait on the auth provider before painting. LandingNav is the
 * one client island, for the scroll-linked header.
 */

export const metadata: Metadata = {
  title: "SurfaceWatch — Attack surface management for security teams",
  description:
    "Continuously discover your internet-facing assets, correlate them against live CVE data, and get fix steps written for the stack actually running on the host.",
  // Overrides the root layout, which sets noindex for the authenticated console.
  // That default is right for every other route and exactly wrong for this one:
  // a marketing page nobody can find is not a marketing page.
  robots: { index: true, follow: true },
  openGraph: {
    title: "SurfaceWatch — Your attack surface, fully mapped.",
    description:
      "Continuous asset discovery, CVE correlation and change alerting for security teams.",
    type: "website",
  },
};

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-bg">
      <LandingNav />
      {/* The nav is sticky rather than fixed, so no top offset is needed here —
          it occupies its own space in the flow ahead of the hero. */}
      <main>
        <LandingHero />
        <LandingStats />
        <LandingFeatures />
        <LandingCta />
      </main>
      <LandingFooter />
    </div>
  );
}
