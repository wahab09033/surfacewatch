"use client";

/**
 * The landing page's sticky navbar.
 *
 * This is the only interactive piece of the marketing page, which is why it is
 * the only Client Component in it — everything else is static and renders on the
 * server. The one bit of state is whether the page has scrolled, used to fade in
 * the bottom border and the blur: sitting flush against the hero with a hard
 * border from the first frame makes the header look detached from the page.
 */

import Link from "next/link";
import { useEffect, useState } from "react";

import { Logo } from "@/components/app/icons";
import { buttonClass } from "@/components/ui/buttonStyles";
import { cn } from "@/lib/format";

// Product is the only one with a section on this page. The other three point at
// routes that do not exist yet — they are the standard marketing-nav set and are
// here because the layout needs them, but they will 404 until those pages are
// built. Better a real href to write than an anchor that silently scrolls
// nowhere, which is what `#docs` would do today.
const NAV_LINKS = [
  { label: "Product", href: "#product" },
  { label: "Docs", href: "/docs" },
  { label: "Pricing", href: "/pricing" },
  { label: "Blog", href: "/blog" },
];

export function LandingNav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    // Read once on mount as well as on scroll: a reload partway down the page
    // restores the scroll position without firing an event, and the header
    // would otherwise render transparent over content.
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={cn(
        "sticky top-0 z-40 transition-colors duration-200",
        // supports-[backdrop-filter] so browsers without it get an opaque bar
        // rather than translucent text over scrolling content.
        scrolled
          ? "border-b border-border bg-bg/80 supports-[backdrop-filter]:backdrop-blur-md"
          : "border-b border-transparent bg-transparent",
      )}
    >
      <nav className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2 rounded text-text transition-colors hover:text-accent"
        >
          <Logo />
          <span className="text-sm font-semibold tracking-tight">SurfaceWatch</span>
        </Link>

        {/* Hidden below md rather than collapsed into a hamburger: four
            same-page anchors are reachable by scrolling on a phone, and a menu
            that exists only to hold them is a control with nothing behind it. */}
        <ul className="hidden items-center gap-1 md:flex">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              <Link
                href={link.href}
                className="rounded px-3 py-1.5 text-sm text-muted transition-colors hover:bg-surface hover:text-text"
              >
                {link.label}
              </Link>
            </li>
          ))}
        </ul>

        <div className="flex shrink-0 items-center gap-2">
          <Link href="/login" className={cn(buttonClass("ghost", "sm"), "hidden sm:inline-flex")}>
            Log in
          </Link>
          <Link href="/register" className={buttonClass("primary", "sm")}>
            Get started
          </Link>
        </div>
      </nav>
    </header>
  );
}
