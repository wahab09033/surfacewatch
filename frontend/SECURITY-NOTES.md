# Dependency security posture

Recorded at build time so the trade-offs are explicit rather than discovered
during an audit.

## Next.js — pinned to the most-patched 14.x, advisories remain

The spec calls for **Next.js 14 App Router**, so that is what this app targets.
Pinned to **14.2.35**, the final 14.2.x release. `npm audit` still reports
high-severity advisories against it, and **no Next.js 14.x release resolves
them** — the fixes landed in 15.5.x and later. Upgrading would mean leaving
the specified major version, which is a product decision, not a build-time one.

Assessed against how this app is actually deployed:

| Advisory class | Applies here? | Why |
| --- | --- | --- |
| Image Optimization (DoS, cache confusion, content injection, disk growth) | **No** | `next/image` is not used anywhere; there are no remote image patterns and no raster assets. All iconography is inline SVG. |
| Server Actions (DoS, SSRF, unbounded payload) | **No** | No Server Actions. Every mutation goes through the FastAPI client in `src/lib/api.ts`. |
| React Server Components (DoS, cache poisoning, deserialization) | **Limited** | Every page is a Client Component (`"use client"`), because the UI is driven by a bearer token held in the browser. There is no RSC payload carrying user data. |
| Middleware / Proxy (SSRF, cache poisoning, redirect handling, i18n bypass) | **No** | No `middleware.ts`, no `rewrites`, no `redirects`, no i18n. Auth is enforced client-side by `AuthGuard` and server-side by the API on every request. |
| CSP nonce XSS / `beforeInteractive` scripts | **No** | No `next/script` with `beforeInteractive`, and no CSP nonce integration. |
| Dev-server origin verification (GHSA-3h52-269p-cp9r) | **Fixed** | Resolved in 14.2.30; we are on 14.2.35. |
| `x-middleware-subrequest-id` leak (GHSA-223j-4rm8-mrmf) | **Fixed** | Affected 14.2.25 exactly; we are on 14.2.35. |

The residual risk concentrates in features this app does not use. That is a
reasoned position, not a clean bill of health.

**To clear the advisories entirely, upgrade to Next 15.5.21+.** The App Router
code here is forward-compatible; the migration cost is the framework major, not
this codebase.

## postcss / glob — build-time only

Both are transitive dev dependencies. `postcss` is pinned to 8.5.25, the latest
published release; its remaining advisories concern `sourceMappingURL` handling
and CSS stringification of untrusted stylesheet input. `glob`'s advisory is in
its **CLI** (`-c/--cmd`), which nothing here invokes.

Neither package ships to the browser or runs against user-controlled input —
they process this repository's own CSS at build time. Attacker-controlled input
never reaches them.

## Re-checking

```bash
npm audit                     # full detail
npm audit --omit=dev          # runtime-only surface
```
