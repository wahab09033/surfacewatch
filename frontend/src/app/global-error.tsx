"use client";

/**
 * The outermost boundary: the root layout itself threw.
 *
 * Two constraints shape this file and explain why it does not reuse
 * `CrashScreen`:
 *
 * * It **replaces** the root layout, so it must render `<html>` and `<body>`
 *   itself, and it cannot assume `globals.css` loaded — hence the inline styles.
 * * It cannot use any provider or the design system, because any of them may be
 *   what failed.
 *
 * The colours are CSS system colours (`Canvas`, `CanvasText`, `ButtonFace`)
 * rather than the app's tokens: with no stylesheet guaranteed, these are the one
 * pair that adapts to the operating system's light or dark setting on its own.
 * That means it follows the OS rather than the in-app theme toggle, which is the
 * right trade at this depth — the theme toggle's state lives in the tree that
 * just crashed.
 */

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Unhandled error in the root layout:", error);
  }, [error]);

  const button: React.CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    height: 32,
    padding: "0 12px",
    border: "1px solid ButtonBorder",
    borderRadius: 4,
    background: "ButtonFace",
    color: "ButtonText",
    fontSize: 13,
    fontFamily: "inherit",
    cursor: "pointer",
  };

  return (
    <html lang="en" style={{ colorScheme: "light dark" }}>
      <body
        style={{
          margin: 0,
          minHeight: "100dvh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 16,
          background: "Canvas",
          color: "CanvasText",
          fontFamily:
            'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
        }}
      >
        <main style={{ maxWidth: 420, textAlign: "center" }}>
          <h1 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>
            SurfaceWatch could not start
          </h1>
          <p style={{ margin: "8px 0 0", fontSize: 13, lineHeight: 1.6, opacity: 0.75 }}>
            Something failed in the console&rsquo;s own shell, before any page could render. Your
            data is unaffected — nothing here writes to the database for display. Reloading is worth
            one try; if it fails again the API or the web service needs a look.
          </p>

          <div
            style={{
              marginTop: 20,
              display: "flex",
              gap: 8,
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            <button type="button" onClick={reset} style={button}>
              Try again
            </button>
            <button
              type="button"
              onClick={() => window.location.assign("/")}
              style={button}
            >
              Reload the console
            </button>
          </div>

          {error.digest ? (
            <p style={{ marginTop: 16, fontSize: 12, opacity: 0.6 }}>
              Reference <code>{error.digest}</code>
            </p>
          ) : null}
        </main>
      </body>
    </html>
  );
}
