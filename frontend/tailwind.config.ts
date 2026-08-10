import type { Config } from "tailwindcss";

/**
 * The palette is defined once in globals.css as CSS custom properties and
 * referenced here. Tailwind therefore emits `var(--…)` rather than literal hex,
 * so switching themes is one class on <html> instead of a `dark:` variant on
 * every element.
 */
const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        surface: "var(--surface)",
        "surface-hover": "var(--surface-hover)",
        border: "var(--border)",
        "border-strong": "var(--border-strong)",
        text: "var(--text)",
        muted: "var(--muted)",
        accent: "var(--accent)",
        "accent-hover": "var(--accent-hover)",
        "accent-subtle": "var(--accent-subtle)",

        // Severity tints: a light wash behind dark text. Deliberately not the
        // saturated reds/oranges a status LED would use — a table with twelve
        // criticals in it has to stay readable.
        "sev-critical-bg": "var(--sev-critical-bg)",
        "sev-critical-fg": "var(--sev-critical-fg)",
        "sev-high-bg": "var(--sev-high-bg)",
        "sev-high-fg": "var(--sev-high-fg)",
        "sev-medium-bg": "var(--sev-medium-bg)",
        "sev-medium-fg": "var(--sev-medium-fg)",
        "sev-low-bg": "var(--sev-low-bg)",
        "sev-low-fg": "var(--sev-low-fg)",
        "sev-info-bg": "var(--sev-info-bg)",
        "sev-info-fg": "var(--sev-info-fg)",

        "ok-bg": "var(--ok-bg)",
        "ok-fg": "var(--ok-fg)",
        "warn-bg": "var(--warn-bg)",
        "warn-fg": "var(--warn-fg)",
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "Inter",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        // Reserved for machine-readable values: IPs, hostnames, CVE IDs,
        // ports, fingerprints, terminal output. Never for prose.
        mono: ["SF Mono", "SFMono-Regular", "Fira Code", "JetBrains Mono", "Menlo", "Consolas", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: {
        DEFAULT: "6px",
        lg: "8px",
        xl: "10px",
      },
      // No glow shadows. Depth comes from 1px borders and surface fills.
      boxShadow: {
        panel: "0 1px 2px rgba(0, 0, 0, 0.04)",
        drawer: "-1px 0 0 var(--border), 0 8px 24px rgba(0, 0, 0, 0.08)",
        modal: "0 8px 32px rgba(0, 0, 0, 0.12)",
        none: "none",
      },
      keyframes: {
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "slide-in": {
          from: { transform: "translateX(100%)" },
          to: { transform: "translateX(0)" },
        },
        "scale-in": {
          from: { opacity: "0", transform: "scale(0.97)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
      },
      animation: {
        shimmer: "shimmer 1.6s infinite",
        "fade-in": "fade-in 120ms ease-out",
        "slide-in": "slide-in 180ms cubic-bezier(0.22, 1, 0.36, 1)",
        "scale-in": "scale-in 120ms cubic-bezier(0.22, 1, 0.36, 1)",
      },
    },
  },
  plugins: [],
};

export default config;
