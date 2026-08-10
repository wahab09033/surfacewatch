"use client";

/**
 * Theme provider.
 *
 * Three states: "light", "dark", "system". System follows the OS and keeps
 * following it, so a user who changes their OS appearance at dusk sees the app
 * change with it rather than staying stuck at whatever it resolved to on load.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "sw.theme";

interface ThemeContextValue {
  preference: ThemePreference;
  resolved: ResolvedTheme;
  setPreference: (value: ThemePreference) => void;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(resolved: ResolvedTheme): void {
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  // Tells the browser to render form controls and scrollbars to match.
  root.style.colorScheme = resolved;
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  // Starts at "system" to match the inline script in layout.tsx; the stored
  // preference is read in the effect below, after hydration.
  const [preference, setPreferenceState] = useState<ThemePreference>("system");
  const [resolved, setResolved] = useState<ResolvedTheme>("light");

  useEffect(() => {
    let stored: ThemePreference = "system";
    try {
      const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
      if (raw === "light" || raw === "dark" || raw === "system") stored = raw;
    } catch {
      // Storage unavailable — fall back to following the OS.
    }
    setPreferenceState(stored);
    const next = stored === "system" ? systemTheme() : stored;
    setResolved(next);
    applyTheme(next);
  }, []);

  // Keep following the OS while the preference is "system".
  useEffect(() => {
    if (preference !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      const next = media.matches ? "dark" : "light";
      setResolved(next);
      applyTheme(next);
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [preference]);

  const setPreference = useCallback((value: ThemePreference) => {
    setPreferenceState(value);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, value);
    } catch {
      // Non-persistent for this session; still applies below.
    }
    const next = value === "system" ? systemTheme() : value;
    setResolved(next);
    applyTheme(next);
  }, []);

  // Toggle acts on what is on screen, not on the preference: from "system"
  // resolved dark, the obvious next step is explicit light.
  const toggle = useCallback(() => {
    setPreference(resolved === "dark" ? "light" : "dark");
  }, [resolved, setPreference]);

  const value = useMemo(
    () => ({ preference, resolved, setPreference, toggle }),
    [preference, resolved, setPreference, toggle],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used inside <ThemeProvider>");
  return context;
}
