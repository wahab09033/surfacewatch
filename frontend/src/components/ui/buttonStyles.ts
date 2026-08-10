/**
 * The Button visual recipe, kept out of Button.tsx on purpose.
 *
 * Button.tsx is a `"use client"` module. Importing a *function* from a client
 * module into a Server Component does not give you the function — it gives you a
 * client reference stub, and calling it fails at prerender with a bare
 * "u is not a function". Rendering a client *component* from the server is fine;
 * calling a client *function* is not.
 *
 * The landing page is server-rendered and styles its `<Link>` CTAs with this, so
 * the recipe lives here, where both sides can reach it, and Button.tsx imports it
 * back rather than keeping a second copy to drift.
 */

import { cn } from "@/lib/format";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

export const BUTTON_BASE =
  "inline-flex select-none items-center justify-center whitespace-nowrap rounded border font-medium transition-colors";

export const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: "border-accent bg-accent text-white hover:bg-accent-hover disabled:hover:bg-accent",
  secondary: "border-border bg-bg text-text hover:bg-surface disabled:hover:bg-bg",
  ghost:
    "border-transparent bg-transparent text-muted hover:bg-surface hover:text-text disabled:hover:bg-transparent",
  danger: "border-sev-critical-bg bg-sev-critical-bg text-sev-critical-fg hover:border-sev-critical-fg/30",
};

export const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "h-7 gap-1.5 px-2.5 text-xs",
  md: "h-8 gap-2 px-3 text-sm",
  lg: "h-10 gap-2 px-4 text-sm",
};

/**
 * The button recipe as a class string, for elements that must not be `<button>`.
 *
 * The landing page's CTAs navigate, so they are anchors — a `<button onClick=…>`
 * that routes is not middle-clickable, not keyboard-navigable as a link, and
 * reads wrong to a screen reader.
 */
export function buttonClass(
  variant: ButtonVariant = "secondary",
  size: ButtonSize = "md",
): string {
  return cn(BUTTON_BASE, BUTTON_VARIANTS[variant], BUTTON_SIZES[size]);
}
