"use client";

import { forwardRef } from "react";

import {
  BUTTON_BASE,
  BUTTON_SIZES,
  BUTTON_VARIANTS,
  type ButtonSize,
  type ButtonVariant,
} from "@/components/ui/buttonStyles";
import { cn } from "@/lib/format";

type Variant = ButtonVariant;
type Size = ButtonSize;

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  /** Shows the busy affordance and blocks further input. */
  busy?: boolean;
  fullWidth?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", busy = false, fullWidth, className, children, disabled, type, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      // A button inside a form defaults to submit, which turns a stray "Cancel"
      // into an accidental save. Callers opt into submit explicitly.
      type={type ?? "button"}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={cn(
        BUTTON_BASE,
        "disabled:cursor-not-allowed disabled:opacity-50",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        fullWidth && "w-full",
        className,
      )}
      {...rest}
    >
      {busy ? <BusyDots /> : null}
      {children}
    </button>
  );
});

/**
 * Three pulsing dots rather than a rotating spinner.
 *
 * Spinners are banned as loading affordances in this design system; on a button
 * we still need to say "working", but without implying page-level indeterminate
 * progress.
 */
function BusyDots() {
  return (
    <span className="flex items-center gap-[3px]" aria-hidden="true">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1 w-1 rounded-full bg-current opacity-50 motion-safe:animate-pulse"
          style={{ animationDelay: `${i * 140}ms` }}
        />
      ))}
    </span>
  );
}

/** Square icon-only button. The accessible label is mandatory. */
export const IconButton = forwardRef<
  HTMLButtonElement,
  Omit<ButtonProps, "fullWidth"> & { "aria-label": string }
>(function IconButton({ variant = "ghost", size = "md", className, ...rest }, ref) {
  return (
    <Button
      ref={ref}
      variant={variant}
      size={size}
      className={cn(
        "px-0",
        size === "sm" && "h-7 w-7",
        size === "md" && "h-8 w-8",
        size === "lg" && "h-10 w-10",
        className,
      )}
      {...rest}
    />
  );
});
