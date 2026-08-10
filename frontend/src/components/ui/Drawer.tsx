"use client";

/**
 * Right-hand slide-over panel.
 *
 * Shares Modal's focus and scroll handling, but is a distinct component because
 * its dismissal rules differ: a drawer is a reading surface, so backdrop clicks
 * and Escape always close it, and it never blocks.
 */

import { useCallback, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

import { cn } from "@/lib/format";
import { useMounted } from "@/lib/hooks";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: "md" | "lg";
}

export function Drawer({ open, onClose, title, subtitle, children, footer, width = "md" }: DrawerProps) {
  const mounted = useMounted();
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreFocusTo = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreFocusTo.current = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => {
      restoreFocusTo.current?.focus?.();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const { body, documentElement } = document;
    const previousOverflow = body.style.overflow;
    const previousPadding = body.style.paddingRight;
    const gap = window.innerWidth - documentElement.clientWidth;
    body.style.overflow = "hidden";
    if (gap > 0) body.style.paddingRight = `${gap}px`;
    return () => {
      body.style.overflow = previousOverflow;
      body.style.paddingRight = previousPadding;
    };
  }, [open]);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;

      const nodes = Array.from(panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
      if (nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (!first || !last) return;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  if (!mounted || !open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[60] flex justify-end" onKeyDown={onKeyDown}>
      <div className="absolute inset-0 bg-black/25 animate-fade-in dark:bg-black/50" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        tabIndex={-1}
        className={cn(
          "relative flex h-full w-full flex-col border-l border-border bg-bg shadow-drawer animate-slide-in",
          width === "md" ? "sm:max-w-md" : "sm:max-w-xl",
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3.5">
          <div className="min-w-0">
            <h2 id="drawer-title" className="truncate text-sm font-medium text-text">
              {title}
            </h2>
            {subtitle ? <div className="mt-0.5 truncate text-xs text-muted">{subtitle}</div> : null}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="-mr-1 shrink-0 rounded p-1.5 text-muted transition-colors hover:bg-surface hover:text-text"
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
              <path d="M3 3l8 8m0-8l-8 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">{children}</div>

        {footer ? (
          <footer className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">{footer}</footer>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}

/** A titled block inside a drawer. */
export function DrawerSection({
  title,
  action,
  children,
  className,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("py-3 first:pt-0", className)}>
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-2xs font-medium uppercase tracking-wide text-muted">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}
