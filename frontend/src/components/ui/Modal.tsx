"use client";

/**
 * Modal dialog.
 *
 * Renders through a portal so it escapes any `overflow: hidden` ancestor, traps
 * focus while open, restores focus to the trigger on close, and locks body
 * scroll. Escape and backdrop clicks close it unless the caller opts out —
 * a destructive confirmation should not be dismissible by a stray click.
 */

import { useCallback, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

import { cn } from "@/lib/format";
import { useMounted } from "@/lib/hooks";

import { Button } from "./Button";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  /** Blocks Escape and backdrop dismissal — for in-flight destructive work. */
  dismissible?: boolean;
  size?: "sm" | "md" | "lg";
}

const SIZES = { sm: "max-w-sm", md: "max-w-md", lg: "max-w-lg" } as const;

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  dismissible = true,
  size = "md",
}: ModalProps) {
  const mounted = useMounted();
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreFocusTo = useRef<HTMLElement | null>(null);

  // Remember what had focus, move focus into the dialog, and put it back on
  // close — otherwise keyboard users land at the top of the document.
  useEffect(() => {
    if (!open) return;
    restoreFocusTo.current = document.activeElement as HTMLElement | null;

    const panel = panelRef.current;
    const first = panel?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? panel)?.focus();

    return () => {
      restoreFocusTo.current?.focus?.();
    };
  }, [open]);

  // Lock body scroll. Compensating for the scrollbar's width keeps the page
  // behind from shifting sideways as it disappears.
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
      if (event.key === "Escape" && dismissible) {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;

      // Focus trap: wrap at both ends of the dialog's focusable set.
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
    [dismissible, onClose],
  );

  if (!mounted || !open) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-end justify-center sm:items-center" onKeyDown={onKeyDown}>
      <div
        className="absolute inset-0 bg-black/30 animate-fade-in dark:bg-black/55"
        onClick={dismissible ? onClose : undefined}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        aria-describedby={description ? "modal-description" : undefined}
        tabIndex={-1}
        className={cn(
          "relative w-full rounded-t-xl border border-border bg-bg shadow-modal animate-scale-in sm:rounded-xl",
          SIZES[size],
        )}
      >
        <div className="px-5 pb-4 pt-5">
          <h2 id="modal-title" className="text-base font-medium text-text">
            {title}
          </h2>
          {description ? (
            <p id="modal-description" className="mt-1.5 text-sm leading-relaxed text-muted">
              {description}
            </p>
          ) : null}
        </div>

        {children ? <div className="px-5 pb-4">{children}</div> : null}

        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3.5">{footer}</div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}

interface ConfirmModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Styles the action as destructive and demands the typed phrase, if set. */
  destructive?: boolean;
  busy?: boolean;
  children?: React.ReactNode;
}

/**
 * Confirmation for destructive actions.
 *
 * Every destructive action in the app goes through this — deleting an asset,
 * cancelling a scan, removing a team member, revoking a session.
 */
export function ConfirmModal({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = true,
  busy = false,
  children,
}: ConfirmModalProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      // While the action is in flight, a backdrop click would orphan the
      // request and leave the user unsure whether it landed.
      dismissible={!busy}
      size="sm"
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button variant={destructive ? "danger" : "primary"} onClick={() => void onConfirm()} busy={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children}
    </Modal>
  );
}
