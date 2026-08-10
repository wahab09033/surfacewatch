"use client";

/** Form controls. */

import { forwardRef, useId } from "react";

import { cn } from "@/lib/format";

const FIELD =
  "w-full rounded border border-border bg-bg text-sm text-text transition-colors placeholder:text-muted hover:border-border-strong disabled:cursor-not-allowed disabled:bg-surface disabled:text-muted";

interface FieldShellProps {
  label?: string;
  hint?: string;
  error?: string;
  required?: boolean;
  htmlFor: string;
  children: React.ReactNode;
  className?: string;
}

function FieldShell({ label, hint, error, required, htmlFor, children, className }: FieldShellProps) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      {label ? (
        <label htmlFor={htmlFor} className="text-xs font-medium text-text">
          {label}
          {required ? (
            <span className="ml-0.5 text-accent" aria-hidden="true">
              *
            </span>
          ) : null}
        </label>
      ) : null}
      {children}
      {/*
        The hint is hidden once there is an error: stacking "must be 12+
        characters" under "Password is too short" says the same thing twice.
      */}
      {error ? (
        <p id={`${htmlFor}-error`} role="alert" className="text-xs leading-snug text-accent">
          {error}
        </p>
      ) : hint ? (
        <p id={`${htmlFor}-hint`} className="text-xs leading-snug text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
  error?: string;
  /** Monospace the value — for targets, hostnames, IPs, CVE IDs. */
  mono?: boolean;
  leading?: React.ReactNode;
  trailing?: React.ReactNode;
  wrapperClassName?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { label, hint, error, mono, leading, trailing, className, wrapperClassName, id, ...rest },
  ref,
) {
  const generated = useId();
  const fieldId = id ?? generated;

  return (
    <FieldShell
      label={label}
      hint={hint}
      error={error}
      required={rest.required}
      htmlFor={fieldId}
      className={wrapperClassName}
    >
      <div className="relative flex items-center">
        {leading ? (
          <span className="pointer-events-none absolute left-2.5 flex text-muted" aria-hidden="true">
            {leading}
          </span>
        ) : null}
        <input
          ref={ref}
          id={fieldId}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
          className={cn(
            FIELD,
            "h-9 px-2.5",
            // Boolean(): a ReactNode may be 0 or "", which would leak a falsy
            // non-boolean into cn() rather than dropping out.
            Boolean(leading) && "pl-8",
            Boolean(trailing) && "pr-9",
            mono && "font-mono text-[0.8125rem] tabular",
            error && "border-accent",
            className,
          )}
          {...rest}
        />
        {trailing ? <span className="absolute right-2 flex items-center">{trailing}</span> : null}
      </div>
    </FieldShell>
  );
});

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
  mono?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { label, hint, error, mono, className, id, rows = 4, ...rest },
  ref,
) {
  const generated = useId();
  const fieldId = id ?? generated;

  return (
    <FieldShell label={label} hint={hint} error={error} required={rest.required} htmlFor={fieldId}>
      <textarea
        ref={ref}
        id={fieldId}
        rows={rows}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        className={cn(
          FIELD,
          "resize-y px-2.5 py-2 leading-relaxed",
          mono && "font-mono text-[0.8125rem]",
          error && "border-accent",
          className,
        )}
        {...rest}
      />
    </FieldShell>
  );
});

export interface SelectOption<T extends string> {
  value: T;
  label: string;
}

export interface SelectProps<T extends string>
  extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, "onChange" | "value"> {
  label?: string;
  hint?: string;
  error?: string;
  value: T;
  options: readonly SelectOption<T>[];
  onValueChange: (value: T) => void;
  wrapperClassName?: string;
}

/**
 * A native select.
 *
 * Deliberately not a custom listbox: the native control gets mobile pickers,
 * type-ahead, and screen-reader behaviour for free, and nothing about these
 * menus needs custom rendering.
 */
export function Select<T extends string>({
  label,
  hint,
  error,
  value,
  options,
  onValueChange,
  className,
  wrapperClassName,
  id,
  ...rest
}: SelectProps<T>) {
  const generated = useId();
  const fieldId = id ?? generated;

  return (
    <FieldShell
      label={label}
      hint={hint}
      error={error}
      required={rest.required}
      htmlFor={fieldId}
      className={wrapperClassName}
    >
      <div className="relative flex items-center">
        <select
          id={fieldId}
          value={value}
          onChange={(event) => onValueChange(event.target.value as T)}
          aria-invalid={error ? true : undefined}
          className={cn(
            FIELD,
            "h-9 cursor-pointer appearance-none pl-2.5 pr-8",
            error && "border-accent",
            className,
          )}
          {...rest}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <svg
          width="10"
          height="10"
          viewBox="0 0 10 10"
          fill="none"
          aria-hidden="true"
          className="pointer-events-none absolute right-2.5 text-muted"
        >
          <path d="M2 4l3 3 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
    </FieldShell>
  );
}

/** A switch. Used for the scan module toggles. */
export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
  id,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
  id?: string;
}) {
  const generated = useId();
  const fieldId = id ?? generated;

  return (
    <div className={cn("flex items-start gap-3", disabled && "opacity-55")}>
      <button
        type="button"
        role="switch"
        id={fieldId}
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          "relative mt-0.5 h-[18px] w-8 shrink-0 rounded-full border transition-colors",
          checked ? "border-accent bg-accent" : "border-border bg-surface",
          !disabled && "cursor-pointer",
          disabled && "cursor-not-allowed",
        )}
      >
        <span
          aria-hidden="true"
          className={cn(
            "absolute top-1/2 block h-3 w-3 -translate-y-1/2 rounded-full bg-white transition-transform",
            checked ? "translate-x-[16px]" : "translate-x-[2px]",
            !checked && "border border-border",
          )}
        />
      </button>
      <div className="min-w-0 flex-1">
        <label htmlFor={fieldId} className={cn("block text-sm text-text", !disabled && "cursor-pointer")}>
          {label}
        </label>
        {description ? <p className="mt-0.5 text-xs leading-snug text-muted">{description}</p> : null}
      </div>
    </div>
  );
}

/** A checkbox with a label. */
export function Checkbox({
  checked,
  onChange,
  label,
  disabled,
  id,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: React.ReactNode;
  disabled?: boolean;
  id?: string;
}) {
  const generated = useId();
  const fieldId = id ?? generated;

  return (
    <div className="flex items-center gap-2">
      <input
        type="checkbox"
        id={fieldId}
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        className="h-3.5 w-3.5 cursor-pointer rounded border-border accent-accent disabled:cursor-not-allowed"
      />
      <label htmlFor={fieldId} className="cursor-pointer select-none text-sm text-text">
        {label}
      </label>
    </div>
  );
}
