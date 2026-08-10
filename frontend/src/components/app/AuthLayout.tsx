"use client";

/**
 * Shared chrome for /login and /register.
 *
 * Centred, single column, no marketing. Anyone here either has credentials or
 * is creating an organisation; a hero image would be in the way.
 */

import Link from "next/link";

import { Logo } from "@/components/app/icons";

export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-bg px-4 py-10">
      <div className="w-full max-w-[380px]">
        <div className="flex flex-col items-center text-center">
          <Link href="/" className="text-accent" aria-label="SurfaceWatch">
            <Logo size={28} />
          </Link>
          <h1 className="mt-4 text-lg font-semibold tracking-[-0.01em] text-text">{title}</h1>
          <p className="mt-1 text-sm text-muted">{subtitle}</p>
        </div>

        <div className="mt-6 rounded-lg border border-border bg-bg p-5 shadow-panel">{children}</div>

        <p className="mt-4 text-center text-sm text-muted">{footer}</p>
      </div>
    </main>
  );
}

/**
 * A form-level error.
 *
 * Field-level problems render under their input; this is for the rest —
 * bad credentials, a duplicate domain, the API being unreachable.
 */
export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="mb-4 rounded border border-sev-critical-bg bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical-fg"
    >
      {message}
    </div>
  );
}

/** The backend's password policy, stated up front rather than after a failure. */
export const PASSWORD_HINT = "At least 12 characters, including a letter and a digit.";

/**
 * Mirrors backend/schemas/auth.py::_validate_password.
 *
 * Duplicated deliberately: the API stays the authority and re-checks every
 * value, but a round trip to be told "too short" is a poor experience. If the
 * backend rule changes, change this too.
 */
export function validatePassword(value: string): string | null {
  if (value.length < 12) return "Password must be at least 12 characters";
  // bcrypt truncates past 72 bytes, so the backend rejects longer values
  // outright. Count bytes, not characters — emoji and accents cost more.
  if (new TextEncoder().encode(value).length > 72) return "Password must be at most 72 bytes";
  if (!/[A-Za-z]/.test(value)) return "Password must contain at least one letter";
  if (!/\d/.test(value)) return "Password must contain at least one digit";
  return null;
}

/** Mirrors the backend's domain normaliser closely enough to catch typos early. */
export function validateDomain(value: string): string | null {
  const domain = value.trim().toLowerCase().replace(/^\w+:\/\//, "").split("/")[0] ?? "";
  if (domain.length < 3) return "Enter a domain, e.g. example.com";
  if (!domain.includes(".")) return "Enter a fully-qualified domain, e.g. example.com";
  return null;
}
