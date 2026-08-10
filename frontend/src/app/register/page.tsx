"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AuthLayout, FormError, PASSWORD_HINT, validateDomain, validatePassword } from "@/components/app/AuthLayout";
import { useAuth } from "@/components/providers/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ApiError } from "@/lib/api";

export default function RegisterPage() {
  const { register, user, loading } = useAuth();
  const router = useRouter();

  const [orgName, setOrgName] = useState("");
  const [domain, setDomain] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    // Check locally first so the obvious problems do not cost a round trip.
    // The API re-validates everything regardless.
    const local: Record<string, string> = {};
    const passwordProblem = validatePassword(password);
    if (passwordProblem) local.password = passwordProblem;
    const domainProblem = validateDomain(domain);
    if (domainProblem) local.domain = domainProblem;
    if (orgName.trim().length < 2) local.org_name = "Organisation name must be at least 2 characters";

    if (Object.keys(local).length > 0) {
      setFieldErrors(local);
      return;
    }

    setFieldErrors({});
    setBusy(true);
    try {
      await register({
        org_name: orgName.trim(),
        domain: domain.trim(),
        email: email.trim(),
        password,
        full_name: fullName.trim() || null,
      });
    } catch (caught) {
      if (caught instanceof ApiError) {
        setFieldErrors(caught.fieldErrors);
        setError(
          caught.status === 409
            ? "That email or domain is already registered."
            : Object.keys(caught.fieldErrors).length > 0
              ? "Please correct the highlighted fields."
              : caught.message,
        );
      } else {
        setError("Could not reach the API. Check that the backend is running.");
      }
      setBusy(false);
    }
  }

  return (
    <AuthLayout
      title="Create your organisation"
      subtitle="You will be the owner, with full access to settings and team management."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-text underline decoration-border underline-offset-2 hover:decoration-accent">
            Sign in
          </Link>
        </>
      }
    >
      <FormError message={error} />

      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <Input
          label="Organisation name"
          value={orgName}
          onChange={(event) => setOrgName(event.target.value)}
          error={fieldErrors.org_name}
          autoComplete="organization"
          autoFocus
          required
          placeholder="Acme Security"
        />

        <Input
          label="Primary domain"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          error={fieldErrors.domain}
          hint="The domain you intend to monitor. You can add more targets later."
          mono
          required
          placeholder="example.com"
          inputMode="url"
          autoCapitalize="none"
          spellCheck={false}
        />

        <Input
          label="Your name"
          value={fullName}
          onChange={(event) => setFullName(event.target.value)}
          error={fieldErrors.full_name}
          autoComplete="name"
          placeholder="Optional"
        />

        <Input
          label="Email"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          error={fieldErrors.email}
          autoComplete="email"
          required
          placeholder="you@example.com"
        />

        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          error={fieldErrors.password}
          hint={PASSWORD_HINT}
          autoComplete="new-password"
          required
        />

        <Button
          type="submit"
          variant="primary"
          size="lg"
          fullWidth
          busy={busy}
          disabled={!orgName || !domain || !email || !password}
        >
          Create organisation
        </Button>
      </form>
    </AuthLayout>
  );
}
