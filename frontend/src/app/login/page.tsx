"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AuthLayout, FormError } from "@/components/app/AuthLayout";
import { useAuth } from "@/components/providers/AuthProvider";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ApiError } from "@/lib/api";

export default function LoginPage() {
  const { login, user, loading } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  // Someone who still holds a valid session should not sit on the login form.
  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setFieldErrors({});
    setBusy(true);
    try {
      await login(email.trim(), password);
      // login() navigates on success; leave `busy` set so the button stays
      // disabled through the transition rather than flickering back to idle.
    } catch (caught) {
      if (caught instanceof ApiError) {
        setFieldErrors(caught.fieldErrors);
        setError(
          caught.status === 401
            ? "Those credentials did not match an active account."
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
      title="Sign in to SurfaceWatch"
      subtitle="Attack surface management for security teams."
      footer={
        <>
          No organisation yet?{" "}
          <Link href="/register" className="font-medium text-text underline decoration-border underline-offset-2 hover:decoration-accent">
            Create one
          </Link>
        </>
      }
    >
      <FormError message={error} />

      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <Input
          label="Email"
          type="email"
          name="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          error={fieldErrors.email}
          autoComplete="email"
          autoFocus
          required
          placeholder="you@example.com"
        />

        <Input
          label="Password"
          type="password"
          name="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          error={fieldErrors.password}
          autoComplete="current-password"
          required
        />

        <Button type="submit" variant="primary" size="lg" fullWidth busy={busy} disabled={!email || !password}>
          Sign in
        </Button>
      </form>
    </AuthLayout>
  );
}
