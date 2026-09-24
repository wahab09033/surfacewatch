"use client";

/**
 * Session state: the signed-in user and their organisation.
 *
 * The API is the real authority — every request is authorised server-side
 * against the caller's org. This context exists so the UI can render the right
 * chrome (role-gated buttons, org name) without refetching /me on every page.
 * It is never the security boundary.
 */

import { useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { ApiError, api, setSessionExpiredHandler, tokens } from "@/lib/api";
import type { Organisation, RegisterPayload, User, UserRole } from "@/lib/types";

interface AuthContextValue {
  user: User | null;
  organisation: Organisation | null;
  /** True until the initial session check settles. */
  loading: boolean;
  /**
   * Set when the session check could not complete for a reason that says nothing
   * about whether the session is valid — an API that could not be reached, or one
   * that answered 5xx. The stored token is deliberately kept in that case, so
   * retrying can restore the session without making anyone sign in again.
   */
  sessionError: ApiError | null;
  /** Retry the initial session check. */
  retrySession: () => void;
  login: (email: string, password: string) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  /** Role gate, mirroring the backend's ranking. */
  hasRole: (minimum: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const ROLE_RANK: Record<UserRole, number> = {
  viewer: 1,
  analyst: 2,
  admin: 3,
  owner: 4,
};

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [organisation, setOrganisation] = useState<Organisation | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionError, setSessionError] = useState<ApiError | null>(null);
  /** Bumped by retrySession to re-run the effect below. */
  const [attempt, setAttempt] = useState(0);

  const loadSession = useCallback(async (signal?: AbortSignal) => {
    // Both are needed on nearly every screen, so fetch them together rather
    // than letting the org name pop in a beat after the rest of the chrome.
    const [me, org] = await Promise.all([api.auth.me(signal), api.auth.organisation(signal)]);
    setUser(me);
    setOrganisation(org);
  }, []);

  // Restore the session on mount if a token survived the reload.
  useEffect(() => {
    const controller = new AbortController();

    if (!tokens.access()) {
      setLoading(false);
      return () => controller.abort();
    }

    setLoading(true);
    setSessionError(null);

    loadSession(controller.signal)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;

        // Only a 401 proves the session is dead, and only that is worth
        // destroying. Everything else here is a statement about the network or
        // the server, not about the token:
        //
        //   * status 0 — the request never reached the API, so the token has not
        //     been checked at all. Clearing it turns a backend restart or a
        //     dropped wifi connection into a forced re-login, and the user has
        //     no way to tell those apart from being signed out.
        //   * 5xx — the API is up but broken. The token is probably fine.
        //
        // The token is therefore kept for both, and the guard offers a retry
        // instead of a redirect. A 401 has already been through the api client,
        // which cleared the tokens and fired the session-expired handler, so
        // this branch is belt-and-braces.
        const keepSession = !(error instanceof ApiError) || !error.isAuth;
        if (keepSession) {
          setSessionError(
            error instanceof ApiError
              ? error
              : new ApiError(0, "Could not reach the API. Is the backend running?"),
          );
          setUser(null);
          setOrganisation(null);
          return;
        }

        tokens.clear();
        setUser(null);
        setOrganisation(null);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [loadSession, attempt]);

  const retrySession = useCallback(() => setAttempt((previous) => previous + 1), []);

  // Kept in a ref so the api module's expiry handler always calls the current
  // router instance without re-registering on every render.
  const routerRef = useRef(router);
  routerRef.current = router;

  // The api client calls this when a refresh attempt fails, so an expired
  // session lands on /login instead of leaving a half-rendered page.
  useEffect(() => {
    setSessionExpiredHandler(() => {
      setUser(null);
      setOrganisation(null);
      routerRef.current.replace("/login");
    });
    return () => setSessionExpiredHandler(null);
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      setSessionError(null);
      tokens.set(await api.auth.login(email, password));
      await loadSession();
      router.replace("/dashboard");
    },
    [loadSession, router],
  );

  const register = useCallback(
    async (payload: RegisterPayload) => {
      setSessionError(null);
      // Registration returns a token pair directly — the new owner is signed
      // in immediately rather than bounced to the login form.
      tokens.set(await api.auth.register(payload));
      await loadSession();
      router.replace("/dashboard");
    },
    [loadSession, router],
  );

  const logout = useCallback(() => {
    const refresh = tokens.refresh();
    tokens.clear();
    setUser(null);
    setOrganisation(null);
    // Otherwise the guard would keep showing "could not reach the API" to
    // somebody who has just deliberately signed out.
    setSessionError(null);
    if (refresh) {
      // Best-effort server-side revocation: a signed-out session's token must
      // not be replayable. Failure just means the token lives until its exp.
      api.auth.logout(refresh).catch(() => undefined);
    }
    router.replace("/login");
  }, [router]);

  const refreshUser = useCallback(async () => {
    try {
      await loadSession();
    } catch (error) {
      if (error instanceof ApiError && error.isAuth) logout();
    }
  }, [loadSession, logout]);

  const hasRole = useCallback(
    (minimum: UserRole) => (user ? ROLE_RANK[user.role] >= ROLE_RANK[minimum] : false),
    [user],
  );

  const value = useMemo(
    () => ({
      user,
      organisation,
      loading,
      sessionError,
      retrySession,
      login,
      register,
      logout,
      refreshUser,
      hasRole,
    }),
    [
      user,
      organisation,
      loading,
      sessionError,
      retrySession,
      login,
      register,
      logout,
      refreshUser,
      hasRole,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}
