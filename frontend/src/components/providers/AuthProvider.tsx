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

    loadSession(controller.signal)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        // A dead or tampered token is not an error worth showing; the guard
        // will redirect to /login.
        tokens.clear();
        setUser(null);
        setOrganisation(null);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [loadSession]);

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
      tokens.set(await api.auth.login(email, password));
      await loadSession();
      router.replace("/dashboard");
    },
    [loadSession, router],
  );

  const register = useCallback(
    async (payload: RegisterPayload) => {
      // Registration returns a token pair directly — the new owner is signed
      // in immediately rather than bounced to the login form.
      tokens.set(await api.auth.register(payload));
      await loadSession();
      router.replace("/dashboard");
    },
    [loadSession, router],
  );

  const logout = useCallback(() => {
    tokens.clear();
    setUser(null);
    setOrganisation(null);
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
    () => ({ user, organisation, loading, login, register, logout, refreshUser, hasRole }),
    [user, organisation, loading, login, register, logout, refreshUser, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}
