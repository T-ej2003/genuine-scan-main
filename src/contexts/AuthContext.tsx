import React, { createContext, useContext, useEffect, useMemo, useRef, useState, ReactNode } from "react";
import { useLocation } from "react-router";

import { shouldBootstrapCurrentUser } from "@/contexts/auth-bootstrap";
import apiClient from "@/lib/api-client";
import { isActivePrintSessionSuppressed } from "@/lib/active-print-session";
import { clearRequestCoordinator, getRequestCoordinatorScope, isRequestCoordinatorScopeReady, isRequestCoordinatorUserCurrent, setRequestCoordinatorScope } from "@/lib/api/request-coordinator";
import type { AuthState, PendingAuthSession, User } from "@/types";

interface AuthContextType {
  user: User | null;
  pendingAuth: PendingAuthSession | null;
  isLoading: boolean;
  authReady: boolean;
  authBootstrapStatus: "bootstrapping" | "authenticated" | "unauthenticated";
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string; sessionStage?: "ACTIVE" | "MFA_BOOTSTRAP" }>;
  logout: () => void;
  refresh: () => Promise<void>;
  completeMfaSession: (payload: { user?: any; auth?: AuthState | null }) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const AUTH_BOOTSTRAP_MIN_INTERVAL_MS = 60_000;
const DISABLE_E2E_AUTH_POLLING = import.meta.env.VITE_E2E_DISABLE_AUTH_POLLING === "true";

const normalizeRole = (role: any): User["role"] => {
  const r = String(role || "").trim().toUpperCase();
  if (r === "SUPER_ADMIN" || r === "PLATFORM_SUPER_ADMIN") return "super_admin";
  if (r === "LICENSEE_ADMIN" || r === "ORG_ADMIN") return "licensee_admin";
  if (r === "MANUFACTURER" || r === "MANUFACTURER_ADMIN" || r === "MANUFACTURER_USER") return "manufacturer";
  return "manufacturer";
};

function normalizeUser(u: any): User {
  const licenseeId = u.licenseeId ?? u.licensee?.id ?? undefined;
  const linkedLicensees = Array.isArray(u.linkedLicensees)
    ? u.linkedLicensees
        .filter((entry: any) => entry?.id)
        .map((entry: any) => ({
          id: String(entry.id),
          name: String(entry.name || ""),
          prefix: String(entry.prefix || ""),
          brandName: entry.brandName ?? null,
          orgId: entry.orgId ?? null,
          isPrimary: Boolean(entry.isPrimary),
          scopeVersion: entry.scopeVersion ?? null,
        }))
    : undefined;

  return {
    id: String(u.id),
    email: String(u.email),
    name: String(u.name ?? ""),
    role: normalizeRole(u.role),
    rawRole: String(u.role || "").trim().toUpperCase() || null,
    emailVerifiedAt: u.emailVerifiedAt ?? null,
    pendingEmail: u.pendingEmail ?? null,
    pendingEmailRequestedAt: u.pendingEmailRequestedAt ?? null,
    licenseeId,
    scopeVersion: u.scopeVersion ?? null,
    orgId: u.orgId ?? null,
    licensee: u.licensee
      ? {
          id: String(u.licensee.id),
          name: String(u.licensee.name || ""),
          prefix: String(u.licensee.prefix || ""),
          brandName: u.licensee.brandName ?? null,
        }
      : null,
    linkedLicensees,
    createdAt: u.createdAt ?? new Date().toISOString(),
    isActive: typeof u.isActive === "boolean" ? u.isActive : true,
    deletedAt: u.deletedAt ?? null,
    auth: u.auth ?? null,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const [user, setUser] = useState<User | null>(null);
  const [pendingAuth, setPendingAuth] = useState<PendingAuthSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authBootstrapStatus, setAuthBootstrapStatus] = useState<"bootstrapping" | "authenticated" | "unauthenticated">("bootstrapping");
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const lastRefreshAttemptAtRef = useRef(0);
  const lastRefreshSuccessAtRef = useRef(0);
  const refreshCooldownUntilRef = useRef(0);
  const sessionGenerationRef = useRef(0);
  const scopeRetryRef = useRef<number | null>(null);

  const clearSession = () => {
    if (scopeRetryRef.current !== null) window.clearTimeout(scopeRetryRef.current);
    scopeRetryRef.current = null;
    sessionGenerationRef.current += 1;
    setRequestCoordinatorScope(null);
    setUser(null);
    setPendingAuth(null);
    setAuthBootstrapStatus("unauthenticated");
    apiClient.logout();
    clearRequestCoordinator();
  };

  const completeMfaSession = (payload: { user?: any; auth?: AuthState | null }) => {
    if (!payload.user) {
      clearSession();
      return;
    }

    sessionGenerationRef.current += 1;
    setPendingAuth(null);
    const normalized = normalizeUser({ ...payload.user, auth: payload.auth || payload.user?.auth || null });
    setRequestCoordinatorScope(normalized);
    setUser(normalized);
    setAuthBootstrapStatus("authenticated");
  };

  const setAuthStateFromPayload = (payload: { user?: any; auth?: AuthState | null } | null) => {
    if (!payload?.user) {
      clearSession();
      return false;
    }

    sessionGenerationRef.current += 1;
    const auth = payload.auth || payload.user?.auth || null;
    const normalized = normalizeUser({ ...payload.user, auth });

    if (auth?.sessionStage === "MFA_BOOTSTRAP") {
      setRequestCoordinatorScope(null);
      setUser(null);
      setPendingAuth({ user: normalized, auth });
      setAuthBootstrapStatus("unauthenticated");
      return true;
    }

    setPendingAuth(null);
    setRequestCoordinatorScope(normalized);
    setUser(normalized);
    setAuthBootstrapStatus("authenticated");
    return true;
  };

  const authPayloadFromResponseData = (data: any): { user?: any; auth?: AuthState | null } | null => {
    if (!data) return null;
    if (data.user) return { user: data.user, auth: data.auth || data.user?.auth || null };
    return { user: data, auth: data.auth || null };
  };

  const refresh = async () => {
    if (refreshInFlightRef.current) return refreshInFlightRef.current;
    if (Date.now() < refreshCooldownUntilRef.current) return;
    refreshInFlightRef.current = (async () => {
      const generation = sessionGenerationRef.current;
      lastRefreshAttemptAtRef.current = Date.now();

      const canRefreshSession = typeof apiClient.refreshSession === "function";
      const canGetCurrentUser = typeof apiClient.getCurrentUser === "function";
      const refreshSession = () =>
        canRefreshSession
          ? apiClient.refreshSession()
          : Promise.resolve({ success: false, error: "Session refresh is unavailable" });
      const getCurrentUser = () =>
        canGetCurrentUser
          ? apiClient.getCurrentUser()
          : Promise.resolve({ success: false, error: "Current session lookup is unavailable" });
      const restoreAttempts: Array<() => Promise<any>> = apiClient.getToken?.()
        ? [getCurrentUser, refreshSession]
        : [refreshSession, getCurrentUser];

      for (const attempt of restoreAttempts) {
        const res = await attempt().catch((error: unknown) => ({
          success: false,
          status: 0,
          error: error instanceof Error ? error.message : "Session restore failed",
        }));
        if (generation !== sessionGenerationRef.current) return;
        if (res?.success && res.data) {
          lastRefreshSuccessAtRef.current = Date.now();
          if (setAuthStateFromPayload(authPayloadFromResponseData(res.data))) return;
        }
        if (res?.status === 403 || res?.status === 429 || res?.status === 0 || (res?.status && res.status >= 500)) {
          refreshCooldownUntilRef.current = Date.now() + Math.max(10, Number(res?.retryAfterSec) || 10) * 1000;
          return;
        }
      }

      if (generation === sessionGenerationRef.current) clearSession();
    })().finally(() => {
      refreshInFlightRef.current = null;
    });
    return refreshInFlightRef.current;
  };

  useEffect(() => {
    const onAuthLogout = () => clearSession();
    let retryCount = 0;
    const onScopeRefresh = () => {
      if (scopeRetryRef.current !== null) window.clearTimeout(scopeRetryRef.current);
      scopeRetryRef.current = null;
      if (isRequestCoordinatorScopeReady()) return;
      apiClient.setToken(null);
      const scope = getRequestCoordinatorScope();
      const generation = sessionGenerationRef.current;
      const retry = (retryAfterSec?: number) => {
        const delay = Number.isFinite(retryAfterSec) && Number(retryAfterSec) > 0
          ? Number(retryAfterSec)
          : Math.min(60, 10 * 2 ** Math.min(retryCount++, 3));
        scopeRetryRef.current = window.setTimeout(onScopeRefresh, delay * 1000);
      };
      void apiClient.getCurrentUser().then(response => {
        if (generation !== sessionGenerationRef.current || response.code === "REQUEST_SCOPE_CHANGED") return;
        if (response.success && response.data) {
          const payload = authPayloadFromResponseData(response.data);
          if (payload?.user && isRequestCoordinatorUserCurrent(normalizeUser({ ...payload.user, auth: payload.auth || null }))) {
            retryCount = 0;
            setAuthStateFromPayload(payload);
            return;
          }
        }
        if (scope !== getRequestCoordinatorScope()) return;
        if (response.status === 403 || response.status === 429 || response.status === 0 || (response.status && response.status >= 500)) { retry(response.retryAfterSec); return; }
        if (!response.success || !setAuthStateFromPayload(authPayloadFromResponseData(response.data))) clearSession();
      }).catch(() => { if (generation === sessionGenerationRef.current && scope === getRequestCoordinatorScope()) retry(); });
    };
    window.addEventListener("auth:logout", onAuthLogout);
    window.addEventListener("auth:scope-refresh", onScopeRefresh);

    return () => {
      if (scopeRetryRef.current !== null) window.clearTimeout(scopeRetryRef.current);
      window.removeEventListener("auth:logout", onAuthLogout);
      window.removeEventListener("auth:scope-refresh", onScopeRefresh);
    };
  }, []);

  useEffect(() => {
    if (DISABLE_E2E_AUTH_POLLING) {
      setIsLoading(false);
      setAuthBootstrapStatus(user ? "authenticated" : "unauthenticated");
      return;
    }

    if (!shouldBootstrapCurrentUser(location.pathname)) {
      setIsLoading(false);
      setAuthBootstrapStatus(user ? "authenticated" : "unauthenticated");
      return;
    }

    const recentlyLoaded =
      user &&
      (Date.now() - lastRefreshSuccessAtRef.current < AUTH_BOOTSTRAP_MIN_INTERVAL_MS ||
        Date.now() - lastRefreshAttemptAtRef.current < AUTH_BOOTSTRAP_MIN_INTERVAL_MS);
    if (recentlyLoaded) {
      setIsLoading(false);
      return;
    }
    if (user && isActivePrintSessionSuppressed()) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;
    (async () => {
      setIsLoading(true);
      try {
        await refresh();
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname, user]);

  const login = async (email: string, password: string) => {
    const generation = sessionGenerationRef.current;
    try {
      const result = await apiClient.login(email, password);
      if (generation !== sessionGenerationRef.current) return { success: false, error: "Session changed" };
      if (result.success && result.data?.user) {
        const auth = result.data.auth || null;
        setAuthStateFromPayload({ user: result.data.user, auth });
        return { success: true, sessionStage: auth?.sessionStage || "ACTIVE" };
      }
      return { success: false, error: result.error || "Invalid email or password" };
    } catch (e: any) {
      return { success: false, error: e?.message || "Login failed" };
    }
  };

  const logout = () => {
    clearSession();
    void apiClient.logoutSession().catch(() => {
      // Local session state is already cleared; server logout is best effort.
    });
  };

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      pendingAuth,
      isLoading,
      authReady: !isLoading,
      authBootstrapStatus,
      isAuthenticated: !!user && user.auth?.sessionStage !== "MFA_BOOTSTRAP",
      login,
      logout,
      refresh,
      completeMfaSession,
    }),
    [user, pendingAuth, isLoading, authBootstrapStatus]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
