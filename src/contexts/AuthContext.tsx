import React, { createContext, useContext, useEffect, useMemo, useState, ReactNode } from "react";
import { useLocation } from "react-router-dom";

import { shouldBootstrapCurrentUser } from "@/contexts/auth-bootstrap";
import apiClient from "@/lib/api-client";
import type { AuthState, PendingAuthSession, User } from "@/types";

interface AuthContextType {
  user: User | null;
  pendingAuth: PendingAuthSession | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string; sessionStage?: "ACTIVE" | "MFA_BOOTSTRAP" }>;
  logout: () => void;
  refresh: () => Promise<void>;
  completeMfaSession: (payload: { user?: any; auth?: AuthState | null }) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

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

  const clearSession = () => {
    setUser(null);
    setPendingAuth(null);
    apiClient.logout();
  };

  const completeMfaSession = (payload: { user?: any; auth?: AuthState | null }) => {
    if (!payload.user) {
      clearSession();
      return;
    }

    setPendingAuth(null);
    setUser(normalizeUser({ ...payload.user, auth: payload.auth || payload.user?.auth || null }));
  };

  const setAuthStateFromPayload = (payload: { user?: any; auth?: AuthState | null } | null) => {
    if (!payload?.user) {
      clearSession();
      return;
    }

    const auth = payload.auth || payload.user?.auth || null;
    const normalized = normalizeUser({ ...payload.user, auth });

    if (auth?.sessionStage === "MFA_BOOTSTRAP") {
      setUser(null);
      setPendingAuth({ user: normalized, auth });
      return;
    }

    setPendingAuth(null);
    setUser(normalized);
  };

  const refresh = async () => {
    const res = await apiClient.getCurrentUser();
    if (!res.success || !res.data) {
      clearSession();
      return;
    }

    setAuthStateFromPayload({ user: res.data, auth: (res.data as any)?.auth ?? null });
  };

  useEffect(() => {
    const onAuthLogout = () => clearSession();
    window.addEventListener("auth:logout", onAuthLogout);

    return () => window.removeEventListener("auth:logout", onAuthLogout);
  }, []);

  useEffect(() => {
    if (!shouldBootstrapCurrentUser(location.pathname)) {
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
  }, [location.pathname]);

  const login = async (email: string, password: string) => {
    try {
      const result = await apiClient.login(email, password);
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
    apiClient.logoutSession().finally(() => clearSession());
  };

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      pendingAuth,
      isLoading,
      isAuthenticated: !!user && user.auth?.sessionStage !== "MFA_BOOTSTRAP",
      login,
      logout,
      refresh,
      completeMfaSession,
    }),
    [user, pendingAuth, isLoading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
