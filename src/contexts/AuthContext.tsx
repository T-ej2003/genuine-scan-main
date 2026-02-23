import React, { createContext, useContext, useEffect, useMemo, useState, ReactNode } from "react";
import apiClient from "@/lib/api-client";
import type { User } from "@/types";

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const normalizeRole = (role: any): User["role"] => {
  const r = String(role || "").trim().toUpperCase();
  if (r === "SUPER_ADMIN" || r === "PLATFORM_SUPER_ADMIN") return "super_admin";
  if (r === "LICENSEE_ADMIN" || r === "ORG_ADMIN") return "licensee_admin";
  if (r === "MANUFACTURER" || r === "MANUFACTURER_ADMIN" || r === "MANUFACTURER_USER") return "manufacturer";
  // safest (least privilege)
  return "manufacturer";
};

function normalizeUser(u: any): User {
  const licenseeId = u.licenseeId ?? u.licensee?.id ?? undefined;
  return {
    id: String(u.id),
    email: String(u.email),
    name: String(u.name ?? ""),
    role: normalizeRole(u.role),
    licenseeId,
    createdAt: u.createdAt ?? new Date().toISOString(),
    isActive: typeof u.isActive === "boolean" ? u.isActive : true,
    deletedAt: u.deletedAt ?? null,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const clearSession = () => {
    setUser(null);
    apiClient.logout();
  };

  const setSessionUser = (u: any | null) => {
    if (!u) {
      clearSession();
      return;
    }
    const fixed = normalizeUser(u);
    setUser(fixed);
  };

  const refresh = async () => {
    const res = await apiClient.getCurrentUser(); // GET /auth/me
    if (!res.success || !res.data) {
      clearSession();
      return;
    }

    setSessionUser(res.data);
  };

  useEffect(() => {
    const onAuthLogout = () => clearSession();
    window.addEventListener("auth:logout", onAuthLogout);

    (async () => {
      setIsLoading(true);
      try {
        await refresh();
      } finally {
        setIsLoading(false);
      }
    })();

    return () => window.removeEventListener("auth:logout", onAuthLogout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const result = await apiClient.login(email, password);
      if (result.success && result.data?.user) {
        setSessionUser(result.data.user);
        return { success: true };
      }
      return { success: false, error: result.error || "Invalid email or password" };
    } catch (e: any) {
      return { success: false, error: e?.message || "Login failed" };
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    apiClient.logoutSession().finally(() => clearSession());
  };

  const value = useMemo<AuthContextType>(
    () => ({
      user,
      isLoading,
      isAuthenticated: !!user,
      login,
      logout,
      refresh,
    }),
    [user, isLoading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
