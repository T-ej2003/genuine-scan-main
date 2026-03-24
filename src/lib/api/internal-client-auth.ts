import { type ApiClientCore, type ApiResponse } from "@/lib/api/internal-client-core";

export const createAuthApi = (core: ApiClientCore) => ({
  async login(email: string, password: string) {
    const response = await core.request<{
      token?: string;
      user?: any;
      email?: string;
      role?: string;
      riskScore?: number;
      riskLevel?: string;
      reasons?: string[];
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    if (response.success && response.data?.token) core.setToken(response.data.token);
    return response;
  },

  async getCurrentUser() {
    return core.request("/auth/me");
  },

  async refreshSession() {
    const response = await core.request<{ token: string; user: any }>("/auth/refresh", { method: "POST" });
    if (response.success && response.data?.token) core.setToken(response.data.token);
    return response;
  },

  async logoutSession() {
    const response = await core.request("/auth/logout", { method: "POST" });
    core.logout();
    return response;
  },

  async forgotPassword(email: string) {
    return core.request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
  },

  async resetPassword(token: string, password: string) {
    return core.request("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
  },

  async acceptInvite(payload: { token: string; password: string; name?: string }) {
    const response = await core.request<{
      token?: string;
      user?: any;
      email?: string;
      role?: string;
      riskScore?: number;
      riskLevel?: string;
      reasons?: string[];
    }>("/auth/accept-invite", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    if (response.success && response.data?.token) core.setToken(response.data.token);
    return response;
  },

  async getInvitePreview(token: string) {
    const query = `?token=${encodeURIComponent(token)}`;
    return core.request<{
      email: string;
      role: string;
      expiresAt: string;
      licenseeName: string | null;
      requiresConnector: boolean;
    }>(`/auth/invite-preview${query}`);
  },

  async getConnectorReleaseManifest() {
    return core.request<{
      productName: string;
      latestVersion: string;
      supportPath: string;
      helpPath: string;
      setupGuidePath: string;
      releases: Array<{
        version: string;
        publishedAt: string;
        summary: string;
        notes: string[];
        platforms: {
          macos: null | {
            platform: "macos";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
          };
          windows: null | {
            platform: "windows";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
          };
        };
      }>;
    }>("/public/connector/releases");
  },

  async getLatestConnectorRelease() {
    return core.request<{
      productName: string;
      latestVersion: string;
      supportPath: string;
      helpPath: string;
      setupGuidePath: string;
      release: {
        version: string;
        publishedAt: string;
        summary: string;
        notes: string[];
        platforms: {
          macos: null | {
            platform: "macos";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
          };
          windows: null | {
            platform: "windows";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
          };
        };
      };
    }>("/public/connector/releases/latest");
  },

  async inviteUser(payload: {
    email: string;
    role: string;
    name?: string;
    licenseeId?: string;
    manufacturerId?: string;
    allowExistingInvitedUser?: boolean;
  }) {
    return core.request("/auth/invite", { method: "POST", body: JSON.stringify(payload) });
  },
});

export type AuthApi = ReturnType<typeof createAuthApi>;
export type { ApiResponse };
