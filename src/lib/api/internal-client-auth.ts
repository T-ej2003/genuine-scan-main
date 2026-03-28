import { type ApiClientCore, type ApiResponse } from "@/lib/api/internal-client-core";

export const createAuthApi = (core: ApiClientCore) => ({
  async login(email: string, password: string) {
    const response = await core.request<{
      user?: any;
      auth?: {
        sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
        authAssurance: "PASSWORD" | "ADMIN_MFA";
        mfaRequired: boolean;
        mfaEnrolled: boolean;
        authenticatedAt?: string | null;
        mfaVerifiedAt?: string | null;
        stepUpRequired?: boolean;
      };
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    return response;
  },

  async getCurrentUser() {
    return core.request("/auth/me");
  },

  async refreshSession() {
    return core.request<{ user: any; auth?: any }>("/auth/refresh", { method: "POST" });
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
      user?: any;
      auth?: {
        sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
        authAssurance: "PASSWORD" | "ADMIN_MFA";
        mfaRequired: boolean;
        mfaEnrolled: boolean;
        authenticatedAt?: string | null;
        mfaVerifiedAt?: string | null;
        stepUpRequired?: boolean;
      };
    }>("/auth/accept-invite", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return response;
  },

  async verifyEmail(token: string) {
    return core.request<{ verified: boolean; purpose: string; email: string }>("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
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

  async getAdminMfaStatus() {
    return core.request<{
      required: boolean;
      sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
      enrolled: boolean;
      enabled: boolean;
      backupCodesRemaining?: number;
      verifiedAt?: string | null;
      lastUsedAt?: string | null;
      createdAt?: string | null;
      updatedAt?: string | null;
    }>("/auth/mfa/status");
  },

  async beginAdminMfaSetup() {
    return core.request<{
      secret: string;
      otpauthUri: string;
      backupCodes: string[];
    }>("/auth/mfa/setup/begin", {
      method: "POST",
    });
  },

  async confirmAdminMfaSetup(code: string) {
    return core.request<{ user?: any; auth?: any; enabled?: boolean }>("/auth/mfa/setup/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  },

  async beginAdminMfaChallenge() {
    return core.request<{ ticket: string; expiresAt: string }>("/auth/mfa/challenge/begin", {
      method: "POST",
    });
  },

  async completeAdminMfaChallenge(ticket: string, code: string) {
    return core.request<{ user?: any; auth?: any }>("/auth/mfa/challenge/complete", {
      method: "POST",
      body: JSON.stringify({ ticket, code }),
    });
  },

  async rotateAdminMfaBackupCodes(code: string) {
    return core.request<{ backupCodes: string[] }>("/auth/mfa/backup-codes/rotate", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  },

  async disableAdminMfa(payload: { code: string; currentPassword: string }) {
    return core.request<{ enabled: boolean }>("/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },
});

export type AuthApi = ReturnType<typeof createAuthApi>;
export type { ApiResponse };
