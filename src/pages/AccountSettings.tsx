import React, { useEffect, useState } from "react";
import QRCode from "qrcode";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import { AdminMfaCard } from "@/features/account-settings/AdminMfaCard";
import { PasswordSettingsCard } from "@/features/account-settings/PasswordSettingsCard";
import { ProfileSettingsCard } from "@/features/account-settings/ProfileSettingsCard";
import { SessionSecurityCard } from "@/features/account-settings/SessionSecurityCard";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  isWebAuthnSupported,
  startAdminWebAuthnAuthentication,
  startAdminWebAuthnRegistration,
} from "@/lib/webauthn";
import {
  type ActiveSessionItem,
  type AdminMfaStatus,
  type BrowserStorageSummary,
  type SessionSecuritySummary,
  readBrowserStorageSummary,
  STORAGE_RISK_KEYS,
} from "@/features/account-settings/types";

export default function AccountSettings() {
  const { user, refresh } = useAuth();
  const { toast } = useToast();

  const [profileLoading, setProfileLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [mfaLoading, setMfaLoading] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");

  const [mfaStatus, setMfaStatus] = useState<AdminMfaStatus | null>(null);
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauthUri: string; backupCodes: string[] } | null>(null);
  const [mfaQrDataUrl, setMfaQrDataUrl] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaDisablePassword, setMfaDisablePassword] = useState("");
  const [mfaDisableCode, setMfaDisableCode] = useState("");
  const [mfaRotateCode, setMfaRotateCode] = useState("");
  const [webauthnLabel, setWebauthnLabel] = useState("");
  const [removingWebAuthnId, setRemovingWebAuthnId] = useState<string | null>(null);
  const [rotatedBackupCodes, setRotatedBackupCodes] = useState<string[] | null>(null);
  const [sessions, setSessions] = useState<ActiveSessionItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);
  const [revokeAllLoading, setRevokeAllLoading] = useState(false);
  const [storageSummary, setStorageSummary] = useState<BrowserStorageSummary>(() => readBrowserStorageSummary());
  const [sessionSecuritySummary, setSessionSecuritySummary] = useState<SessionSecuritySummary | null>(null);

  const isAdminUser = user?.role === "super_admin" || user?.role === "licensee_admin";
  const webauthnAvailable = isWebAuthnSupported();

  const loadMfaStatus = async () => {
    if (!isAdminUser) return;
    const response = await apiClient.getAdminMfaStatus();
    if (response.success && response.data) {
      setMfaStatus(response.data);
    }
  };

  const refreshStorageSummary = () => {
    setStorageSummary(readBrowserStorageSummary());
  };

  const loadSessions = async () => {
    setSessionsLoading(true);
    try {
      const response = await apiClient.listSessions();
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not load active sessions.");
      }
      setSessions(response.data.items || []);
      setSessionSecuritySummary(response.data.summary || null);
    } catch (error: any) {
      toast({
        title: "Could not load sessions",
        description: error?.message || "Please refresh and try again.",
        variant: "destructive",
      });
    } finally {
      setSessionsLoading(false);
      refreshStorageSummary();
    }
  };

  useEffect(() => {
    setName(user?.name || "");
    setEmail(user?.email || "");
  }, [user?.name, user?.email]);

  useEffect(() => {
    void loadMfaStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdminUser]);

  useEffect(() => {
    void loadSessions();
    refreshStorageSummary();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => {
    if (!mfaSetup?.otpauthUri) {
      setMfaQrDataUrl("");
      return;
    }

    let active = true;
    void QRCode.toDataURL(mfaSetup.otpauthUri, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 220,
    }).then((value: string) => {
      if (active) setMfaQrDataUrl(value);
    }).catch(() => {
      if (active) setMfaQrDataUrl("");
    });

    return () => {
      active = false;
    };
  }, [mfaSetup?.otpauthUri]);

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (profileLoading) return;

    const n = name.trim();
    const em = email.trim().toLowerCase();

    if (!n || n.length < 2) {
      toast({ title: "Invalid name", description: "Name must be at least 2 characters.", variant: "destructive" });
      return;
    }
    if (!em || !em.includes("@")) {
      toast({ title: "Invalid email", description: "Enter a valid email address.", variant: "destructive" });
      return;
    }

    setProfileLoading(true);
    try {
      const res = await apiClient.updateMyProfile({ name: n, email: em });
      if (!res.success) {
        if (res.code === "STEP_UP_REQUIRED") return;
        throw new Error(res.error || "Update failed");
      }

      const emailChange = (res.data as any)?.emailChange;
      if (emailChange?.verificationRequired && emailChange?.pendingEmail) {
        toast({
          title: "Check your email",
          description: `Confirm ${emailChange.pendingEmail} from the verification message before the change goes live.`,
        });
      } else {
        toast({ title: "Saved", description: "Your profile has been updated." });
      }
      await refresh();
    } catch (e: any) {
      toast({ title: "Save failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setProfileLoading(false);
    }
  };

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passwordLoading) return;

    if (!currentPassword) {
      toast({ title: "Missing current password", description: "Enter your current password.", variant: "destructive" });
      return;
    }
    if (!newPassword || newPassword.length < 8) {
      toast({ title: "Weak password", description: "New password must be at least 8 characters.", variant: "destructive" });
      return;
    }
    if (newPassword !== confirmNewPassword) {
      toast({ title: "Passwords do not match", description: "Confirm the new password correctly.", variant: "destructive" });
      return;
    }

    setPasswordLoading(true);
    try {
      const res = await apiClient.changeMyPassword({ currentPassword, newPassword });
      if (!res.success) {
        if (res.code === "STEP_UP_REQUIRED") return;
        throw new Error(res.error || "Password change failed");
      }

      toast({ title: "Password updated", description: "Your password has been changed successfully." });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
    } catch (e: any) {
      toast({ title: "Failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setPasswordLoading(false);
    }
  };

  const beginMfaSetup = async () => {
    setMfaLoading(true);
    try {
      const response = await apiClient.beginAdminMfaSetup();
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not begin MFA setup.");
      }
      setMfaSetup(response.data);
      setRotatedBackupCodes(null);
    } catch (e: any) {
      toast({ title: "Extra protection setup failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setMfaLoading(false);
    }
  };

  const confirmMfaSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaLoading(true);
    try {
      const response = await apiClient.confirmAdminMfaSetup(mfaCode.trim());
      if (!response.success) {
        throw new Error(response.error || "Could not confirm MFA setup.");
      }
      toast({ title: "Extra protection enabled", description: "Your admin account now has extra sign-in protection." });
      setMfaCode("");
      setMfaSetup(null);
      await loadMfaStatus();
      await refresh();
    } catch (e: any) {
      toast({ title: "Confirmation failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setMfaLoading(false);
    }
  };

  const rotateBackupCodes = async () => {
    setMfaLoading(true);
    try {
      const response = await apiClient.rotateAdminMfaBackupCodes(mfaRotateCode.trim());
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not rotate backup codes.");
      }
      setRotatedBackupCodes(response.data.backupCodes || []);
      setMfaRotateCode("");
      await loadMfaStatus();
      toast({ title: "Backup codes rotated", description: "Store the new backup codes somewhere safe now." });
    } catch (e: any) {
      toast({ title: "Rotation failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setMfaLoading(false);
    }
  };

  const disableMfa = async () => {
    setMfaLoading(true);
    try {
      const response = await apiClient.disableAdminMfa({
        currentPassword: mfaDisablePassword,
        code: mfaDisableCode.trim(),
      });
      if (!response.success) {
        throw new Error(response.error || "Could not disable MFA.");
      }
      setMfaDisablePassword("");
      setMfaDisableCode("");
      setMfaSetup(null);
      setRotatedBackupCodes(null);
      await loadMfaStatus();
      toast({
        title: "Extra protection disabled",
        description: "Extra sign-in protection is off for this account. The next admin sign-in will require setup again.",
      });
    } catch (e: any) {
      toast({ title: "Disable failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setMfaLoading(false);
    }
  };

  const beginWebAuthnSetup = async () => {
    setMfaLoading(true);
    try {
      const beginResponse = await apiClient.beginAdminWebAuthnSetup();
      if (!beginResponse.success || !beginResponse.data) {
        if (beginResponse.code === "STEP_UP_REQUIRED") return;
        throw new Error(beginResponse.error || "Could not start passkey setup.");
      }

      const registration = await startAdminWebAuthnRegistration(
        beginResponse.data,
        webauthnLabel.trim() || `${window.navigator.platform || "This device"} security key`
      );
      const finishResponse = await apiClient.completeAdminWebAuthnSetup(registration);
      if (!finishResponse.success) {
        if (finishResponse.code === "STEP_UP_REQUIRED") return;
        throw new Error(finishResponse.error || "Could not save the passkey.");
      }

      setWebauthnLabel("");
      await loadMfaStatus();
      await refresh();
      toast({
        title: "Passkey added",
        description: "Your passkey is ready and will be preferred for future admin verification when available.",
      });
    } catch (error: any) {
      toast({
        title: "Passkey setup failed",
        description: error?.message || "Could not add this passkey.",
        variant: "destructive",
      });
    } finally {
      setMfaLoading(false);
    }
  };

  const verifyWithWebAuthn = async () => {
    setMfaLoading(true);
    try {
      const beginResponse = await apiClient.beginAdminWebAuthnChallenge();
      if (!beginResponse.success || !beginResponse.data) {
        throw new Error(beginResponse.error || "Could not start passkey verification.");
      }

      const assertion = await startAdminWebAuthnAuthentication(beginResponse.data);
      const finishResponse = await apiClient.completeAdminWebAuthnChallenge(assertion);
      if (!finishResponse.success) {
        throw new Error(finishResponse.error || "Could not verify the passkey.");
      }

      await refresh();
      await loadMfaStatus();
      toast({
        title: "Verification refreshed",
        description: "Your passkey was accepted for admin verification.",
      });
    } catch (error: any) {
      toast({
        title: "Verification failed",
        description: error?.message || "Could not verify the passkey.",
        variant: "destructive",
      });
    } finally {
      setMfaLoading(false);
    }
  };

  const removeWebAuthnCredential = async (credentialId: string) => {
    setRemovingWebAuthnId(credentialId);
    try {
      const response = await apiClient.deleteAdminWebAuthnCredential(credentialId);
      if (!response.success) {
        if (response.code === "STEP_UP_REQUIRED") return;
        throw new Error(response.error || "Could not remove the passkey.");
      }

      await loadMfaStatus();
      toast({
        title: "Passkey removed",
        description: "That passkey can no longer be used for admin verification.",
      });
    } catch (error: any) {
      toast({
        title: "Removal failed",
        description: error?.message || "Could not remove the passkey.",
        variant: "destructive",
      });
    } finally {
      setRemovingWebAuthnId(null);
    }
  };

  const revokeSession = async (sessionId: string, current: boolean) => {
    setRevokingSessionId(sessionId);
    try {
      const response = await apiClient.revokeSession(sessionId);
      if (!response.success) {
        throw new Error(response.error || "Could not revoke this session.");
      }

      toast({
        title: current ? "Current device signed out" : "Session revoked",
        description: current
          ? "This device session was revoked and will close immediately."
          : "That device can no longer refresh its session.",
      });

      if (current || response.data?.currentSessionRevoked) {
        window.dispatchEvent(new Event("auth:logout"));
        return;
      }

      await loadSessions();
    } catch (error: any) {
      toast({
        title: "Session revoke failed",
        description: error?.message || "Please try again.",
        variant: "destructive",
      });
    } finally {
      setRevokingSessionId(null);
    }
  };

  const revokeAllSessions = async () => {
    setRevokeAllLoading(true);
    try {
      const response = await apiClient.revokeAllSessions();
      if (!response.success) {
        throw new Error(response.error || "Could not revoke active sessions.");
      }

      toast({
        title: "All sessions revoked",
        description: `Revoked ${response.data?.revokedCount ?? 0} active session(s). This device will sign out now.`,
      });
      window.dispatchEvent(new Event("auth:logout"));
    } catch (error: any) {
      toast({
        title: "Bulk revoke failed",
        description: error?.message || "Please try again.",
        variant: "destructive",
      });
    } finally {
      setRevokeAllLoading(false);
    }
  };

  const currentSession = sessions.find((session) => session.current) || null;
  const currentSessionSecurity = currentSession?.security || null;
  const storagePostureHealthy =
    storageSummary.localStorageKeys.every((key) => !STORAGE_RISK_KEYS.includes(key)) &&
    storageSummary.sessionStorageKeys.every((key) => !["auth_token", "auth_user"].includes(key));
  const currentDeviceTrustLabel =
    user?.auth?.sessionStage !== "ACTIVE"
      ? "Step-up pending"
      : user?.auth?.authAssurance === "ADMIN_MFA"
        ? "Extra protection verified"
        : isAdminUser
          ? currentSessionSecurity?.riskLevel === "HIGH" || currentSessionSecurity?.riskLevel === "CRITICAL"
            ? "Admin session needs review"
            : "Password-verified admin session"
          : "Cookie-bound operator session";

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Account & Security</h1>
          <p className="text-muted-foreground">Manage your profile, password, and sign-in safety.</p>
        </div>

        <ProfileSettingsCard
          email={email}
          name={name}
          onSubmit={saveProfile}
          profileLoading={profileLoading}
          setEmail={setEmail}
          setName={setName}
          user={user ? { emailVerifiedAt: user.emailVerifiedAt, pendingEmail: user.pendingEmail } : null}
        />

        <PasswordSettingsCard
          changePassword={changePassword}
          confirmNewPassword={confirmNewPassword}
          currentPassword={currentPassword}
          newPassword={newPassword}
          passwordLoading={passwordLoading}
          setConfirmNewPassword={setConfirmNewPassword}
          setCurrentPassword={setCurrentPassword}
          setNewPassword={setNewPassword}
          stepUpMethod={user?.auth?.stepUpMethod}
          stepUpRequired={user?.auth?.stepUpRequired}
        />

        <SessionSecurityCard
          currentDeviceTrustLabel={currentDeviceTrustLabel}
          currentSession={currentSession}
          currentSessionSecurity={currentSessionSecurity}
          isAdminUser={isAdminUser}
          loadSessions={loadSessions}
          revokeAllLoading={revokeAllLoading}
          revokeAllSessions={revokeAllSessions}
          revokeSession={revokeSession}
          revokingSessionId={revokingSessionId}
          sessionSecuritySummary={sessionSecuritySummary}
          sessions={sessions}
          sessionsLoading={sessionsLoading}
          storagePostureHealthy={storagePostureHealthy}
          storageSummary={storageSummary}
          userAuth={user?.auth}
        />

        <AdminMfaCard
          beginMfaSetup={beginMfaSetup}
          beginWebAuthnSetup={beginWebAuthnSetup}
          confirmMfaSetup={confirmMfaSetup}
          disableMfa={disableMfa}
          disablePassword={mfaDisablePassword}
          disableCode={mfaDisableCode}
          isAdminUser={isAdminUser}
          mfaCode={mfaCode}
          mfaLoading={mfaLoading}
          mfaQrDataUrl={mfaQrDataUrl}
          mfaRotateCode={mfaRotateCode}
          mfaSetup={mfaSetup}
          mfaStatus={mfaStatus}
          onDisableCodeChange={setMfaDisableCode}
          onDisablePasswordChange={setMfaDisablePassword}
          onMfaCodeChange={setMfaCode}
          onRotateCodeChange={setMfaRotateCode}
          onSetMfaSetup={setMfaSetup}
          onWebauthnLabelChange={setWebauthnLabel}
          removeWebAuthnCredential={removeWebAuthnCredential}
          removingWebAuthnId={removingWebAuthnId}
          rotateBackupCodes={rotateBackupCodes}
          rotatedBackupCodes={rotatedBackupCodes}
          verifyWithWebAuthn={verifyWithWebAuthn}
          webauthnAvailable={webauthnAvailable}
          webauthnLabel={webauthnLabel}
        />
      </div>
    </DashboardLayout>
  );
}
