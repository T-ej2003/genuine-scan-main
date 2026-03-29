import React, { useEffect, useState } from "react";
import QRCode from "qrcode";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { ActionButton } from "@/components/ui/action-button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { createUiActionState } from "@/lib/ui-actions";
import {
  isWebAuthnSupported,
  startAdminWebAuthnAuthentication,
  startAdminWebAuthnRegistration,
  type AdminWebAuthnCredentialSummary,
} from "@/lib/webauthn";

type AdminMfaStatus = {
  required: boolean;
  sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
  enrolled: boolean;
  enabled: boolean;
  totpEnabled?: boolean;
  hasWebAuthn?: boolean;
  methods?: Array<"TOTP" | "WEBAUTHN">;
  preferredMethod?: "TOTP" | "WEBAUTHN" | null;
  backupCodesRemaining?: number;
  verifiedAt?: string | null;
  lastUsedAt?: string | null;
  webauthnCredentials?: AdminWebAuthnCredentialSummary[];
};

type ActiveSession = {
  id: string;
  current: boolean;
  createdAt: string;
  lastUsedAt?: string | null;
  expiresAt: string;
  authenticatedAt?: string | null;
  mfaVerifiedAt?: string | null;
  userAgent?: string | null;
  ipHash?: string | null;
};

export default function AccountSettings() {
  const { user, refresh, logout } = useAuth();
  const { toast } = useToast();

  const [profileLoading, setProfileLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [mfaLoading, setMfaLoading] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);

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
  const [sessions, setSessions] = useState<ActiveSession[]>([]);

  const isAdminUser = user?.role === "super_admin" || user?.role === "licensee_admin";
  const webauthnAvailable = isWebAuthnSupported();

  const loadSessions = async () => {
    if (!user) {
      setSessions([]);
      return;
    }

    setSessionsLoading(true);
    try {
      const response = await apiClient.listSessions();
      if (response.success && response.data) {
        setSessions(response.data.items || []);
      }
    } finally {
      setSessionsLoading(false);
    }
  };

  const loadMfaStatus = async () => {
    if (!isAdminUser) return;
    const response = await apiClient.getAdminMfaStatus();
    if (response.success && response.data) {
      setMfaStatus(response.data);
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
      await loadSessions();
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

  const revokeSession = async (sessionId: string) => {
    setRevokingSessionId(sessionId);
    try {
      const response = await apiClient.revokeSession(sessionId);
      if (!response.success) {
        if (response.code === "STEP_UP_REQUIRED") return;
        throw new Error(response.error || "Could not revoke session.");
      }

      if (response.data?.currentSessionRevoked) {
        toast({
          title: "Current session revoked",
          description: "This browser session was closed. Sign in again if you still need access.",
        });
        logout();
        return;
      }

      toast({ title: "Session revoked", description: "That device can no longer use this session." });
      await loadSessions();
    } catch (error: any) {
      toast({
        title: "Session revoke failed",
        description: error?.message || "Could not revoke that session.",
        variant: "destructive",
      });
    } finally {
      setRevokingSessionId(null);
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
      toast({ title: "MFA setup failed", description: e?.message || "Error", variant: "destructive" });
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
      toast({ title: "MFA enabled", description: "Your admin MFA is now active." });
      setMfaCode("");
      setMfaSetup(null);
      await loadMfaStatus();
      await refresh();
    } catch (e: any) {
      toast({ title: "MFA confirmation failed", description: e?.message || "Error", variant: "destructive" });
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
        title: "MFA disabled",
        description: "MFA is off for this account. The next admin sign-in will require setup again.",
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
        throw new Error(beginResponse.error || "Could not start WebAuthn setup.");
      }

      const registration = await startAdminWebAuthnRegistration(
        beginResponse.data,
        webauthnLabel.trim() || `${window.navigator.platform || "This device"} security key`
      );
      const finishResponse = await apiClient.completeAdminWebAuthnSetup(registration);
      if (!finishResponse.success) {
        if (finishResponse.code === "STEP_UP_REQUIRED") return;
        throw new Error(finishResponse.error || "Could not save the WebAuthn credential.");
      }

      setWebauthnLabel("");
      await loadMfaStatus();
      await refresh();
      toast({
        title: "Security key added",
        description: "WebAuthn is ready and will be preferred for future admin verification when available.",
      });
    } catch (error: any) {
      toast({
        title: "Security key setup failed",
        description: error?.message || "Could not add this WebAuthn credential.",
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
        throw new Error(beginResponse.error || "Could not start WebAuthn verification.");
      }

      const assertion = await startAdminWebAuthnAuthentication(beginResponse.data);
      const finishResponse = await apiClient.completeAdminWebAuthnChallenge(assertion);
      if (!finishResponse.success) {
        throw new Error(finishResponse.error || "Could not verify the WebAuthn credential.");
      }

      await refresh();
      await loadMfaStatus();
      toast({
        title: "Verification refreshed",
        description: "Your WebAuthn credential was accepted for admin verification.",
      });
    } catch (error: any) {
      toast({
        title: "Verification failed",
        description: error?.message || "Could not verify the WebAuthn credential.",
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
        throw new Error(response.error || "Could not remove the WebAuthn credential.");
      }

      await loadMfaStatus();
      toast({
        title: "Security key removed",
        description: "That WebAuthn credential can no longer be used for admin verification.",
      });
    } catch (error: any) {
      toast({
        title: "Removal failed",
        description: error?.message || "Could not remove the WebAuthn credential.",
        variant: "destructive",
      });
    } finally {
      setRemovingWebAuthnId(null);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Account & Security</h1>
          <p className="text-muted-foreground">Manage your profile, sign-in safety, and active sessions.</p>
        </div>

        <Card>
          <CardHeader className="pb-2">
            <div className="font-semibold">Profile</div>
            <div className="text-sm text-muted-foreground">
              Update your name. Email changes stay pending until you confirm them from your inbox.
            </div>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={saveProfile}>
              <div className="space-y-2">
                <Label>Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
              </div>

              <div className="space-y-2">
                <Label>Email</Label>
                <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
                {user?.pendingEmail ? (
                  <p className="text-sm text-amber-700">
                    Pending change: <strong>{user.pendingEmail}</strong>. Open the verification email to finish this update.
                  </p>
                ) : user?.emailVerifiedAt ? (
                  <p className="text-sm text-muted-foreground">Verified on {new Date(user.emailVerifiedAt).toLocaleString()}.</p>
                ) : (
                  <p className="text-sm text-amber-700">This account email is not verified yet.</p>
                )}
              </div>

              <div className="flex justify-end">
                <ActionButton
                  data-testid="account-save-profile"
                  type="submit"
                  state={profileLoading ? createUiActionState("pending", "Saving your latest profile details.") : createUiActionState("enabled")}
                  idleLabel="Save changes"
                  pendingLabel="Saving..."
                  showReasonBelow={false}
                />
              </div>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="font-semibold">Security</div>
            <div className="text-sm text-muted-foreground">
              Change your password. You will need your current password.
            </div>
          </CardHeader>
          <CardContent>
            {user?.auth?.stepUpRequired ? (
              <Alert className="mb-4 border-amber-200 bg-amber-50 text-amber-950">
                <AlertDescription>
                  Sensitive actions are locked until you confirm{" "}
                  {user.auth.stepUpMethod === "ADMIN_MFA" ? "your authenticator code" : "your current password"} again.
                </AlertDescription>
              </Alert>
            ) : null}
            <form className="space-y-4" onSubmit={changePassword}>
              <div className="space-y-2">
                <Label>Current password</Label>
                <Input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
              </div>

              <div className="space-y-2">
                <Label>New password</Label>
                <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
              </div>

              <div className="space-y-2">
                <Label>Confirm new password</Label>
                <Input type="password" value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)} />
              </div>

              <div className="flex justify-end">
                <ActionButton
                  data-testid="account-change-password"
                  type="submit"
                  state={
                    passwordLoading
                      ? createUiActionState("pending", "Saving your new password now.")
                      : createUiActionState("enabled")
                  }
                  idleLabel="Update password"
                  pendingLabel="Updating..."
                  showReasonBelow={false}
                />
              </div>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="font-semibold">Active Sessions</div>
            <div className="text-sm text-muted-foreground">
              Review browser sessions using this account and revoke the ones you do not recognize.
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {user?.auth?.sessionExpiresAt ? (
              <Alert>
                <AlertDescription>
                  Current session expires on {new Date(user.auth.sessionExpiresAt).toLocaleString()}.
                </AlertDescription>
              </Alert>
            ) : null}

            {sessionsLoading ? (
              <div className="text-sm text-muted-foreground">Loading active sessions...</div>
            ) : sessions.length === 0 ? (
              <div className="text-sm text-muted-foreground">No active sessions are available right now.</div>
            ) : (
              <div className="space-y-3">
                {sessions.map((session) => (
                  <div key={session.id} className="rounded-xl border p-4">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="space-y-1">
                        <div className="font-medium">
                          {session.current ? "Current browser session" : session.userAgent || "Saved browser session"}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Started {new Date(session.createdAt).toLocaleString()}.
                          {session.lastUsedAt ? ` Last used ${new Date(session.lastUsedAt).toLocaleString()}.` : ""}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          Expires {new Date(session.expiresAt).toLocaleString()}.
                          {session.mfaVerifiedAt ? ` MFA confirmed ${new Date(session.mfaVerifiedAt).toLocaleString()}.` : ""}
                        </div>
                      </div>

                      <Button
                        data-testid="account-revoke-session"
                        type="button"
                        variant={session.current ? "destructive" : "outline"}
                        disabled={revokingSessionId === session.id}
                        onClick={() => void revokeSession(session.id)}
                      >
                        {revokingSessionId === session.id
                          ? "Revoking..."
                          : session.current
                            ? "Sign out this browser"
                            : "Revoke session"}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {isAdminUser ? (
          <Card>
            <CardHeader className="pb-2">
              <div className="font-semibold">Admin MFA</div>
              <div className="text-sm text-muted-foreground">
                Sensitive admin actions stay locked behind a recent MFA confirmation.
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {mfaStatus ? (
                <Alert>
                  <AlertDescription>
                    {mfaStatus.enabled
                      ? `MFA is enabled. Backup codes remaining: ${mfaStatus.backupCodesRemaining ?? 0}.`
                      : "MFA is not enabled for this admin account yet."}
                    {mfaStatus.preferredMethod ? ` Preferred method: ${mfaStatus.preferredMethod === "WEBAUTHN" ? "Security key / passkey" : "Authenticator app"}.` : ""}
                    {mfaStatus.lastUsedAt ? ` Last used: ${new Date(mfaStatus.lastUsedAt).toLocaleString()}.` : ""}
                  </AlertDescription>
                </Alert>
              ) : null}

              {!mfaStatus?.enabled ? (
                <div className="space-y-4">
                  {!mfaSetup ? (
                    <Button onClick={() => void beginMfaSetup()} disabled={mfaLoading}>
                      {mfaLoading ? "Preparing..." : "Begin MFA setup"}
                    </Button>
                  ) : (
                    <form className="space-y-4" onSubmit={confirmMfaSetup}>
                      {mfaQrDataUrl ? (
                        <img src={mfaQrDataUrl} alt="Admin MFA QR code" className="h-52 w-52 rounded-xl border p-2" />
                      ) : null}
                      <div className="space-y-2">
                        <Label>Manual setup key</Label>
                        <Input value={mfaSetup.secret} readOnly className="font-mono text-sm" />
                      </div>
                      <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
                        <div className="font-medium">Backup codes</div>
                        <div className="mt-2 grid grid-cols-2 gap-2">
                          {mfaSetup.backupCodes.map((code) => (
                            <div key={code} className="rounded-lg border border-amber-200 bg-white px-3 py-2 font-mono text-xs">
                              {code}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label>Authenticator code</Label>
                        <Input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="123456" />
                      </div>
                      <div className="flex justify-end gap-3">
                        <Button type="button" variant="outline" onClick={() => setMfaSetup(null)} disabled={mfaLoading}>
                          Cancel
                        </Button>
                        <Button type="submit" disabled={mfaLoading}>
                          {mfaLoading ? "Confirming..." : "Enable MFA"}
                        </Button>
                      </div>
                    </form>
                  )}
                </div>
              ) : (
                <div className="grid gap-6 lg:grid-cols-3">
                  <div className="space-y-3 rounded-xl border p-4">
                    <div className="font-medium">Security keys / passkeys</div>
                    <div className="text-sm text-muted-foreground">
                      Prefer WebAuthn security keys when this browser supports them. Authenticator codes stay available as a fallback.
                    </div>
                    {webauthnAvailable ? (
                      <>
                        <div className="space-y-2">
                          <Label>Device label</Label>
                          <Input
                            value={webauthnLabel}
                            onChange={(e) => setWebauthnLabel(e.target.value)}
                            placeholder="Factory MacBook or Security key"
                          />
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Button onClick={() => void beginWebAuthnSetup()} disabled={mfaLoading}>
                            {mfaLoading ? "Preparing..." : "Add security key"}
                          </Button>
                          {mfaStatus?.hasWebAuthn ? (
                            <Button variant="outline" onClick={() => void verifyWithWebAuthn()} disabled={mfaLoading}>
                              {mfaLoading ? "Waiting..." : "Verify with security key"}
                            </Button>
                          ) : null}
                        </div>
                      </>
                    ) : (
                      <div className="text-sm text-muted-foreground">
                        This browser does not support WebAuthn security keys. You can still use the authenticator-app flow below.
                      </div>
                    )}

                    {mfaStatus?.webauthnCredentials?.length ? (
                      <div className="space-y-3">
                        {mfaStatus.webauthnCredentials.map((credential) => (
                          <div key={credential.id} className="rounded-xl border bg-muted/30 p-3">
                            <div className="flex items-start justify-between gap-3">
                              <div className="space-y-1">
                                <div className="font-medium">{credential.label}</div>
                                <div className="text-xs text-muted-foreground">
                                  {(credential.transports || []).length ? `Transports: ${credential.transports?.join(", ")}.` : "Security key enrolled."}
                                  {credential.lastUsedAt ? ` Last used ${new Date(credential.lastUsedAt).toLocaleString()}.` : ""}
                                </div>
                              </div>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={removingWebAuthnId === credential.id}
                                onClick={() => void removeWebAuthnCredential(credential.id)}
                              >
                                {removingWebAuthnId === credential.id ? "Removing..." : "Remove"}
                              </Button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-sm text-muted-foreground">No WebAuthn security keys are enrolled yet.</div>
                    )}
                  </div>

                  <div className="space-y-3 rounded-xl border p-4">
                    <div className="font-medium">Rotate backup codes</div>
                    <div className="text-sm text-muted-foreground">
                      Enter a current authenticator or backup code to issue a fresh backup-code set.
                    </div>
                    <Label>Current MFA code</Label>
                    <Input value={mfaRotateCode} onChange={(e) => setMfaRotateCode(e.target.value)} placeholder="123456 or ABCDE-12345" />
                    <Button onClick={() => void rotateBackupCodes()} disabled={mfaLoading}>
                      {mfaLoading ? "Rotating..." : "Rotate backup codes"}
                    </Button>
                    {rotatedBackupCodes?.length ? (
                      <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                        <div className="font-medium text-amber-950">New backup codes</div>
                        <div className="mt-3 grid grid-cols-2 gap-2">
                          {rotatedBackupCodes.map((code) => (
                            <div key={code} className="rounded-lg border border-amber-200 bg-white px-3 py-2 font-mono text-xs">
                              {code}
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>

                  <div className="space-y-3 rounded-xl border border-red-200 p-4">
                    <div className="font-medium text-red-900">Disable MFA</div>
                    <div className="text-sm text-red-900/80">
                      This is only for controlled recovery. The next admin sign-in will force MFA setup again.
                    </div>
                    <div className="space-y-2">
                      <Label>Current password</Label>
                      <Input type="password" value={mfaDisablePassword} onChange={(e) => setMfaDisablePassword(e.target.value)} />
                    </div>
                    <div className="space-y-2">
                      <Label>Current MFA code</Label>
                      <Input value={mfaDisableCode} onChange={(e) => setMfaDisableCode(e.target.value)} placeholder="123456 or ABCDE-12345" />
                    </div>
                    <Button variant="destructive" onClick={() => void disableMfa()} disabled={mfaLoading}>
                      {mfaLoading ? "Disabling..." : "Disable MFA"}
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
