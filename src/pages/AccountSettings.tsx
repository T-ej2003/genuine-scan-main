import React, { useEffect, useState } from "react";
import QRCode from "qrcode";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";

type AdminMfaStatus = {
  required: boolean;
  sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
  enrolled: boolean;
  enabled: boolean;
  backupCodesRemaining?: number;
  verifiedAt?: string | null;
  lastUsedAt?: string | null;
};

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
  const [rotatedBackupCodes, setRotatedBackupCodes] = useState<string[] | null>(null);

  const isAdminUser = user?.role === "super_admin" || user?.role === "licensee_admin";

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
      if (!res.success) throw new Error(res.error || "Update failed");

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
      if (!res.success) throw new Error(res.error || "Password change failed");

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

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Account Settings</h1>
          <p className="text-muted-foreground">Manage your profile and security.</p>
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
                <Button type="submit" disabled={profileLoading}>
                  {profileLoading ? "Saving..." : "Save changes"}
                </Button>
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
                <Button type="submit" disabled={passwordLoading}>
                  {passwordLoading ? "Updating..." : "Update password"}
                </Button>
              </div>
            </form>
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
                <div className="grid gap-6 lg:grid-cols-2">
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
