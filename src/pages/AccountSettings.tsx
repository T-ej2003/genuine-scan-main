import React, { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";
import { MfaEnrollmentPanel, type MfaEnrollmentData } from "@/components/auth/MfaEnrollmentPanel";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck } from "lucide-react";

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
  const [mfaStatus, setMfaStatus] = useState<null | {
    enrolled: boolean;
    enabled: boolean;
    verifiedAt: string | null;
    lastUsedAt: string | null;
    backupCodesRemaining: number;
    createdAt: string | null;
    updatedAt: string | null;
  }>(null);
  const [mfaSetup, setMfaSetup] = useState<MfaEnrollmentData | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  const mfaRequiredForRole =
    user?.role === "super_admin" || user?.role === "licensee_admin" || user?.role === "manufacturer";

  useEffect(() => {
    setName(user?.name || "");
    setEmail(user?.email || "");
  }, [user?.name, user?.email]);

  const loadMfaStatus = async () => {
    const res = await apiClient.getMfaStatus();
    if (res.success && res.data) {
      setMfaStatus(res.data);
    }
  };

  useEffect(() => {
    if (!user || !mfaRequiredForRole) return;
    void loadMfaStatus();
  }, [user, mfaRequiredForRole]);

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

      toast({ title: "Saved", description: "Your profile has been updated." });

      // Refresh the AuthContext user so UI updates immediately
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
    if (!newPassword || newPassword.length < 6) {
      toast({ title: "Weak password", description: "New password must be at least 6 characters.", variant: "destructive" });
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

  const beginMfaEnrollment = async () => {
    setMfaLoading(true);
    try {
      const res = await apiClient.beginMfaSetup();
      if (!res.success || !res.data) {
        throw new Error(res.error || "Failed to initialize MFA setup");
      }
      setMfaSetup(res.data);
      setMfaCode("");
      toast({
        title: mfaStatus?.enabled ? "MFA reset started" : "MFA setup started",
        description: "Scan the QR, store the backup codes, and enter the authenticator code to finish.",
      });
    } catch (e: any) {
      toast({ title: "MFA setup failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setMfaLoading(false);
    }
  };

  const confirmMfaEnrollment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaSetup) return;
    setMfaLoading(true);
    try {
      const res = await apiClient.confirmMfaSetup(mfaCode.trim());
      if (!res.success) {
        throw new Error(res.error || "Failed to enable MFA");
      }
      setMfaSetup(null);
      setMfaCode("");
      await loadMfaStatus();
      toast({ title: "MFA enabled", description: "This account now uses authenticator-based sign-in." });
    } catch (e: any) {
      toast({ title: "MFA enable failed", description: e?.message || "Error", variant: "destructive" });
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
              Update your name and email address.
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

        {mfaRequiredForRole ? (
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2 font-semibold">
                Multi-factor authentication
                <Badge className="bg-slate-900 text-white hover:bg-slate-900">Required</Badge>
              </div>
              <div className="text-sm text-muted-foreground">
                Super admins, licensee admins, and manufacturers must use an authenticator app plus backup codes.
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {mfaStatus?.enabled ? (
                <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950">
                  <ShieldCheck className="h-4 w-4 text-emerald-700" />
                  <AlertTitle>MFA is active</AlertTitle>
                  <AlertDescription>
                    Last used {mfaStatus.lastUsedAt ? new Date(mfaStatus.lastUsedAt).toLocaleString() : "not yet"}.
                    Backup codes remaining: {mfaStatus.backupCodesRemaining}.
                  </AlertDescription>
                </Alert>
              ) : (
                <Alert className="border-amber-200 bg-amber-50 text-amber-950">
                  <AlertTitle>MFA is not enabled yet</AlertTitle>
                  <AlertDescription>
                    Finish setup now so your next sign-in is not blocked by the required MFA policy.
                  </AlertDescription>
                </Alert>
              )}

              {mfaSetup ? (
                <form className="space-y-4" onSubmit={confirmMfaEnrollment}>
                  <MfaEnrollmentPanel
                    title={mfaStatus?.enabled ? "Reset authenticator setup" : "Set up your authenticator app"}
                    description="Scan the QR, save the backup codes, then enter the current 6-digit code from your app."
                    setup={mfaSetup}
                    code={mfaCode}
                    onCodeChange={setMfaCode}
                    confirming={mfaLoading}
                    error={null}
                  />

                  <div className="flex flex-col gap-3 sm:flex-row">
                    <Button type="submit" className="sm:flex-1" disabled={mfaLoading || mfaCode.trim().length < 6}>
                      {mfaLoading ? "Enabling..." : "Enable MFA"}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      className="sm:flex-1"
                      disabled={mfaLoading}
                      onClick={() => {
                        setMfaSetup(null);
                        setMfaCode("");
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </form>
              ) : (
                <div className="flex flex-col gap-3 sm:flex-row">
                  <Button type="button" onClick={beginMfaEnrollment} disabled={mfaLoading}>
                    {mfaLoading ? "Preparing..." : mfaStatus?.enabled ? "Reset MFA" : "Set up MFA"}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
