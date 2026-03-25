import React, { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

export default function AccountSettings() {
  const { user, refresh } = useAuth();
  const { toast } = useToast();

  const [profileLoading, setProfileLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");

  useEffect(() => {
    setName(user?.name || "");
    setEmail(user?.email || "");
  }, [user?.name, user?.email]);

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
      </div>
    </DashboardLayout>
  );
}
