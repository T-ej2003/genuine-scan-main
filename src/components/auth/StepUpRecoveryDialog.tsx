import React, { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { isWebAuthnSupported, startAdminWebAuthnAuthentication } from "@/lib/webauthn";
import type { StepUpMethod } from "@/types";

type StepUpEventDetail = {
  endpoint?: string;
  method?: string;
  message?: string;
  stepUpMethod?: StepUpMethod | null;
};
type AdminMfaInputMode = "authenticator" | "backup";

const defaultMessageForMethod = (method: StepUpMethod) =>
  method === "ADMIN_MFA"
    ? "Enter your current authenticator or backup code to unlock this action."
    : "Confirm your current password to continue with this sensitive action.";

export function StepUpRecoveryDialog() {
  const { refresh, user } = useAuth();
  const { toast } = useToast();

  const [open, setOpen] = useState(false);
  const [stepUpMethod, setStepUpMethod] = useState<StepUpMethod>("PASSWORD_REAUTH");
  const [message, setMessage] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [adminMfaInputMode, setAdminMfaInputMode] = useState<AdminMfaInputMode>("authenticator");
  const [mfaAuthenticatorCode, setMfaAuthenticatorCode] = useState("");
  const [mfaBackupCode, setMfaBackupCode] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const isAdminUser = user?.role === "super_admin" || user?.role === "licensee_admin";
  const adminCanUseWebAuthn =
    stepUpMethod === "ADMIN_MFA" &&
    isAdminUser &&
    isWebAuthnSupported() &&
    Boolean(user?.auth?.availableMfaMethods?.includes("WEBAUTHN"));
  const fallbackStepUpMethod: StepUpMethod = isAdminUser ? "ADMIN_MFA" : "PASSWORD_REAUTH";

  useEffect(() => {
    const onStepUpRequired = (event: Event) => {
      const detail = ((event as CustomEvent<StepUpEventDetail>).detail || {}) as StepUpEventDetail;
      const method = detail.stepUpMethod || fallbackStepUpMethod;
      setStepUpMethod(method);
      setMessage(detail.message || defaultMessageForMethod(method));
      setCurrentPassword("");
      setAdminMfaInputMode("authenticator");
      setMfaAuthenticatorCode("");
      setMfaBackupCode("");
      setOpen(true);
    };

    window.addEventListener("auth:step-up-required", onStepUpRequired as EventListener);
    return () => window.removeEventListener("auth:step-up-required", onStepUpRequired as EventListener);
  }, [fallbackStepUpMethod]);

  const title = useMemo(
    () => (stepUpMethod === "ADMIN_MFA" ? "Confirm Admin Verification" : "Confirm Your Password"),
    [stepUpMethod]
  );

  const handleClose = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (!nextOpen) {
      setSubmitting(false);
      setCurrentPassword("");
      setAdminMfaInputMode("authenticator");
      setMfaAuthenticatorCode("");
      setMfaBackupCode("");
    }
  };

  const submit = async () => {
    const adminCode =
      adminMfaInputMode === "backup"
        ? mfaBackupCode.trim().toUpperCase()
        : mfaAuthenticatorCode.trim();
    setSubmitting(true);
    try {
      const response =
        stepUpMethod === "ADMIN_MFA"
          ? await apiClient.stepUpWithAdminMfa(adminCode)
          : await apiClient.stepUpWithPassword(currentPassword);

      if (!response.success) {
        throw new Error(response.error || "Verification failed.");
      }

      await refresh();
      toast({
        title: "Verification refreshed",
        description: "Sensitive actions are unlocked again. Retry the action you were taking.",
      });
      handleClose(false);
    } catch (error: any) {
      toast({
        title: "Verification failed",
        description: error?.message || "Could not refresh your verification.",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const submitWebAuthn = async () => {
    setSubmitting(true);
    try {
      const beginResponse = await apiClient.beginAdminWebAuthnChallenge();
      if (!beginResponse.success || !beginResponse.data) {
        throw new Error(beginResponse.error || "Could not start WebAuthn verification.");
      }

      const assertion = await startAdminWebAuthnAuthentication(beginResponse.data);
      const response = await apiClient.completeAdminWebAuthnChallenge(assertion);
      if (!response.success) {
        throw new Error(response.error || "Could not verify the security key.");
      }

      await refresh();
      toast({
        title: "Verification refreshed",
        description: "Your security key unlocked sensitive actions again. Retry what you were doing.",
      });
      handleClose(false);
    } catch (error: any) {
      toast({
        title: "Verification failed",
        description: error?.message || "Could not verify the security key.",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-md rounded-2xl p-6">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{message || defaultMessageForMethod(stepUpMethod)}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {stepUpMethod === "ADMIN_MFA" ? (
            <div className="space-y-4">
              {adminCanUseWebAuthn ? (
                <Button type="button" variant="outline" onClick={() => void submitWebAuthn()} disabled={submitting}>
                  {submitting ? "Waiting for security key..." : "Use security key / passkey"}
                </Button>
              ) : null}
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={adminMfaInputMode === "authenticator" ? "default" : "outline"}
                    onClick={() => setAdminMfaInputMode("authenticator")}
                    disabled={submitting}
                  >
                    Authenticator code
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={adminMfaInputMode === "backup" ? "default" : "outline"}
                    onClick={() => setAdminMfaInputMode("backup")}
                    disabled={submitting}
                  >
                    Backup code
                  </Button>
                </div>
                {adminMfaInputMode === "authenticator" ? (
                  <>
                    <Label htmlFor="step-up-mfa-auth-code">Authenticator code</Label>
                    <Input
                      id="step-up-mfa-auth-code"
                      value={mfaAuthenticatorCode}
                      onChange={(event) => setMfaAuthenticatorCode(event.target.value)}
                      inputMode="numeric"
                      placeholder="123456"
                      autoComplete="one-time-code"
                    />
                  </>
                ) : (
                  <>
                    <Label htmlFor="step-up-mfa-backup-code">Backup code</Label>
                    <Input
                      id="step-up-mfa-backup-code"
                      value={mfaBackupCode}
                      onChange={(event) => setMfaBackupCode(event.target.value)}
                      placeholder="ABCDE-12345"
                      autoComplete="one-time-code"
                    />
                  </>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="step-up-password">Current password</Label>
              <Input
                id="step-up-password"
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </div>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button type="button" variant="outline" onClick={() => handleClose(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void submit()}
            disabled={
              submitting ||
              (stepUpMethod === "ADMIN_MFA"
                ? !(adminMfaInputMode === "backup" ? mfaBackupCode.trim() : mfaAuthenticatorCode.trim())
                : !currentPassword)
            }
          >
            {submitting ? "Verifying..." : "Continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default StepUpRecoveryDialog;
