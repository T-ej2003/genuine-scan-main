import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { AlertCircle, Eye, EyeOff, KeyRound, Loader2, ShieldCheck } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";
import { AuthShell } from "@/components/auth/AuthShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { isWebAuthnSupported, startAdminWebAuthnAuthentication } from "@/lib/webauthn";

type MfaMode = "setup" | "challenge";
type MfaChallengeMethod = "authenticator" | "backup";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const [mfaMode, setMfaMode] = useState<MfaMode | null>(null);
  const [mfaSetupCode, setMfaSetupCode] = useState("");
  const [mfaChallengeMethod, setMfaChallengeMethod] = useState<MfaChallengeMethod>("authenticator");
  const [mfaChallengeCode, setMfaChallengeCode] = useState("");
  const [mfaBackupCode, setMfaBackupCode] = useState("");
  const [mfaTicket, setMfaTicket] = useState<string | null>(null);
  const [mfaSetup, setMfaSetup] = useState<{ secret: string; otpauthUri: string; backupCodes: string[] } | null>(null);
  const [mfaQrDataUrl, setMfaQrDataUrl] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaBackupCodesRevealed, setMfaBackupCodesRevealed] = useState(true);
  const webauthnSupported = isWebAuthnSupported();

  const { login, logout, pendingAuth, completeMfaSession } = useAuth();
  const navigate = useNavigate();

  const humanizeAuthError = (value?: string) => {
    const text = String(value || "").toLowerCase();
    if (text.includes("invalid email or password") || text.includes("password")) {
      return "Incorrect password. Try again.";
    }
    if (text.includes("verify your email")) {
      return "Verify your email before signing in. Use the latest message sent to your inbox.";
    }
    if (text.includes("temporarily locked")) {
      return "Your account is temporarily locked after repeated sign-in attempts. Try again later.";
    }
    if (text.includes("too many")) {
      return "Too many sign-in attempts. Wait a moment, then try again.";
    }
    if (text.includes("session expired")) {
      return "Your session expired. Sign in again to continue.";
    }
    if (text.includes("mfa")) {
      return "The security code could not be verified. Check the code and try again.";
    }
    return value || "Login failed";
  };

  useEffect(() => {
    if (!pendingAuth) {
      setMfaMode(null);
      setMfaTicket(null);
      setMfaSetup(null);
      setMfaQrDataUrl("");
      setMfaSetupCode("");
      setMfaChallengeMethod("authenticator");
      setMfaChallengeCode("");
      setMfaBackupCode("");
      return;
    }

    setError("");
    setMfaMode(pendingAuth.auth.mfaEnrolled ? "challenge" : "setup");
    setMfaChallengeMethod("authenticator");
    setMfaChallengeCode("");
    setMfaBackupCode("");
  }, [pendingAuth]);

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

  useEffect(() => {
    if (!pendingAuth || mfaLoading) return;
    if (mfaMode === "setup" && !mfaSetup) {
      setMfaLoading(true);
      void apiClient.beginAdminMfaSetup()
        .then((response) => {
          if (!response.success || !response.data) {
            throw new Error(response.error || "Could not start MFA setup.");
          }
          setMfaSetup(response.data);
          setMfaBackupCodesRevealed(true);
        })
        .catch((err: any) => {
          setError(humanizeAuthError(err?.message || "Could not start MFA setup."));
        })
        .finally(() => setMfaLoading(false));
    }

    if (mfaMode === "challenge" && !mfaTicket) {
      setMfaLoading(true);
      void apiClient.beginAdminMfaChallenge()
        .then((response) => {
          if (!response.success || !response.data?.ticket) {
            throw new Error(response.error || "Could not start MFA challenge.");
          }
          setMfaTicket(response.data.ticket);
        })
        .catch((err: any) => {
          setError(humanizeAuthError(err?.message || "Could not start MFA challenge."));
        })
        .finally(() => setMfaLoading(false));
    }
  }, [humanizeAuthError, mfaLoading, mfaMode, mfaSetup, mfaTicket, pendingAuth]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      const result = await login(email.trim().toLowerCase(), password);
      if (result.success && result.sessionStage === "ACTIVE") {
        navigate("/dashboard");
        return;
      }
      if (!result.success) {
        setError(humanizeAuthError(result.error));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleConfirmMfaSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setMfaLoading(true);

    try {
      const response = await apiClient.confirmAdminMfaSetup(mfaSetupCode.trim());
      if (!response.success) {
        setError(humanizeAuthError(response.error || "Could not complete MFA setup."));
        return;
      }

      if (response.data?.user) {
        completeMfaSession({ user: response.data.user, auth: response.data.auth || null });
        navigate("/dashboard");
        return;
      }

      setError("MFA setup was saved, but the session needs to be renewed. Sign in again.");
    } finally {
      setMfaLoading(false);
    }
  };

  const handleCompleteMfaChallenge = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!mfaTicket) {
      setError("This security challenge expired. Start again.");
      return;
    }
    const challengeCode = mfaChallengeMethod === "backup"
      ? mfaBackupCode.trim().toUpperCase()
      : mfaChallengeCode.trim();
    if (!challengeCode) {
      setError(mfaChallengeMethod === "backup" ? "Enter a backup code." : "Enter the authenticator code.");
      return;
    }

    setMfaLoading(true);
    try {
      const response = await apiClient.completeAdminMfaChallenge(mfaTicket, challengeCode);
      if (!response.success || !response.data?.user) {
        setError(humanizeAuthError(response.error || "Could not complete MFA challenge."));
        return;
      }

      completeMfaSession({ user: response.data.user, auth: response.data.auth || null });
      navigate("/dashboard");
    } finally {
      setMfaLoading(false);
    }
  };

  const handleCompleteWebAuthnChallenge = async () => {
    setError("");
    setMfaLoading(true);
    try {
      const beginResponse = await apiClient.beginAdminWebAuthnChallenge();
      if (!beginResponse.success || !beginResponse.data) {
        setError(humanizeAuthError(beginResponse.error || "Could not start WebAuthn verification."));
        return;
      }

      const assertion = await startAdminWebAuthnAuthentication(beginResponse.data);
      const response = await apiClient.completeAdminWebAuthnChallenge(assertion);
      if (!response.success || !response.data?.user) {
        setError(humanizeAuthError(response.error || "Could not complete WebAuthn verification."));
        return;
      }

      completeMfaSession({ user: response.data.user, auth: response.data.auth || null });
      navigate("/dashboard");
    } catch (error: any) {
      setError(humanizeAuthError(error?.message || "Could not verify the security key."));
    } finally {
      setMfaLoading(false);
    }
  };

  const resetMfaFlow = () => {
    setMfaMode(null);
    setMfaSetupCode("");
    setMfaChallengeMethod("authenticator");
    setMfaChallengeCode("");
    setMfaBackupCode("");
    setMfaTicket(null);
    setMfaSetup(null);
    setMfaQrDataUrl("");
    setError("");
    logout();
  };

  const shellContent = useMemo(() => {
    if (!pendingAuth || !mfaMode) {
      return {
        title: "Welcome back",
        description: "Sign in to manage code requests, batches, printing, and traceability workflows.",
        sideTitle: "Control secure product code operations from one console.",
        sideDescription:
          "Built for Super Admins, Licensee Admins, and Manufacturer Admins with role-safe access, audit visibility, and day-to-day operational control.",
      };
    }

    if (mfaMode === "setup") {
      return {
        title: "Set up admin MFA",
        description: "This one-time step protects policy changes, QR allocation, and other sensitive admin actions.",
        sideTitle: "Strict admin access starts here.",
        sideDescription:
          "Scan the code with an authenticator app, save the backup codes, then confirm with the 6-digit code to finish sign-in.",
      };
    }

    return {
      title: "Confirm your admin sign-in",
      description: "Enter the code from your authenticator app or one of your backup codes to continue.",
      sideTitle: "Sensitive admin operations require MFA.",
      sideDescription:
        "MSCQR will only open the full admin session after the second factor is verified, so QR issuance and policy changes stay tightly controlled.",
    };
  }, [mfaMode, pendingAuth]);

  return (
    <AuthShell
      title={shellContent.title}
      description={shellContent.description}
      sideTitle={shellContent.sideTitle}
      sideDescription={shellContent.sideDescription}
    >
      {!pendingAuth || !mfaMode ? (
        <form onSubmit={handleSubmit} className="space-y-5">
          {error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={submitting}
              className="h-11"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">Password</Label>
              <Link
                to="/forgot-password"
                className="text-xs font-medium text-emerald-700 hover:text-emerald-800 underline-offset-4 hover:underline"
              >
                Forgot password?
              </Link>
            </div>
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={submitting}
                className="h-11 pr-12"
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 inline-flex w-11 items-center justify-center text-muted-foreground hover:text-foreground"
                aria-label={showPassword ? "Hide password" : "Show password"}
                onClick={() => setShowPassword((prev) => !prev)}
                disabled={submitting}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-emerald-100 bg-emerald-50/60 px-4 py-3 text-xs text-emerald-900">
            Password reset and account verification both use secure email links. Internal admin roles are now required
            to finish MFA before MSCQR opens the full session.
          </div>

          <Button type="submit" className="h-11 w-full bg-slate-900 text-white hover:bg-slate-800" disabled={submitting}>
            {submitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              "Sign in"
            )}
          </Button>
        </form>
      ) : mfaMode === "setup" ? (
        <form onSubmit={handleConfirmMfaSetup} className="space-y-5">
          {error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="rounded-2xl border border-emerald-100 bg-emerald-50/60 p-4 text-sm text-emerald-950">
            <div className="flex items-center gap-2 font-medium">
              <ShieldCheck className="h-4 w-4" />
              Admin MFA is now required for {pendingAuth.user.email}
            </div>
            <div className="mt-2 text-xs text-emerald-900/80">
              Open Google Authenticator, 1Password, Microsoft Authenticator, or any TOTP app and scan this QR code.
            </div>
          </div>

          <div className="rounded-2xl border p-4">
            {mfaQrDataUrl ? (
              <img src={mfaQrDataUrl} alt="Authenticator setup QR code" className="mx-auto h-52 w-52 rounded-xl border p-2" />
            ) : (
              <div className="flex h-52 items-center justify-center rounded-xl border bg-muted/30 text-sm text-muted-foreground">
                {mfaLoading ? "Preparing QR code..." : "QR code unavailable"}
              </div>
            )}

            <div className="mt-4 space-y-2">
              <Label>Manual setup key</Label>
              <Input value={mfaSetup?.secret || ""} readOnly className="font-mono text-sm" />
            </div>
          </div>

          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
            <div className="font-medium">Save your backup codes before you continue</div>
            <div className="mt-1 text-xs text-amber-900/80">
              Each code can be used once if you lose access to your authenticator app.
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="mt-3 px-0 text-amber-900 hover:bg-transparent"
              onClick={() => setMfaBackupCodesRevealed((value) => !value)}
            >
              {mfaBackupCodesRevealed ? "Hide backup codes" : "Show backup codes"}
            </Button>
            {mfaBackupCodesRevealed ? (
              <div className="mt-3 grid grid-cols-2 gap-2">
                {(mfaSetup?.backupCodes || []).map((code) => (
                  <div key={code} className="rounded-lg border border-amber-200 bg-white px-3 py-2 font-mono text-xs">
                    {code}
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          <div className="space-y-2">
            <Label htmlFor="mfa-setup-code">6-digit authenticator code</Label>
            <Input
              id="mfa-setup-code"
              value={mfaSetupCode}
              onChange={(e) => setMfaSetupCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              disabled={mfaLoading}
              className="h-11"
            />
          </div>

          <div className="flex gap-3">
            <Button type="button" variant="outline" className="flex-1" disabled={mfaLoading} onClick={resetMfaFlow}>
              Use different account
            </Button>
            <Button type="submit" className="flex-1 bg-slate-900 text-white hover:bg-slate-800" disabled={mfaLoading}>
              {mfaLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Confirming...
                </>
              ) : (
                "Finish secure sign-in"
              )}
            </Button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleCompleteMfaChallenge} className="space-y-5">
          {error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm">
            <div className="flex items-center gap-2 font-medium text-slate-950">
              <KeyRound className="h-4 w-4" />
              Second factor required for {pendingAuth.user.email}
            </div>
            <div className="mt-2 text-xs text-slate-700">
              Use your authenticator app or one of your saved backup codes. This keeps high-risk admin actions locked
              until the secure session is fully verified.
            </div>
            {pendingAuth.auth.preferredMfaMethod === "WEBAUTHN" ? (
              <div className="mt-2 text-xs font-medium text-emerald-800">
                This account prefers a security key or passkey first. Authenticator codes still work as fallback.
              </div>
            ) : null}
          </div>

          {webauthnSupported && pendingAuth.auth.availableMfaMethods?.includes("WEBAUTHN") ? (
            <Button
              type="button"
              variant="outline"
              className="w-full"
              disabled={mfaLoading}
              onClick={() => void handleCompleteWebAuthnChallenge()}
            >
              {mfaLoading ? "Waiting for security key..." : "Use security key / passkey"}
            </Button>
          ) : null}

          <div className="space-y-2">
            <div className="flex gap-2">
              <Button
                type="button"
                variant={mfaChallengeMethod === "authenticator" ? "default" : "outline"}
                size="sm"
                onClick={() => setMfaChallengeMethod("authenticator")}
                disabled={mfaLoading}
              >
                Authenticator code
              </Button>
              <Button
                type="button"
                variant={mfaChallengeMethod === "backup" ? "default" : "outline"}
                size="sm"
                onClick={() => setMfaChallengeMethod("backup")}
                disabled={mfaLoading}
              >
                Backup code
              </Button>
            </div>
            {mfaChallengeMethod === "authenticator" ? (
              <>
                <Label htmlFor="mfa-challenge-code">Authenticator code</Label>
                <Input
                  id="mfa-challenge-code"
                  value={mfaChallengeCode}
                  onChange={(e) => setMfaChallengeCode(e.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  disabled={mfaLoading}
                  className="h-11"
                />
              </>
            ) : (
              <>
                <Label htmlFor="mfa-backup-code">Backup code</Label>
                <Input
                  id="mfa-backup-code"
                  value={mfaBackupCode}
                  onChange={(e) => setMfaBackupCode(e.target.value)}
                  autoComplete="one-time-code"
                  placeholder="ABCDE-12345"
                  disabled={mfaLoading}
                  className="h-11"
                />
              </>
            )}
          </div>

          <div className="flex gap-3">
            <Button type="button" variant="outline" className="flex-1" disabled={mfaLoading} onClick={resetMfaFlow}>
              Use different account
            </Button>
            <Button type="submit" className="flex-1 bg-slate-900 text-white hover:bg-slate-800" disabled={mfaLoading}>
              {mfaLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                "Open secure session"
              )}
            </Button>
          </div>
        </form>
      )}
    </AuthShell>
  );
}
