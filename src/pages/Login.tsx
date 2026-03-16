import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { AuthShell } from "@/components/auth/AuthShell";
import { MfaEnrollmentPanel, type MfaEnrollmentData } from "@/components/auth/MfaEnrollmentPanel";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, Eye, EyeOff } from "lucide-react";
import apiClient from "@/lib/api-client";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaTicket, setMfaTicket] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRiskLevel, setMfaRiskLevel] = useState<string | null>(null);
  const [mfaSetupTicket, setMfaSetupTicket] = useState("");
  const [mfaSetup, setMfaSetup] = useState<MfaEnrollmentData | null>(null);
  const [mfaSetupCode, setMfaSetupCode] = useState("");
  const [mfaSetupEmail, setMfaSetupEmail] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { login, completeMfaLogin } = useAuth();
  const navigate = useNavigate();

  const humanizeAuthError = (value?: string) => {
    const text = String(value || "").toLowerCase();
    if (text.includes("invalid email or password") || text.includes("password")) {
      return "incorrect-password. try again.";
    }
    if (text.includes("mfa setup session expired")) {
      return "your MFA setup session expired. sign in again.";
    }
    return value || "Login failed";
  };

  const resetMfaSetupState = () => {
    setMfaSetupTicket("");
    setMfaSetup(null);
    setMfaSetupCode("");
    setMfaSetupEmail("");
  };

  const loadMfaSetup = async (ticket: string, bootstrapEmail?: string) => {
    const setupResult = await apiClient.beginMfaBootstrapSetup(ticket);
    if (!setupResult.success || !setupResult.data) {
      resetMfaSetupState();
      setError(humanizeAuthError(setupResult.error || "Failed to start MFA setup"));
      return false;
    }

    setMfaTicket("");
    setMfaCode("");
    setMfaRiskLevel(null);
    setMfaSetupTicket(ticket);
    setMfaSetup(setupResult.data);
    setMfaSetupCode("");
    setMfaSetupEmail(bootstrapEmail || "");
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);

    try {
      const result = await login(email.trim().toLowerCase(), password);
      if (result.success) {
        navigate("/dashboard");
        return;
      }

      if (result.mfaRequired && result.mfaTicket) {
        setMfaTicket(result.mfaTicket);
        setMfaRiskLevel(result.riskLevel || null);
        setMfaCode("");
        resetMfaSetupState();
        return;
      }

      if (result.mfaSetupRequired && result.mfaSetupToken) {
        await loadMfaSetup(result.mfaSetupToken, result.email);
        return;
      }

      setError(humanizeAuthError(result.error));
    } finally {
      setSubmitting(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!mfaTicket) return;
    setSubmitting(true);

    try {
      const result = await completeMfaLogin(mfaTicket, mfaCode.trim());
      if (result.success) {
        navigate("/dashboard");
        return;
      }
      setError(result.error || "MFA verification failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleMfaSetupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!mfaSetupTicket) return;
    setSubmitting(true);

    try {
      const result = await apiClient.confirmMfaBootstrapSetup(mfaSetupTicket, mfaSetupCode.trim());
      if (result.success && result.data?.user) {
        navigate("/dashboard");
        return;
      }
      setError(result.error || "MFA setup failed");
    } finally {
      setSubmitting(false);
    }
  };

  const mode = mfaSetup ? "setup" : mfaTicket ? "mfa" : "login";

  return (
    <AuthShell
      title="Welcome back"
      description="Sign in to access QR operations, approvals, and traceability workflows. Super admins, licensee admins, and manufacturers use required MFA."
      sideTitle="Control secure QR inventory and approvals from one console."
      sideDescription="Designed for super users, licensee users, and manufacturer users with role-safe access, required MFA, audit visibility, and operational continuity."
    >
      <form onSubmit={mode === "setup" ? handleMfaSetupSubmit : mode === "mfa" ? handleMfaSubmit : handleSubmit} className="space-y-5">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {mode === "setup" && mfaSetup ? (
          <MfaEnrollmentPanel
            title="Set up multi-factor authentication"
            description={`This account${mfaSetupEmail ? ` (${mfaSetupEmail})` : ""} must enroll in MFA before portal access is granted.`}
            setup={mfaSetup}
            code={mfaSetupCode}
            onCodeChange={setMfaSetupCode}
            confirming={submitting}
            error={null}
          />
        ) : mode === "mfa" ? (
          <div className="space-y-2">
            <Label htmlFor="mfaCode">MFA code</Label>
            <Input
              id="mfaCode"
              type="text"
              autoComplete="one-time-code"
              placeholder="6-digit code or backup code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              required
              disabled={submitting}
              className="h-11"
            />
            <p className="text-xs text-slate-500">
              {mfaRiskLevel ? `Risk level: ${mfaRiskLevel}. ` : ""}
              Complete second-factor verification to continue.
            </p>
          </div>
        ) : (
          <>
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
          </>
        )}

        <div className="rounded-2xl border border-emerald-100 bg-emerald-50/60 px-4 py-3 text-xs text-emerald-900">
          {mode === "setup"
            ? "Scan the QR with Microsoft Authenticator, Google Authenticator, 1Password, or a compatible app, then store the backup codes before you continue."
            : mfaTicket
            ? "Use your authenticator app code or a one-time backup code."
            : "Password reset is available directly from the sign-in form and uses the existing secure email token flow."}
        </div>

        <Button
          type="submit"
          className="h-11 w-full bg-slate-900 text-white hover:bg-slate-800"
          disabled={submitting || (mode === "setup" && mfaSetupCode.trim().length < 6)}
        >
          {submitting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {mode === "setup" ? "Enabling MFA..." : mfaTicket ? "Verifying..." : "Signing in..."}
            </>
          ) : (
            mode === "setup" ? "Enable MFA and continue" : mfaTicket ? "Verify MFA" : "Sign in"
          )}
        </Button>

        {mode !== "login" ? (
          <Button
            type="button"
            variant="outline"
            className="h-11 w-full"
            onClick={() => {
              setMfaTicket("");
              setMfaCode("");
              setMfaRiskLevel(null);
              resetMfaSetupState();
              setError("");
            }}
          >
            Use different account
          </Button>
        ) : null}
      </form>
    </AuthShell>
  );
}
