import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { AuthShell } from "@/components/auth/AuthShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, Eye, EyeOff } from "lucide-react";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaTicket, setMfaTicket] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRiskLevel, setMfaRiskLevel] = useState<string | null>(null);
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
    return value || "Login failed";
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

  return (
    <AuthShell
      title="Welcome back"
      description="Sign in to access QR operations, approvals, and traceability workflows."
      sideTitle="Control secure QR inventory and approvals from one console."
      sideDescription="Designed for super users, licensee users, and manufacturer users with role-safe access, audit visibility, and operational continuity."
    >
      <form onSubmit={mfaTicket ? handleMfaSubmit : handleSubmit} className="space-y-5">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {mfaTicket ? (
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
              className="app-tooltip absolute inset-y-0 right-0 inline-flex w-11 items-center justify-center text-muted-foreground hover:text-foreground"
              aria-label={showPassword ? "Hide password" : "Show password"}
              data-tooltip={showPassword ? "Hide password characters" : "Show password characters"}
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
          {mfaTicket
            ? "Use your authenticator app code or a one-time backup code."
            : "Password reset is available directly from the sign-in form and uses the existing secure email token flow."}
        </div>

        <Button type="submit" className="h-11 w-full bg-slate-900 text-white hover:bg-slate-800" disabled={submitting}>
          {submitting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {mfaTicket ? "Verifying..." : "Signing in..."}
            </>
          ) : (
            mfaTicket ? "Verify MFA" : "Sign in"
          )}
        </Button>

        {mfaTicket ? (
          <Button
            type="button"
            variant="outline"
            className="h-11 w-full"
            onClick={() => {
              setMfaTicket("");
              setMfaCode("");
              setMfaRiskLevel(null);
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
