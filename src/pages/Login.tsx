import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { login } = useAuth();
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
      setError(humanizeAuthError(result.error));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Welcome back"
      description="Sign in to manage code requests, batches, printing, and traceability workflows."
      sideTitle="Control secure product code operations from one console."
      sideDescription="Built for Super Admins, Licensee Admins, and Manufacturer Admins with role-safe access, audit visibility, and day-to-day operational control."
    >
      <form onSubmit={handleSubmit} className="space-y-5">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

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
          Password reset and account verification both use secure email links. If access is blocked after setup, check your inbox for the latest verification message.
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
    </AuthShell>
  );
}
