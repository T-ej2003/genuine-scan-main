import React, { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import apiClient from "@/lib/api-client";
import { AuthShell } from "@/components/auth/AuthShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, CheckCircle2, KeyRound } from "lucide-react";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  const token = useMemo(() => String(params.get("token") || "").trim(), [params]);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = token && password.length >= 8 && password === confirm;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!token) {
      setError("Missing reset token");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }

    setSubmitting(true);
    try {
      const res = await apiClient.resetPassword(token, password);
      if (!res.success) {
        setError(res.error || "Reset failed");
        return;
      }
      setDone(true);
      window.setTimeout(() => navigate("/login"), 1200);
    } catch (err: any) {
      setError(err?.message || "Reset failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Set a new password"
      description="Use the secure reset link from email to set a fresh password and return to the admin console."
      sideTitle="Password reset with short-lived tokens and guarded recovery."
      sideDescription="This screen completes the existing server-side reset workflow. Tokens are validated before password updates and the user is redirected back to sign in."
    >
      {!token ? (
        <Alert variant="destructive" className="mb-4">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Missing reset token. Please use the link from your email.</AlertDescription>
        </Alert>
      ) : null}

      {error ? (
        <Alert variant="destructive" className="mb-4">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {done ? (
        <Alert className="mb-4 border-emerald-200 bg-emerald-50 text-emerald-950">
          <CheckCircle2 className="h-4 w-4 text-emerald-700" />
          <AlertDescription>Password updated. Redirecting to sign in…</AlertDescription>
        </Alert>
      ) : null}

      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="password">New password</Label>
          <div className="relative">
            <KeyRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="password"
              type="password"
              autoComplete="new-password"
              placeholder="At least 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={submitting || done}
              className="h-11 pl-9"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirm">Confirm password</Label>
          <Input
            id="confirm"
            type="password"
            autoComplete="new-password"
            placeholder="Re-enter password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            disabled={submitting || done}
            className="h-11"
          />
        </div>

        <Button type="submit" className="h-11 w-full bg-slate-900 text-white hover:bg-slate-800" disabled={submitting || done || !canSubmit}>
          {submitting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Updating...
            </>
          ) : done ? (
            "Updated"
          ) : (
            "Update password"
          )}
        </Button>

        <div className="text-sm text-center text-muted-foreground">
          <Link to="/login" className="hover:text-foreground underline-offset-4 hover:underline">
            Back to sign in
          </Link>
        </div>
      </form>
    </AuthShell>
  );
}
