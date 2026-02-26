import React, { useState } from "react";
import { Link } from "react-router-dom";
import apiClient from "@/lib/api-client";
import { AuthShell } from "@/components/auth/AuthShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Mail, AlertCircle, CheckCircle2 } from "lucide-react";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await apiClient.forgotPassword(email.trim().toLowerCase());
      if (!res.success) {
        setError(res.error || "Failed to request reset");
        return;
      }
      setDone(true);
    } catch (err: any) {
      setError(err?.message || "Failed to request reset");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell
      title="Reset your password"
      description="Enter your email address and we will send a secure password reset link if the account exists."
      sideTitle="Fast recovery without exposing account data."
      sideDescription="The reset request flow keeps account discovery protections in place while issuing a time-limited email token to continue securely."
    >
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {done ? (
        <Alert className="mb-4 border-emerald-200 bg-emerald-50 text-emerald-950">
          <CheckCircle2 className="h-4 w-4 text-emerald-700" />
          <AlertDescription>Request received. Check your inbox for a password reset link.</AlertDescription>
        </Alert>
      ) : null}

      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={submitting}
              className="h-11 pl-9"
            />
          </div>
        </div>

        <Button type="submit" className="h-11 w-full bg-slate-900 text-white hover:bg-slate-800" disabled={submitting || done}>
          {submitting ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Sending...
            </>
          ) : done ? (
            "Email sent"
          ) : (
            "Send reset link"
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
