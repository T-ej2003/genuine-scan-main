import React, { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import apiClient from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, CheckCircle2, UserPlus, KeyRound } from "lucide-react";

export default function AcceptInvite() {
  const [params] = useSearchParams();
  const navigate = useNavigate();

  const token = useMemo(() => String(params.get("token") || "").trim(), [params]);

  const [name, setName] = useState("");
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
      setError("Missing invite token");
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
      const res = await apiClient.acceptInvite({
        token,
        password,
        name: name.trim() || undefined,
      });
      if (!res.success) {
        setError(res.error || "Invite acceptance failed");
        return;
      }
      setDone(true);
      window.setTimeout(() => navigate("/dashboard"), 800);
    } catch (err: any) {
      setError(err?.message || "Invite acceptance failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-secondary via-slate-800 to-slate-900 p-4">
      <div className="w-full max-w-md animate-fade-in">
        <Card className="border-0 shadow-2xl">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-2xl font-bold text-center">Activate your account</CardTitle>
            <CardDescription className="text-center">
              Set your password to finish onboarding. This link expires after 24 hours.
            </CardDescription>
          </CardHeader>

          <CardContent>
            {!token ? (
              <Alert variant="destructive" className="mb-4">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Missing invite token. Please use the link from your invitation email.
                </AlertDescription>
              </Alert>
            ) : null}

            {error ? (
              <Alert variant="destructive" className="mb-4">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}

            {done ? (
              <Alert className="mb-4">
                <CheckCircle2 className="h-4 w-4" />
                <AlertDescription>Account activated. Redirecting…</AlertDescription>
              </Alert>
            ) : null}

            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name (optional)</Label>
                <div className="relative">
                  <UserPlus className="h-4 w-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
                  <Input
                    id="name"
                    type="text"
                    autoComplete="name"
                    placeholder="Your name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    disabled={submitting || done}
                    className="pl-9"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <KeyRound className="h-4 w-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
                  <Input
                    id="password"
                    type="password"
                    autoComplete="new-password"
                    placeholder="At least 8 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={submitting || done}
                    className="pl-9"
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
                />
              </div>

              <Button type="submit" className="w-full" disabled={submitting || done || !canSubmit}>
                {submitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Activating...
                  </>
                ) : done ? (
                  "Activated"
                ) : (
                  "Activate account"
                )}
              </Button>

              <div className="text-sm text-center text-muted-foreground">
                <Link to="/login" className="hover:text-foreground underline-offset-4 hover:underline">
                  Back to sign in
                </Link>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

