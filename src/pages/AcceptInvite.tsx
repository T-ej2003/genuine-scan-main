import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AlertCircle, CheckCircle2, KeyRound, Loader2, ShieldCheck, UserPlus } from "lucide-react";

import apiClient from "@/lib/api-client";
import { AuthShell } from "@/components/auth/AuthShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

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
  const [preview, setPreview] = useState<null | {
    email: string;
    role: string;
    expiresAt: string;
    licenseeName: string | null;
    requiresConnector: boolean;
  }>(null);

  const canSubmit = token && password.length >= 8 && password === confirm;

  useEffect(() => {
    let cancelled = false;
    if (!token) {
      setPreview(null);
      return () => undefined;
    }

    void apiClient.getInvitePreview(token).then((res) => {
      if (cancelled) return;
      if (res.success && res.data) setPreview(res.data);
    });

    return () => {
      cancelled = true;
    };
  }, [token]);

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
    <AuthShell
      title="Activate your account"
      description="Set your password to finish onboarding. This secure link works once and expires after 24 hours."
      sideTitle="Secure activation for invited MSCQR users"
      sideDescription="Finish account setup here, then continue in MSCQR with the tools and visibility appropriate for your role. Manufacturer users can also open the connector download page from here before their first print run."
    >
      <div className="space-y-5">
        {!token ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Missing invite token. Please use the link from your invitation email.
            </AlertDescription>
          </Alert>
        ) : null}

        {preview ? (
          <Card className="border-emerald-200 bg-emerald-50/70">
            <CardContent className="space-y-3 p-5 text-sm text-emerald-950">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="bg-emerald-700 text-white hover:bg-emerald-700">
                  {preview.role === "MANUFACTURER" ? "Manufacturer onboarding" : "Secure invite"}
                </Badge>
                {preview.licenseeName ? <Badge variant="outline">{preview.licenseeName}</Badge> : null}
              </div>
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-700" />
                <div>
                  This activation link is for <strong>{preview.email}</strong>.
                  {preview.requiresConnector ? (
                    <span> If you will print from a workstation, install the MSCQR Connector on that Mac or Windows computer before the first live print run.</span>
                  ) : null}
                </div>
              </div>
              {preview.requiresConnector ? (
                <div className="flex flex-wrap gap-2">
                  <Button asChild size="sm" variant="outline">
                    <Link to={`/connector-download?inviteToken=${encodeURIComponent(token)}`}>Install Connector</Link>
                  </Button>
                  <Button asChild size="sm" variant="ghost">
                    <Link to="/help/getting-access">Onboarding steps</Link>
                  </Button>
                </div>
              ) : null}
            </CardContent>
          </Card>
        ) : null}

        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        {done ? (
          <Alert>
            <CheckCircle2 className="h-4 w-4" />
            <AlertDescription>Account activated. Redirecting…</AlertDescription>
          </Alert>
        ) : null}

        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name (optional)</Label>
            <div className="relative">
              <UserPlus className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
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

          <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
            <Link to="/login" className="underline-offset-4 hover:text-foreground hover:underline">
              Back to sign in
            </Link>
            {token ? (
              <Link to={`/connector-download?inviteToken=${encodeURIComponent(token)}`} className="underline-offset-4 hover:text-foreground hover:underline">
                Install Connector
              </Link>
            ) : null}
          </div>
        </form>
      </div>
    </AuthShell>
  );
}
