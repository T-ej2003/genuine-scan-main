import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AlertCircle, CheckCircle2, Loader2, MailCheck } from "lucide-react";

import apiClient from "@/lib/api-client";
import { AuthShell } from "@/components/auth/AuthShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = useMemo(() => String(params.get("token") || "").trim(), [params]);

  const [state, setState] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("Confirming your email...");
  const [email, setEmail] = useState("");

  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      if (!token) {
        setState("error");
        setMessage("Missing verification token. Open the latest link from your email.");
        return;
      }

      const result = await apiClient.verifyEmail(token);
      if (cancelled) return;

      if (!result.success || !result.data) {
        setState("error");
        setMessage(result.error || "This verification link is invalid or expired.");
        return;
      }

      setEmail(result.data.email || "");
      setState("success");
      setMessage(
        result.data.purpose === "EMAIL_CHANGE"
          ? "Your email address has been updated."
          : "Your email address is now verified."
      );
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <AuthShell
      title="Verify your email"
      description="Finish this one-time security step to keep your account details current."
      sideTitle="Email confirmation protects account recovery and sign-in."
      sideDescription="MSCQR uses secure email links to confirm account ownership before sensitive account changes are accepted."
    >
      <div className="space-y-5">
        {state === "loading" ? (
          <Alert>
            <Loader2 className="h-4 w-4 animate-spin" />
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        ) : null}

        {state === "success" ? (
          <Alert>
            <CheckCircle2 className="h-4 w-4" />
            <AlertDescription>
              {message}
              {email ? ` ${email} is ready to use.` : ""}
            </AlertDescription>
          </Alert>
        ) : null}

        {state === "error" ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        ) : null}

        <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm text-slate-700">
          <div className="mb-2 flex items-center gap-2 font-medium text-slate-900">
            <MailCheck className="h-4 w-4" />
            What happens next
          </div>
          <p>
            If this link succeeds, you can continue in MSCQR immediately. If it has expired, request a fresh email from the account page or password reset flow.
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <Button onClick={() => navigate("/login")}>Go to sign in</Button>
          <Button variant="outline" asChild>
            <Link to="/forgot-password">Request a new secure email</Link>
          </Button>
        </div>
      </div>
    </AuthShell>
  );
}
