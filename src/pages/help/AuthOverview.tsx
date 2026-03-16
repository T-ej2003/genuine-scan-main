import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { KeyRound, ShieldCheck } from "lucide-react";

export default function AuthOverview() {
  return (
    <HelpShell
      title="Auth overview"
      subtitle="How sign-in works for admins/manufacturers, how sessions are stored, and what to do when login fails."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-primary" />
              What this page covers
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Which parts of MSCQR require sign-in.</li>
              <li>How admin and manufacturer users sign in with email and password.</li>
              <li>How your session is stored (secure cookies) and why you should not share tokens.</li>
              <li>Common login issues (invites not accepted, lockouts).</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <KeyRound className="h-4 w-4" />
          <AlertTitle>Security note</AlertTitle>
          <AlertDescription>
            Admin/manufacturer sessions use <strong>HttpOnly</strong> cookies. This means the browser manages your session automatically and the app does not store tokens in localStorage.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">1. Sign in</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open the login page.</li>
                  <li>Enter your email and password.</li>
                  <li>Select <Badge variant="outline">Sign in</Badge>.</li>
                  <li>If the password is correct, the portal opens immediately.</li>
                  <li>Use the password reset flow if you cannot sign in.</li>
                </ol>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">2. Sessions and expiry</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>Sessions refresh automatically while you use the app.</li>
                  <li>If you are signed out, simply sign in again.</li>
                  <li>For security, repeated failed logins can temporarily lock the account.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <DocScreenshot
            filename="access-super-admin-login.png"
            alt="Login page with credentials entered"
            caption="Login screen (used across roles)."
            eager
          />
          <ScreenshotChecklist
            items={[
              {
                filename: "access-super-admin-login.png",
                whereToCapture: "Login page with credentials entered (any role).",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Account not activated”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                This happens when your account was invited but you have not accepted the invite yet. Ask your admin to resend the invite, or use <Badge variant="outline">Forgot password</Badge> if it is enabled for your account.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Account temporarily locked”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Too many failed login attempts can lock the account for a short period. Wait and try again later, or reset your password.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
