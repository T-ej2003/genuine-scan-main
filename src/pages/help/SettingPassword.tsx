import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { KeyRound, ShieldAlert } from "lucide-react";

export default function SettingPassword() {
  return (
    <HelpShell
      title="Setting your password"
      subtitle="Role-specific password behavior for first login, password reset, and account lockouts."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="text-base">What this page covers</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Accepting an invite (first-time password set).</li>
              <li>Forgot password and reset links.</li>
              <li>How this differs for customers (public verify flow).</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <KeyRound className="h-4 w-4" />
          <AlertTitle>Invite links are single-use</AlertTitle>
          <AlertDescription>
            If you already accepted an invite, the link will not work again. Use <Badge variant="outline">Forgot password</Badge> instead.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">1. Accept invite (Super Admin, Licensee/Admin, Manufacturer)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open the invite email.</li>
                  <li>Select the invite link (it expires in 24 hours).</li>
                  <li>Set a password and confirm.</li>
                  <li>After success, sign in normally.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">2. Forgot password (admins/manufacturers)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open the login page.</li>
                  <li>Select <Badge variant="outline">Forgot password?</Badge></li>
                  <li>Enter your email and submit.</li>
                  <li>Open the reset link from your email and set a new password.</li>
                </ol>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Customers (public verify page)</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">No password required</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ul className="list-disc pl-5">
                <li>Customers do not need an account to verify a product.</li>
                <li>If a customer reports an issue, they can optionally leave contact details in the report form.</li>
              </ul>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="password-accept-invite.png"
              alt="Accept invite screen"
              caption="Accept invite: set your password for the first time."
              eager
            />
            <DocScreenshot
              filename="password-forgot-password.png"
              alt="Forgot password screen"
              caption="Forgot password: request a reset link."
            />
            <DocScreenshot
              filename="password-reset-password.png"
              alt="Reset password screen"
              caption="Reset password: set a new password using the emailed link."
            />
            <DocScreenshot
              filename="access-super-admin-login.png"
              alt="Login page"
              caption="Login page (entry point for password reset link)."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "password-accept-invite.png",
                whereToCapture: "Accept Invite page with password fields visible.",
              },
              {
                filename: "password-forgot-password.png",
                whereToCapture: "Forgot Password page with email filled.",
              },
              {
                filename: "password-reset-password.png",
                whereToCapture: "Reset Password page with new password fields visible.",
              },
              {
                filename: "access-super-admin-login.png",
                whereToCapture: "Login page with credentials entered.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Alert className="border-amber-200 bg-amber-50 text-amber-950">
              <ShieldAlert className="h-4 w-4 text-amber-700" />
              <AlertTitle>Invite expired</AlertTitle>
              <AlertDescription>
                Invite links expire after 24 hours. Ask your admin to send a new invite.
              </AlertDescription>
            </Alert>
            <Alert className="border-amber-200 bg-amber-50 text-amber-950">
              <ShieldAlert className="h-4 w-4 text-amber-700" />
              <AlertTitle>Account locked after failed logins</AlertTitle>
              <AlertDescription>
                After repeated failed password attempts, the system temporarily locks the account. Wait and retry, or reset your password.
              </AlertDescription>
            </Alert>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

