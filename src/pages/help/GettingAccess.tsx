import React from "react";
import { Link } from "react-router-dom";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Mail, UserPlus, ScanLine } from "lucide-react";

export default function GettingAccess() {
  return (
    <HelpShell
      title="Getting access"
      subtitle="How each user type gets access to MSCQR (invite-based onboarding)."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="text-base">What this page covers</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Who creates accounts for each role.</li>
              <li>What invite emails contain and how long invite links remain valid.</li>
              <li>When required MFA is enforced during onboarding.</li>
              <li>What customers need to do to verify a product (no account required).</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Mail className="h-4 w-4" />
          <AlertTitle>Invites expire</AlertTitle>
          <AlertDescription>
            Invite links are single-use and expire after <strong>24 hours</strong>. If you missed the window, ask an admin to send a new invite.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">By user type</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Super Admin</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>Created by the platform owner (not self sign-up).</li>
                  <li>Must complete MFA before first portal access.</li>
                  <li>Has full platform visibility and can invite other roles.</li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Licensee/Admin (brand/company)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Super Admin creates the licensee (tenant).</li>
                  <li>Super Admin or an org admin sends you an invite email.</li>
                  <li>You open the invite link and set your password.</li>
                  <li>You complete required MFA with an authenticator app.</li>
                  <li>You sign in and operate only within your org scope.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Manufacturer (factory user)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>A Licensee/Admin creates or invites the manufacturer user.</li>
                  <li>You receive an invite email with the password-setup link.</li>
                  <li>The same email also includes the MSCQR Connector download page for Mac and Windows.</li>
                  <li>Install the connector once on the computer that will print, then open the invite link to set your password.</li>
                  <li>Complete required MFA before the portal opens.</li>
                  <li>Sign in and you will only see batches assigned to your account.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  Customer <Badge variant="outline">Public</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>No account is required.</li>
                  <li>Scan the QR and the verify page shows authenticity status.</li>
                  <li>You can report suspected counterfeit from the verify page if needed.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline">
              <Link to="/connector-download">Open connector download page</Link>
            </Button>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="superadmin-create-licensee.png"
              alt="Super Admin creating a licensee"
              caption="Super Admin: create a licensee (tenant)."
            />
            <DocScreenshot
              filename="licensee-create-manufacturer.png"
              alt="Licensee/Admin creating a manufacturer account"
              caption="Licensee/Admin: invite a manufacturer user."
            />
            <DocScreenshot
              filename="access-super-admin-login.png"
              alt="Login page with credentials entered"
              caption="Login page used by all admin/manufacturer roles."
            />
            <DocScreenshot
              filename="customer-first-verification.png"
              alt="Customer first verification"
              caption="Customer: verify page (no sign-in required)."
            />
          </div>

          <ScreenshotChecklist
            items={[
              {
                filename: "superadmin-create-licensee.png",
                whereToCapture: "Licensees page with Add Licensee modal open.",
              },
              {
                filename: "licensee-create-manufacturer.png",
                whereToCapture: "Manufacturers page with Add Manufacturer modal open (Invite mode).",
              },
              {
                filename: "access-super-admin-login.png",
                whereToCapture: "Login page with credentials entered (any role).",
              },
              {
                filename: "customer-first-verification.png",
                whereToCapture: "Public verify page showing Verified Authentic (first scan).",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <UserPlus className="h-4 w-4 text-primary" />
                  Invite email not received
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>Check spam/junk folders.</li>
                  <li>Confirm the invite was sent to the correct email address.</li>
                  <li>Ask the admin to resend the invite if the activation link or connector link has expired.</li>
                </ul>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ScanLine className="h-4 w-4 text-primary" />
                  Customer can’t access verify page
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>Ensure the QR link points to <span className="font-mono">/verify/&lt;code&gt;</span>.</li>
                  <li>Try entering the code manually on the verify landing page.</li>
                  <li>If the service is down, wait and retry.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
