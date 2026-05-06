import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Gavel, ShieldCheck } from "lucide-react";

export default function RolesPermissions() {
  return (
    <HelpShell
      title="Roles & permissions"
      subtitle="Who can do what, and how brand/workspace scoping protects data between customers."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-primary" />
              What this page covers
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Available roles and what each role can access.</li>
              <li>Brand workspace scoping and manufacturer scoping.</li>
              <li>Where to request access changes.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Gavel className="h-4 w-4" />
          <AlertTitle>Tenant isolation is enforced</AlertTitle>
          <AlertDescription>
            Brand admins and manufacturer users are scoped to exactly one workspace. They cannot view or edit data belonging to another customer.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Role summary</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Super Admin</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>
                  Full platform access: Brands, QR Requests, History, Governance, and Incident Response.
                </p>
                <p className="text-xs">
                  Login role: <span className="font-mono">SUPER_ADMIN</span>.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Licensee Admin (brand/company)</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>
                  Manages manufacturers and batches within one brand workspace. Can request QR inventory and assign batches.
                </p>
                <p className="text-xs">
                  Login role: <span className="font-mono">LICENSEE_ADMIN</span>.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Manufacturer Admin</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>
                  Operates production: create controlled print jobs, let the MSCQR connector or certified printer route claim and complete them, and monitor status for assigned batches only.
                </p>
                <p className="text-xs">
                  Login role: <span className="font-mono">MANUFACTURER</span>.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  Customer <Badge variant="outline">Public</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>
                  Verification end user. Scans a QR, views verification status, and can report suspected counterfeit from the verify flow.
                </p>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-3">
            <DocScreenshot
              filename="superadmin-create-licensee.png"
              alt="Super Admin Brands workspace"
              caption="Super Admin: platform-wide Brands and approval workflows."
            />
            <DocScreenshot
              filename="licensee-admin-dashboard.png"
              alt="Brand Admin overview"
              caption="Licensee Admin: scoped company workspace."
            />
            <DocScreenshot
              filename="manufacturer-dashboard.png"
              alt="Manufacturer overview"
              caption="Manufacturer: assigned print-workflow scope."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "superadmin-create-licensee.png",
                whereToCapture: "Brands page with Add brand dialog open.",
              },
              {
                filename: "licensee-admin-dashboard.png",
                whereToCapture: "Licensee Admin Overview page with QR totals and quick actions.",
              },
              {
                filename: "manufacturer-dashboard.png",
                whereToCapture: "Manufacturer Overview page with assigned scope and quick actions.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">I can’t see a page my coworker can</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Your role controls which sections appear in the left navigation. Contact your admin to confirm your role and org assignment.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Insufficient permissions”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                This typically means you are trying to access another org’s data or an admin-only feature. Return to your dashboard or request the correct role.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
