import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Shield, Building2, FileCheck2, Siren } from "lucide-react";

export default function SuperAdminHelp() {
  return (
    <HelpShell
      title="Super Admin"
      subtitle="Platform-wide administration: tenants, QR allocation approvals, audit visibility, and Incident Response (IR)."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-primary" />
              What you can do
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Create and manage licensees (organizations/tenants).</li>
              <li>Approve QR inventory requests from licensees.</li>
              <li>View platform audit logs and investigate activity.</li>
              <li>Use the IR Center to triage alerts, open incidents, and apply containment actions.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Siren className="h-4 w-4" />
          <AlertTitle>IR Center is Super Admin only</AlertTitle>
          <AlertDescription>
            Incident Response tooling is restricted to platform admins. Licensees can still report issues via customer reports and licensee audit logs.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Key workflows</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Building2 className="h-4 w-4 text-primary" />
                  Create a licensee
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">Licensees</Badge>.</li>
                  <li>Select <Badge variant="outline">Add Licensee</Badge>.</li>
                  <li>Fill company name, prefix, and optional details.</li>
                  <li>Create the record. The licensee becomes a new tenant/org.</li>
                </ol>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileCheck2 className="h-4 w-4 text-primary" />
                  Approve QR requests
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">QR Requests</Badge>.</li>
                  <li>Filter to <Badge variant="outline">Pending</Badge>.</li>
                  <li>Open a request and select <Badge variant="outline">Approve</Badge> or <Badge variant="outline">Reject</Badge>.</li>
                  <li>Approved requests allocate the next available sequence automatically.</li>
                </ol>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <Siren className="h-4 w-4 text-primary" />
                Triage alerts and incidents
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open <Badge variant="outline">IR Center</Badge>.</li>
                <li>Review <strong>Alerts</strong> (policy triggers) and <strong>Incidents</strong> (cases).</li>
                <li>Assign an owner, set severity/priority, and add notes to build the timeline.</li>
                <li>Apply containment actions only when needed (they are reversible with reason).</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="superadmin-create-licensee.png"
              alt="Create licensee modal"
              caption="Licensees: create a new licensee (tenant)."
            />
            <DocScreenshot
              filename="superadmin-approve-qr-request.png"
              alt="Approve QR request modal"
              caption="QR Requests: approve/reject pending requests."
            />
            <DocScreenshot
              filename="ir-dashboard.png"
              alt="IR Center dashboard"
              caption="IR Center: incidents, alerts, and policy rules."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "superadmin-create-licensee.png",
                whereToCapture: "Licensees page with Add Licensee modal open.",
              },
              {
                filename: "superadmin-approve-qr-request.png",
                whereToCapture: "QR Requests page with Approve Request modal open.",
              },
              {
                filename: "ir-dashboard.png",
                whereToCapture: "IR Center page (Incidents/Alerts/Policies) as Super Admin.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Can’t approve a request</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Ensure you are signed in as Super Admin. If the request is already approved/rejected, refresh the list to sync state.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">IR actions are disabled</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Some actions require a reason and may be blocked if the incident is closed. Reopen the incident if changes are required.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

