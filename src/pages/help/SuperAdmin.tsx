import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { WorkflowScreenshotCard } from "@/components/help/WorkflowScreenshotCard";
import { Shield, Building2, FileCheck2, Siren } from "lucide-react";

export default function SuperAdminHelp() {
  return (
    <HelpShell
      title="Super Admin"
      subtitle="Manage brand workspaces, code approvals, audit visibility, and incident response across the platform."
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
              <li>Create and manage brand workspaces.</li>
              <li>Approve code inventory requests from brand admins.</li>
              <li>Review printer certification state and print trace when a workspace route needs investigation.</li>
              <li>View platform audit logs and investigate activity.</li>
              <li>Use Incident Response to triage alerts, open incidents, and apply containment actions.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Siren className="h-4 w-4" />
          <AlertTitle>Incident Response is Super Admin only</AlertTitle>
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
                  Create a brand workspace
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">Brands</Badge>.</li>
                  <li>Select <Badge variant="outline">Add brand</Badge>.</li>
                  <li>Fill company name, prefix, and optional details.</li>
                  <li>Create the record. The brand becomes the scoped workspace for admins, batches, and audit history.</li>
                </ol>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileCheck2 className="h-4 w-4 text-primary" />
                  Approve QR Requests
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
                <li>Open <Badge variant="outline">Incident Response</Badge>.</li>
                <li>Review <strong>Alerts</strong> (policy triggers) and <strong>Incidents</strong> (cases).</li>
                <li>Assign an owner, set severity/priority, and add notes to build the timeline.</li>
                <li>Apply containment actions only when needed (they are reversible with reason).</li>
              </ol>
              </CardContent>
            </Card>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Investigate a printer route issue</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Confirm whether the issue is brand-scoped or affects multiple sites.</li>
                <li>Review the saved printer profile, live discovery status, and latest print trace before changing certification.</li>
                <li>Use the audit trail to decide whether the route should stay certified, move to review, or be blocked.</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Core workflow screens</h2>
          <p className="text-sm text-muted-foreground">
            These screens cover the platform-admin loop: create the brand workspace, approve inventory, triage incidents, and
            tune policy rules when the platform needs a control change.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Create the brand workspace"
              description="Start every new customer rollout here. This workspace is the anchor for users, batches, scope, and audit history."
              filename="superadmin-create-licensee.png"
              alt="Create brand workspace dialog"
              caption="Brands: create the workspace before inviting admins or reviewing request volume."
              highlights={[
                "Confirm the company name and prefix before saving.",
                "Create the workspace first, then invite the Brand Admin.",
                "Return here for cross-workspace administration and status checks.",
              ]}
            />
            <WorkflowScreenshotCard
              title="Approve a code request"
              description="Use the pending request queue to decide whether the next source sequence should be released."
              filename="superadmin-approve-qr-request.png"
              alt="Approve code request modal"
              caption="QR Requests: review the request and release or reject the next available sequence."
              highlights={[
                "Work from the pending queue first.",
                "Check the quantity and reference before approval.",
                "Reject with a reason if the request needs correction instead of silent rejection.",
              ]}
            />
            <WorkflowScreenshotCard
              title="Triage incidents and alerts"
              description="Use Incident Response as the live operating console for policy triggers, fraud reports, and response ownership."
              filename="ir-dashboard.png"
              alt="Incident Response dashboard"
              caption="Incident Response: review open incidents, alert state, and active platform risk signals."
              highlights={[
                "Prioritise open incidents before tuning lower-priority alerts.",
                "Use owner, severity, and status together to decide the next action.",
                "Open the incident detail when you need evidence, history, or customer communications.",
              ]}
            />
            <WorkflowScreenshotCard
              title="Adjust a policy rule"
              description="Use the policy editor when you need to change the threshold that creates future platform alerts."
              filename="ir-policy-create.png"
              alt="Create policy rule"
              caption="Policy Alerts: create or refine the rule that should generate future alerts."
              highlights={[
                "Change rules after you understand the underlying incident pattern.",
                "Use names and thresholds that another admin can understand later.",
                "Return to the alert queue after saving to confirm the rule behaves correctly.",
              ]}
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "superadmin-create-licensee.png",
                whereToCapture: "Brands page with Add brand dialog open.",
              },
              {
                filename: "superadmin-approve-qr-request.png",
                whereToCapture: "QR Requests page with Approve Request modal open.",
              },
              {
                filename: "ir-dashboard.png",
                whereToCapture: "Incident Response page (Incidents/Alerts/Policies) as Super Admin.",
              },
              {
                filename: "ir-policy-create.png",
                whereToCapture: "Policy Alerts view with the create/edit rule workflow open.",
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
