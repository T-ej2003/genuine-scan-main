import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { WorkflowScreenshotCard } from "@/components/help/WorkflowScreenshotCard";
import { ClipboardList, Factory, History, ScanLine, ShieldCheck } from "lucide-react";

const workflowSteps = [
  "Check Overview before requesting or assigning stock.",
  "Request QR labels from QR Requests when more approved inventory is needed.",
  "Invite manufacturer admins from Manufacturers before assigning batches.",
  "Open a source batch workspace from Batches and allocate quantity in Operations.",
  "Use Scans and History to investigate verification activity and operational changes.",
];

export default function LicenseeAdminHelp() {
  return (
    <HelpShell
      title="Licensee Admin"
      subtitle="Operate your company workspace: QR requests, manufacturers, batch allocation, scans, and history."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-primary" />
              Current scope
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              Licensee Admin users can manage their own company workspace only. They can request QR labels,
              invite manufacturer admins, allocate approved source batches, and review scan/history data for their company.
            </p>
            <ul className="list-disc space-y-1 pl-5">
              {workflowSteps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <ClipboardList className="h-4 w-4" />
          <AlertTitle>Use source batches as the control point</AlertTitle>
          <AlertDescription>
            The Batches table stays stable with one row per source batch. Open the workspace to allocate quantity,
            view remaining stock, and review the merged audit trail.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Core workflow</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Start from Overview"
              description="Confirm current QR label totals, printed counts, scan counts, and recent workspace activity."
              filename="licensee-admin-dashboard.png"
              alt="Licensee Admin Overview"
              caption="Overview: current company QR labels, printing, scans, and next actions."
              highlights={["Confirm stock before requesting more.", "Use quick actions to move into the correct workflow.", "Review recent activity before escalating."]}
              eager
            />
            <WorkflowScreenshotCard
              title="Request QR labels"
              description="Submit a quantity and recognizable batch name for approval."
              filename="licensee-admin-qr-request.png"
              alt="Licensee Admin QR request"
              caption="QR Requests: request labels and track request history."
              highlights={["Enter the required quantity.", "Use a clear batch name.", "Track pending, approved, and rejected requests."]}
            />
            <WorkflowScreenshotCard
              title="Invite a manufacturer"
              description="Create the factory admin user before assigning production stock."
              filename="licensee-admin-manufacturer-invite.png"
              alt="Licensee Admin invite manufacturer"
              caption="Manufacturers: send a one-time invite with printer setup access."
              highlights={["Invite named users instead of sharing accounts.", "Use the factory admin email.", "Confirm active status before assigning batches."]}
            />
            <WorkflowScreenshotCard
              title="Allocate source stock"
              description="Open the source batch workspace, choose a manufacturer, and allocate only the needed quantity."
              filename="licensee-admin-batch-workspace.png"
              alt="Licensee Admin batch workspace"
              caption="Batches: allocate source quantity from the Operations tab."
              highlights={["Start from the source batch row.", "Check remaining unassigned quantity.", "Use Audit to confirm the allocation."]}
            />
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Review and traceability</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Review scans"
              description="Use scan activity to investigate customer verification events and review-needed signals."
              filename="licensee-admin-scan-activity.png"
              alt="Licensee Admin scan activity"
              caption="Scans: filter by code, batch, status, and date range."
              highlights={["Check first and repeated scans.", "Review unusual outcomes.", "Keep batch context before escalating."]}
            />
            <WorkflowScreenshotCard
              title="Check history"
              description="Use History to confirm approvals, assignments, print confirmations, and other operational changes."
              filename="licensee-admin-history.png"
              alt="Licensee Admin history"
              caption="History: audit activity for the company workspace."
              highlights={["Search by relevant record details.", "Use filters for action types.", "Expand technical details only when needed."]}
            />
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">What to do if something looks wrong</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Factory className="h-4 w-4 text-primary" />
                  Manufacturer cannot see a batch
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Open <Badge variant="outline">Manufacturers</Badge>, confirm the manufacturer is active, then open that manufacturer&apos;s batches.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Allocation quantity fails</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Reopen the source batch workspace and check the remaining unassigned quantity before retrying.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ScanLine className="h-4 w-4 text-primary" />
                  Scan result looks unusual
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Open <Badge variant="outline">Scans</Badge>, review the scan summary and batch context, then use History if you need an audit trail.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <History className="h-4 w-4 text-primary" />
                  Recent activity is missing
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Refresh the page or the batch workspace Audit tab. Use the support reporter if the data still does not update.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
