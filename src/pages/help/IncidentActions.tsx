import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Gavel, ShieldAlert, ShieldCheck } from "lucide-react";

export default function IncidentActionsHelp() {
  return (
    <HelpShell
      title="Incident actions"
      subtitle="Containment controls available to Super Admins. All actions are logged and reversible with a reason."
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
              <li>Containment actions (QR, batch, manufacturer users, org/licensee).</li>
              <li>How actions affect the customer verify page.</li>
              <li>How to reinstate and document the reason.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <ShieldAlert className="h-4 w-4 text-amber-700" />
          <AlertTitle>Use the lightest effective action</AlertTitle>
          <AlertDescription>
            Start with “Under investigation” flags when possible. Suspending batches or orgs may impact legitimate customers.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Available actions</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Flag QR as under investigation</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Shows an <strong>Under investigation</strong> banner on the verify page for that QR.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Suspend a batch</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Prevents further trust in codes within the batch while investigation is ongoing.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Suspend manufacturer users</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Disables factory accounts that are suspected to be compromised.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Suspend an org/licensee</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Strong containment action. Use only when needed and document the reason clearly.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <Gavel className="h-4 w-4 text-primary" />
                Apply an action from an incident
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open the incident in <Badge variant="outline">IR Center</Badge>.</li>
                <li>Choose <strong>Actions</strong>.</li>
                <li>Select the action type (QR, batch, org, manufacturer user).</li>
                <li>Provide a reason and submit.</li>
                <li>Confirm the incident timeline includes the action event.</li>
              </ol>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Reinstate (undo) actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Return to the incident.</li>
                <li>Select the corresponding <strong>Reinstate</strong> action.</li>
                <li>Provide the reason (example: “False positive after investigation”).</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <DocScreenshot
            filename="ir-incident-actions.png"
            alt="Incident actions dialog"
            caption="Incident detail: containment actions dialog."
            eager
          />
          <ScreenshotChecklist
            items={[
              {
                filename: "ir-incident-actions.png",
                whereToCapture: "Incident detail page with containment actions dialog open.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Action doesn’t reflect on verify page</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Refresh the verify page. If the banner still does not show, confirm the action targeted the correct QR/batch and was not immediately reinstated.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Need to audit who did what</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Check both the incident timeline and the Audit Logs for the action event, including IP hash and user agent.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

