import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Siren, ShieldCheck } from "lucide-react";

export default function IncidentResponseHelp() {
  return (
    <HelpShell
      title="Incident Response"
      subtitle="How Super Admins triage policy alerts, manage incidents, and apply containment actions."
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
              <li>Incidents lifecycle and severity/priority.</li>
              <li>Where alerts come from and how they map to incidents.</li>
              <li>How to assign and document a case with a timeline.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Siren className="h-4 w-4" />
          <AlertTitle>Super Admin only</AlertTitle>
          <AlertDescription>
            The IR Center is restricted to platform admins. Actions taken in IR will be recorded in audit logs and the incident timeline.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Lifecycle overview</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Common statuses</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <p>Incidents move through a lifecycle, for example:</p>
              <ul className="list-disc pl-5">
                <li><Badge variant="outline">NEW</Badge> or <Badge variant="outline">TRIAGE</Badge>: needs review.</li>
                <li><Badge variant="outline">INVESTIGATING</Badge>: collecting evidence and correlating scans/reports.</li>
                <li><Badge variant="outline">CONTAINMENT</Badge>: applying reversible controls to reduce harm.</li>
                <li><Badge variant="outline">RECOVERY</Badge> / <Badge variant="outline">CLOSED</Badge>: resolution and follow-up.</li>
              </ul>
              <p className="text-xs">
                Tip: always add notes when changing status so the timeline explains why decisions were made.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">1. Open IR Center</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Sign in as Super Admin.</li>
                  <li>Open <Badge variant="outline">IR Center</Badge> from the left navigation.</li>
                  <li>Review <strong>Incidents</strong>, <strong>Alerts</strong>, and <strong>Policies</strong>.</li>
                </ol>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">2. Triage</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open a high severity item first.</li>
                  <li>Set owner/assignee and update severity/priority.</li>
                  <li>Add a note summarizing evidence and next steps.</li>
                </ol>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <DocScreenshot
            filename="ir-dashboard.png"
            alt="IR Center dashboard"
            caption="IR Center: incidents, alerts, and policies."
            eager
          />
          <ScreenshotChecklist
            items={[
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
                <CardTitle className="text-base">No alerts showing</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Alerts only appear after policy evaluation runs (typically triggered by scan ingestion). Confirm scans are being recorded and policies are enabled.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Can’t edit an incident</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Ensure you are signed in as Super Admin. If the incident is closed, reopen it before applying actions.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

