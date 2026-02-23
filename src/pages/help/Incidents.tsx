import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ClipboardList, ShieldAlert } from "lucide-react";

export default function IncidentsHelp() {
  return (
    <HelpShell
      title="Incidents"
      subtitle="Super Admin incident queue guide for triage, assignment, evidence handling, and resolution quality."
    >
      <div className="space-y-6">
        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <ShieldAlert className="h-4 w-4 text-amber-700" />
          <AlertTitle>Decision traceability required</AlertTitle>
          <AlertDescription>
            Every status/severity/assignment change should include a note so incident timeline and audit records remain complete.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">What to review in queue</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Queue-first triage</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Filter by status and severity.</li>
                <li>Prioritize <Badge variant="outline">CRITICAL</Badge> and <Badge variant="outline">HIGH</Badge> items first.</li>
                <li>Open incident detail and validate signals (classification, scan summary, ownership conflicts).</li>
                <li>Assign owner and target next action.</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Investigation workflow</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Evidence and notes</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Attach evidence, review tamper-check signals, and keep narrative notes synchronized with each decision.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Containment and communication</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Apply containment actions through IR actions workflow and send customer/licensee communications with clear outcome messages.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Resolution criteria</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <ClipboardList className="h-4 w-4 text-primary" />
                Before closing an incident
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ul className="list-disc pl-5">
                <li>Root cause recorded.</li>
                <li>Containment status confirmed (or explicitly not required).</li>
                <li>Customer/support communications logged.</li>
                <li>Follow-up controls identified when needed.</li>
              </ul>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Reference screenshot</h2>
          <DocScreenshot
            filename="ir-incident-actions.png"
            alt="Incident detail action view"
            caption="Incident detail with action workflow and evidence timeline."
            eager
          />
        </section>
      </div>
    </HelpShell>
  );
}
