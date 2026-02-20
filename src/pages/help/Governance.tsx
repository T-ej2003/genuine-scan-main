import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, SlidersHorizontal } from "lucide-react";

export default function GovernanceHelp() {
  return (
    <HelpShell
      title="Governance & Reliability"
      subtitle="Super Admin procedure for verification feature flags, retention lifecycle, compliance reporting, and route telemetry."
    >
      <div className="space-y-6">
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>Super Admin scope</AlertTitle>
          <AlertDescription>
            Governance controls are platform-level and should be changed only through approved change windows.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Sections on this page</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Verification UX feature flags</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Enable or disable customer verification behaviors (timeline card, risk card, claim, fraud report, mobile camera assist) per tenant policy.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Evidence retention lifecycle</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Configure retention window, legal hold tags, and purge/export settings. Run preview before apply.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Automated compliance report</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Generate UK GDPR/security/incident workflow summary with operational metrics for audit readiness.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Route transition telemetry</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Review route latency and verify-funnel drop signals captured from in-app telemetry.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Operational workflow</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <SlidersHorizontal className="h-4 w-4 text-primary" />
                Safe change sequence
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Choose tenant scope first.</li>
                <li>Apply feature-flag changes in small increments.</li>
                <li>Review verify page behavior and incident flow after each change.</li>
                <li>Run retention <Badge variant="outline">Preview</Badge> before <Badge variant="outline">Apply</Badge>.</li>
                <li>Generate compliance report and archive output for governance review.</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Feature flag save fails</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Confirm selected tenant scope is valid and that governance storage migration is applied.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Retention job blocked</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Check whether purge is enabled and whether legal hold tags exclude most records.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
