import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { ClipboardList, ShieldCheck } from "lucide-react";

export default function PolicyAlertsHelp() {
  return (
    <HelpShell
      title="Policy alerts"
      subtitle="How policy rules detect anomalies (duplicate labels, geo drift, scan bursts) and raise alerts."
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
              <li>What policy rules exist and what signals they use.</li>
              <li>How to create or tune rules.</li>
              <li>How alerts are acknowledged and linked to incidents.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <ClipboardList className="h-4 w-4" />
          <AlertTitle>Policy rules are configurable</AlertTitle>
          <AlertDescription>
            Policies can be adjusted as counterfeit tactics evolve. Keep thresholds realistic to avoid false alarms.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Rule types (examples)</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Distinct devices</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Triggers when the same QR is scanned by many different device fingerprints inside a short window.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Multi-country / geo drift</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Triggers when coarse locations change in an unrealistic timeframe.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Burst scans</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Triggers when scan rate spikes (many scans in minutes). Useful for detecting copied labels posted online.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Too many reports</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Triggers when many incident reports arrive for the same org/manufacturer within a window.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Create a policy rule</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open <Badge variant="outline">IR Center</Badge>.</li>
                <li>Switch to the <Badge variant="outline">Policies</Badge> tab.</li>
                <li>Select <strong>Create policy</strong>.</li>
                <li>Choose the rule type and set thresholds/time window.</li>
                <li>Enable the rule.</li>
              </ol>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Acknowledge alerts</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open the <Badge variant="outline">Alerts</Badge> tab.</li>
                <li>Review the reason and linked entities (QR/org/manufacturer).</li>
                <li>Acknowledge the alert once triaged, or create an incident.</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="ir-policy-create.png"
              alt="Create policy rule"
              caption="Policies: create or tune a policy rule."
              eager
            />
            <DocScreenshot
              filename="ir-dashboard.png"
              alt="IR Center dashboard"
              caption="IR Center tabs (Incidents, Alerts, Policies)."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "ir-policy-create.png",
                whereToCapture: "Policies tab with Create Policy dialog open.",
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
                <CardTitle className="text-base">Too many alerts</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Lower sensitivity by increasing thresholds or expanding time windows. Use “acknowledge” to reduce noise after review.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">No alerts triggered</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Confirm the rule is enabled and scans/reports are being recorded. Alerts require activity to evaluate against.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

