import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Mail, ShieldCheck } from "lucide-react";

export default function CommunicationsHelp() {
  return (
    <HelpShell
      title="Communications"
      subtitle="Email reporters and org admins from an incident, and keep a complete case timeline."
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
              <li>Sending email from the incident detail page.</li>
              <li>How messages are stored and displayed in the incident timeline.</li>
              <li>How the sender address is chosen (EMAIL_FROM rule).</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Mail className="h-4 w-4" />
          <AlertTitle>EMAIL_FROM behavior</AlertTitle>
          <AlertDescription>
            Outbound emails use the primary Super Admin email when possible. If the SMTP provider rejects that From address, the system retries with the configured SMTP sender and sets Reply-To to the Super Admin.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Send an email</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open the incident detail page.</li>
                  <li>Scroll to <strong>Communications</strong>.</li>
                  <li>Choose recipient and write your message.</li>
                  <li>Select <Badge variant="outline">Send</Badge>.</li>
                </ol>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Review history</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>Sent messages appear in the incident timeline.</li>
                  <li>Failures are recorded with error details for troubleshooting.</li>
                  <li>Use notes for internal-only updates and emails for external communication.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <DocScreenshot
            filename="ir-communication-compose.png"
            alt="Compose incident communication"
            caption="Incident detail: compose and send an email."
            eager
          />
          <ScreenshotChecklist
            items={[
              {
                filename: "ir-communication-compose.png",
                whereToCapture: "Incident detail page Communications section (compose email).",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Email send failed</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Confirm SMTP is configured. If your provider rejects the From address, ensure the Super Admin email matches (or is allowed by) your SMTP sender domain.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">No recipient email available</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Some incidents may not have a reporter email. In that case, use internal notes and contact the licensee admin through known channels.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

