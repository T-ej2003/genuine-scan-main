import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Bell, ShieldCheck, Ticket } from "lucide-react";

export default function SupportHelp() {
  return (
    <HelpShell
      title="Support Tickets"
      subtitle="Super Admin guide for support queue handling, SLA monitoring, and ticket-to-incident workflow."
    >
      <div className="space-y-6">
        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>Super Admin scope</AlertTitle>
          <AlertDescription>
            Support workflow is restricted to Super Admin. Every ticket update is captured in audit logs and linked incident history.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">What the Support page is for</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Ticket operations</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              <ul className="list-disc pl-5">
                <li>Review ticket queue by status, priority, and search terms.</li>
                <li>Open ticket detail with incident stage and SLA context.</li>
                <li>Set ticket status and assignment.</li>
                <li>Add internal or customer-facing support notes.</li>
              </ul>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Real-time in-app notifications</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <Bell className="h-4 w-4 text-primary" />
                Notification bell behavior
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>The top-right bell receives live updates for requests and alerts.</li>
                <li>
                  A green status dot indicates active live stream connection to the notification event channel.
                </li>
                <li>
                  Click a notification to open the linked page (for example <Badge variant="outline">QR Requests</Badge> or{" "}
                  <Badge variant="outline">Incidents</Badge>).
                </li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Ticket lifecycle</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Common statuses</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>
                    <Badge variant="outline">OPEN</Badge>: intake complete, waiting for admin action.
                  </li>
                  <li>
                    <Badge variant="outline">IN_PROGRESS</Badge>: active investigation and handling.
                  </li>
                  <li>
                    <Badge variant="outline">WAITING_CUSTOMER</Badge>: waiting for customer response/details.
                  </li>
                  <li>
                    <Badge variant="outline">RESOLVED</Badge> / <Badge variant="outline">CLOSED</Badge>: completed.
                  </li>
                </ul>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">SLA handling</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li>SLA timer is shown in ticket queue and ticket detail.</li>
                  <li>Breached tickets should be prioritized and documented.</li>
                  <li>When resolving, add a concise note before closure.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step workflow</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <Ticket className="h-4 w-4 text-primary" />
                Process
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open `Support` and filter by high priority or breached SLA first.</li>
                <li>Select a ticket and confirm linked incident state.</li>
                <li>Set status/assignee and save workflow update.</li>
                <li>Add a clear message in ticket timeline (internal or external).</li>
                <li>Move to `Resolved` only after containment and documentation are complete.</li>
              </ol>
            </CardContent>
          </Card>
        </section>
      </div>
    </HelpShell>
  );
}
