import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { ClipboardList, Factory, FileText, ShieldCheck } from "lucide-react";

export default function LicenseeAdminHelp() {
  return (
    <HelpShell
      title="Licensee/Admin (brand/company)"
      subtitle="Operate within your organization: manufacturers, QR requests, batches, tracking, and audit logs."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-primary" />
              What you can do
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Create and manage manufacturer users under your licensee.</li>
              <li>Request additional QR inventory by quantity.</li>
              <li>Assign received QR batches to manufacturers.</li>
              <li>Monitor QR Tracking and review Audit Logs within your org scope.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <ClipboardList className="h-4 w-4" />
          <AlertTitle>Scope</AlertTitle>
          <AlertDescription>
            You only see data for your organization (licensee). You cannot access other licensees.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Key workflows</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Factory className="h-4 w-4 text-primary" />
                  Invite a manufacturer user
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">Manufacturers</Badge>.</li>
                  <li>Select <Badge variant="outline">Add Manufacturer</Badge>.</li>
                  <li>Enter the factory contact details.</li>
                  <li>Choose <strong>Invite</strong> (recommended) to send a one-time link.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <FileText className="h-4 w-4 text-primary" />
                  Request QR inventory
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">QR Requests</Badge>.</li>
                  <li>Enter the quantity you need.</li>
                  <li>Select <Badge variant="outline">Submit Request</Badge>.</li>
                  <li>After Super Admin approval, the received batch appears in <Badge variant="outline">Batches</Badge>.</li>
                </ol>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Assign a received batch to a manufacturer</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open <Badge variant="outline">Batches</Badge>.</li>
                <li>Find a received batch with remaining quantity.</li>
                <li>Open actions and choose <strong>Assign Manufacturer</strong>.</li>
                <li>Select the manufacturer and quantity, then submit.</li>
              </ol>
              <p className="text-xs text-muted-foreground">
                Allocation uses the next available unassigned codes to prevent overlaps.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="licensee-request-qr-inventory.png"
              alt="Licensee request QR inventory"
              caption="QR Requests: submit a quantity request."
              eager
            />
            <DocScreenshot
              filename="licensee-assign-batch.png"
              alt="Assign batch to manufacturer"
              caption="Batches: assign received inventory to a manufacturer."
            />
            <DocScreenshot
              filename="licensee-create-manufacturer.png"
              alt="Create manufacturer modal"
              caption="Manufacturers: invite a factory user."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "licensee-request-qr-inventory.png",
                whereToCapture: "QR Requests page with quantity filled and Submit highlighted.",
              },
              {
                filename: "licensee-assign-batch.png",
                whereToCapture: "Batches page with Assign Manufacturer dialog open.",
              },
              {
                filename: "licensee-create-manufacturer.png",
                whereToCapture: "Manufacturers page with Add Manufacturer modal open (Invite mode).",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Insufficient available quantity”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                The batch may already be partially assigned. Reduce the quantity and retry, then refresh the page.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Manufacturer can’t see a batch</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Confirm the batch was assigned to that manufacturer and the manufacturer user accepted their invite and can sign in.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}

