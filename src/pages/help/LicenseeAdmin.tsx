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
              <CardTitle className="text-base">Manage a source batch from the workspace dialog</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Open <Badge variant="outline">Batches</Badge>.</li>
                <li>Find the source batch row and click <strong>Open</strong>.</li>
                <li>Use the <strong>Overview</strong> tab to confirm total quantity, remaining unassigned stock, and existing manufacturer allocations.</li>
                <li>Use the <strong>Operations</strong> tab to allocate more quantity, rename the source batch, open the allocation structure, or export the audit package.</li>
                <li>Use <strong>View allocation structure</strong> when you need to jump into a related source or manufacturer batch without leaving extra dialogs stacked on screen.</li>
                <li>Use the <strong>Audit</strong> tab to review the merged activity timeline for the source batch and every manufacturer allocation underneath it.</li>
              </ol>
              <p className="text-xs text-muted-foreground">
                The main table now stays stable with one row per original source batch. Split allocations are managed in the workspace instead of appearing as confusing extra rows in the list.
              </p>
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Find pending or printed work by manufacturer</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">Manufacturers</Badge>.</li>
                  <li>Select <strong>View details</strong> for the factory you need.</li>
                  <li>Use the <strong>Pending</strong> or <strong>Printed</strong> chips to jump into the right workload immediately.</li>
                  <li>Choose <strong>Open manufacturer batches</strong> to inspect assigned inventory directly.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Use QR Tracking without losing allocation context</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">QR Tracking</Badge> and filter by batch ID or batch name.</li>
                  <li>Open the allocation structure from the tracked batch when you need to understand where quantity moved.</li>
                  <li>Use batch ID, lifecycle totals, and audit history together before deciding a quantity is missing.</li>
                </ol>
              </CardContent>
            </Card>
          </div>
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
              filename="licensee-batch-workspace-annotated.svg"
              alt="Licensee batch workspace"
              caption="Batches: one stable source row opens a workspace for overview, operations, allocation structure, and merged audit history."
            />
            <DocScreenshot
              filename="licensee-manufacturer-ops-annotated.svg"
              alt="Manufacturer controls"
              caption="Manufacturers: add a factory user, inspect details, and jump into pending or printed work."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "licensee-request-qr-inventory.png",
                whereToCapture: "QR Requests page with quantity filled and Submit highlighted.",
              },
              {
                filename: "licensee-batch-workspace-annotated.svg",
                whereToCapture: "Batches page showing the stable source row and the workspace dialog with Overview, Operations, and Audit tabs.",
              },
              {
                filename: "licensee-manufacturer-ops-annotated.svg",
                whereToCapture: "Manufacturers page showing Add Manufacturer, View details, Pending/Printed chips, and Open manufacturer batches.",
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
                Open the source batch workspace first, then use <Badge variant="outline">View allocation structure</Badge>. It shows the current source remainder and every allocated manufacturer batch so you can assign only the true unassigned quantity.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Manufacturer can’t see a batch</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Open <Badge variant="outline">Manufacturers</Badge>, use <strong>View details</strong> or the <strong>Pending</strong>/<strong>Printed</strong> chips, then open that manufacturer’s batches directly.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Audit tab looks empty after a new allocation</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Click <strong>Refresh history</strong> in the workspace. The audit tab now merges source-batch trace events with batch audit logs for newly created manufacturer allocations.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
