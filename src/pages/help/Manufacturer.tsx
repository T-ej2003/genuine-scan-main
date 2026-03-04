import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Download, Factory, FileArchive, ShieldCheck } from "lucide-react";

export default function ManufacturerHelp() {
  return (
    <HelpShell
      title="Manufacturer (factory user)"
      subtitle="Production execution: assigned batches, direct-print jobs, and one-time token handling."
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
              <li>View batches assigned to your manufacturer account only.</li>
              <li>Create print jobs for approved quantities.</li>
              <li>Request one-time short-lived render tokens via authenticated print agent.</li>
              <li>Confirm print status via the batch status indicators.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <FileArchive className="h-4 w-4" />
          <AlertTitle>Direct-print security mode</AlertTitle>
          <AlertDescription>
            ZIP/PNG distribution is disabled. Industrial printers must request one-time short-lived server render tokens
            for each QR just-in-time.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Factory className="h-4 w-4 text-primary" />
                  Create a print job
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Open <Badge variant="outline">Batches</Badge>.</li>
                  <li>Find your assigned batch.</li>
                  <li>Select <Badge variant="outline">Create Print Job</Badge>.</li>
                  <li>Enter the quantity to print and create.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Download className="h-4 w-4 text-primary" />
                  Request direct-print tokens
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>After job creation, issue one-time render tokens.</li>
                  <li>Your print agent resolves each token and renders QR just-in-time.</li>
                  <li>Printed status updates as tokens are consumed and job confirms on completion.</li>
                </ol>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">What to expect after direct-print</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ul className="list-disc pl-5">
                <li>Batch/QR statuses update to printed after the print workflow.</li>
                <li>If status does not update, refresh and retry once.</li>
                <li>If problems persist, contact your Licensee/Admin with the batch ID and timestamp.</li>
              </ul>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="manufacturer-create-print-job.png"
              alt="Create print job modal"
              caption="Batches: create print job."
              eager
            />
            <DocScreenshot
              filename="manufacturer-download-print-pack.png"
              alt="Issue direct-print tokens"
              caption="Print job: issue one-time render tokens."
            />
            <DocScreenshot
              filename="manufacturer-print-status.png"
              alt="Printed status update"
              caption="Batches: status updates after print workflow."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "manufacturer-create-print-job.png",
                whereToCapture: "Manufacturer Batches page with Create Print Job dialog open.",
              },
              {
                filename: "manufacturer-download-print-pack.png",
                whereToCapture: "Create Print Job dialog showing one-time direct-print token issuance.",
              },
              {
                filename: "manufacturer-print-status.png",
                whereToCapture: "Manufacturer Batches list showing Printed status updated.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Batch not found or not assigned”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                The batch is not assigned to your account. Confirm your manufacturer user and ask your Licensee/Admin to assign the batch.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Direct-print token expired</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Request a new one-time token set. If lock token has expired, create a fresh print job for remaining quantity.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
