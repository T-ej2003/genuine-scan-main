import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { Download, Factory, FileArchive, ShieldCheck, Wrench } from "lucide-react";

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
                  Start controlled dispatch
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>After job creation, MSCQR dispatches approved payloads through the selected printer profile.</li>
                  <li>Local-agent jobs stay tied to the workstation printer. Network-direct jobs are sent from the backend to the registered IP/port target.</li>
                  <li>Printed status updates as the job confirms on completion.</li>
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
          <h2 className="text-lg font-semibold text-foreground">Printer onboarding and diagnostics</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Wrench className="h-4 w-4 text-primary" />
                  Before you expect a printer to connect
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>Install and start the local MSCQR print agent on the workstation that will print.</li>
                  <li>Make sure the operating system already lists the printer and driver correctly.</li>
                  <li>Open <Badge variant="outline">http://127.0.0.1:17866/status</Badge> on that workstation.</li>
                  <li>Confirm the response lists at least one printer before returning to MSCQR.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">If a client says “it didn’t connect”</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li><Badge variant="outline">Agent offline</Badge> means the browser cannot reach the local print agent.</li>
                  <li><Badge variant="outline">No printer connection detected</Badge> means the agent is running but the OS exposed no printer.</li>
                  <li><Badge variant="outline">Trust blocked</Badge> means the server rejected the latest heartbeat or identity material.</li>
                  <li>Open <Badge variant="outline">Printer Diagnostics</Badge> to separate those cases and copy the diagnostic snapshot.</li>
                </ul>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Printer compatibility matrix</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-xl border bg-muted/20 p-4">
                  <div className="font-semibold text-foreground">LOCAL_AGENT</div>
                  <p className="mt-2">
                    Use this for USB, Wi-Fi, home, office, and workstation-managed industrial printers. The operating
                    system driver path must already work before MSCQR can use it.
                  </p>
                </div>
                <div className="rounded-xl border bg-muted/20 p-4">
                  <div className="font-semibold text-foreground">NETWORK_DIRECT</div>
                  <p className="mt-2">
                    Use this for controlled LAN label printers registered by IP and port in Printer Diagnostics.
                    Current direct dispatch support: <strong>ZPL</strong>, <strong>TSPL</strong>, <strong>EPL</strong>,
                    and <strong>CPCL</strong>.
                  </p>
                </div>
              </div>
              <p className="text-xs">
                If a printer uses SBPL, ESC/POS, or another language, keep it on the local-agent path until a direct
                adapter is added.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="manufacturer-print-job-annotated.svg"
              alt="Create print job modal"
              caption="Batches: select the printer profile, validate readiness, and start controlled dispatch."
              eager
            />
            <DocScreenshot
              filename="manufacturer-printer-diagnostics-annotated.svg"
              alt="Printer diagnostics"
              caption="Printer Diagnostics: choose LOCAL_AGENT vs NETWORK_DIRECT and validate registered profiles."
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
                filename: "manufacturer-print-job-annotated.svg",
                whereToCapture: "Manufacturer Batches page showing printer profile selection, dispatch mode, and Create Print Job action.",
              },
              {
                filename: "manufacturer-printer-diagnostics-annotated.svg",
                whereToCapture: "Printer Diagnostics page showing the compatibility matrix and registered printer validation controls.",
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
