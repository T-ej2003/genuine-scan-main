import React from "react";
import { Link } from "react-router-dom";
import { HelpShell } from "@/pages/help/HelpShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { WorkflowScreenshotCard } from "@/components/help/WorkflowScreenshotCard";
import { NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL } from "@/features/printing/advanced-types";
import { Download, Factory, FileArchive, ShieldCheck, Wrench } from "lucide-react";

export default function ManufacturerHelp() {
  return (
    <HelpShell
      title="Manufacturer Admin"
      subtitle="Handle assigned batches, printer readiness, and controlled print jobs for your factory."
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
              <li>Use the approved secure print path for workstation or managed printer jobs.</li>
              <li>Confirm print status via the batch status indicators.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <FileArchive className="h-4 w-4" />
          <AlertTitle>Direct-print security mode</AlertTitle>
          <AlertDescription>
            ZIP/PNG distribution is disabled. Printing happens through the approved secure connector or managed printer route.
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
                  Start printing
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ol className="list-decimal pl-5">
                  <li>After job creation, the app sends approved print payloads through the selected printer route.</li>
                  <li>Workstation printing stays tied to the selected workstation printer. Factory label printer jobs go to saved LAN printer profiles. Office printer jobs send standards-based PDF jobs to AirPrint or IPP Everywhere printers.</li>
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
                <li>Batch and code statuses update to printed after the print workflow.</li>
                <li>If status does not update, refresh and retry once.</li>
                <li>If problems persist, contact your Licensee/Admin with the batch ID and timestamp.</li>
              </ul>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Printer readiness and troubleshooting</h2>
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline">
              <Link to="/connector-download">Install Connector</Link>
            </Button>
          </div>
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
                  <li>Open <Badge variant="outline">Install Connector</Badge> on the workstation that will print.</li>
                  <li>Choose the Mac or Windows installer for that workstation and run it once.</li>
                  <li>Let the installer verify whether the workstation can see a usable printer before you leave setup.</li>
                  <li>Confirm it is configured to auto-start at login and run in the background.</li>
                  <li>Make sure the operating system already lists the printer and driver correctly.</li>
                  <li>Use the <Badge variant="outline">Printer</Badge> status button in MSCQR and choose <Badge variant="outline">Refresh status</Badge>.</li>
                  <li>Confirm the workstation printer or saved network printer shows a ready state before returning to batches.</li>
                </ol>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">If a client says “it didn’t connect”</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <ul className="list-disc pl-5">
                  <li><Badge variant="outline">Connector unavailable</Badge> means MSCQR cannot detect the printer helper on that device.</li>
                  <li><Badge variant="outline">Connector installed, printer needs attention</Badge> means setup succeeded, but Windows or macOS is not exposing a usable online printer yet.</li>
                  <li><Badge variant="outline">No printer detected</Badge> means the connector is running but the operating system is not exposing a usable printer yet.</li>
                  <li><Badge variant="outline">Needs attention</Badge> means the saved printer route or secure connection still needs review.</li>
                  <li>If the connector is not installed yet, return to <Badge variant="outline">Install Connector</Badge> first.</li>
                  <li>Use the <Badge variant="outline">Printer</Badge> status button to separate those cases and gather support details.</li>
                </ul>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Printer compatibility matrix</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="grid gap-3 md:grid-cols-3">
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
                    Use this for controlled LAN label printers saved as approved printer profiles. Certified raw TCP profiles can run{" "}
                    <strong>{NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL}</strong>.
                  </p>
                </div>
                <div className="rounded-xl border bg-muted/20 p-4">
                  <div className="font-semibold text-foreground">NETWORK_IPP</div>
                  <p className="mt-2">
                    Use this for AirPrint and IPP Everywhere printers. Choose backend-direct when the app server can
                    reach the printer, or site gateway when the printer remains inside a private manufacturer LAN.
                  </p>
                </div>
              </div>
              <p className="text-xs">
                If a printer depends on the workstation driver or a non-certified queue, keep it on LOCAL_AGENT. Browser-submitted printing is intentionally disabled; MSCQR creates the job and the connector or certified route completes it directly.
              </p>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Core workflow screens</h2>
          <p className="text-sm text-muted-foreground">
            These screens cover the full manufacturer journey: install the connector, confirm printer readiness, create
            the job, and verify that the run completed correctly.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Install the connector"
              description="Start on the actual workstation that will print. This is the approved entry point for workstation-based printing."
              filename="manufacturer-connector-download.png"
              alt="Connector download page"
              caption="Install Connector: choose the package for the exact computer that will handle printing."
              highlights={[
                "Download the installer on the computer that has the printer attached or reachable.",
                "Finish installation before returning to batch operations.",
                "Use this page first when the connector is not running yet.",
              ]}
            />
            <WorkflowScreenshotCard
              title="Create the print job"
              description="Open your assigned batch, choose the approved printer path, and start the secure print run from the controlled dialog."
              filename="manufacturer-create-print-job.png"
              alt="Create print job modal"
              caption="Batches: select the quantity and approved printer route, then start the print job."
              highlights={[
                "Stay inside your assigned batch scope only.",
                "Confirm quantity, printer, and readiness in the same dialog.",
                "Use this dialog for the actual controlled dispatch step.",
              ]}
              eager
            />
            <WorkflowScreenshotCard
              title="Confirm the result"
              description="Return to the batch status view after printing so you can verify that the system recorded the completed run."
              filename="manufacturer-print-status.png"
              alt="Printed status update"
              caption="Batches: review the latest print status and confirm the run completed correctly."
              highlights={[
                "Check the status immediately after each print run.",
                "Confirm the printed count moved before creating a follow-up job.",
                "If the count is wrong, refresh once and then contact support with batch and time details.",
              ]}
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "manufacturer-connector-download.png",
                whereToCapture: "Illustrative connector download page showing Mac and Windows installer options plus the simple setup steps.",
              },
              {
                filename: "manufacturer-create-print-job.png",
                whereToCapture: "Illustrative Create Print Job dialog showing quantity, saved printer profile, readiness summary, and Start print action.",
              },
              {
                filename: "manufacturer-print-status.png",
                whereToCapture: "Illustrative print progress view showing current status and recent print confirmations.",
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
