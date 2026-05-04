import React from "react";
import { Link } from "react-router-dom";
import { HelpShell } from "@/pages/help/HelpShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { WorkflowScreenshotCard } from "@/components/help/WorkflowScreenshotCard";
import { Factory, Printer, ShieldCheck, Wrench } from "lucide-react";

export default function ManufacturerHelp() {
  return (
    <HelpShell
      title="Manufacturer Admin"
      subtitle="Work assigned batches, confirm printer readiness, and start controlled MSCQR print jobs."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-primary" />
              Current scope
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc space-y-1 pl-5">
              <li>View assigned manufacturer batches only.</li>
              <li>Check printer readiness from the Printing page or print dialog.</li>
              <li>Create controlled print jobs for available assigned quantity.</li>
              <li>Review print status, scans, and history for your manufacturer scope.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <Printer className="h-4 w-4" />
          <AlertTitle>Current print workflow</AlertTitle>
          <AlertDescription>
            Browser ZIP or image-pack printing is not the current production workflow. MSCQR prints through the printer helper
            or an approved registered printer profile.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Core workflow</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Start from Overview"
              description="Confirm your assigned manufacturing scope before opening the print queue."
              filename="manufacturer-dashboard.png"
              alt="Manufacturer Overview"
              caption="Overview: assigned workspace totals, activity, and quick actions."
              highlights={["Confirm the correct brand workspace.", "Check activity before printing.", "Open Batches when ready."]}
              eager
            />
            <WorkflowScreenshotCard
              title="Install the printer helper"
              description="Install once on the computer that actually prints labels."
              filename="manufacturer-connector-download.png"
              alt="Install MSCQR printer helper"
              caption="Install Connector: choose the Mac or Windows installer for the printer computer."
              highlights={["Open this page on the printer computer.", "Run the installer once.", "Return to Printing to confirm readiness."]}
            />
            <WorkflowScreenshotCard
              title="Check printer setup"
              description="Confirm the saved printer profile is active and ready before a production run."
              filename="manufacturer-printer-setup.png"
              alt="Manufacturer printer setup"
              caption="Printing: registered printer profiles and readiness checks."
              highlights={["Use LOCAL_AGENT for workstation printers.", "Use NETWORK_DIRECT or NETWORK_IPP only for approved profiles.", "Refresh readiness before retrying failed jobs."]}
            />
            <WorkflowScreenshotCard
              title="Review assigned batches"
              description="Open Batches to see assigned quantities and available print inventory."
              filename="manufacturer-assigned-batches.png"
              alt="Manufacturer assigned batches"
              caption="Batches: assigned batch queue and print controls."
              highlights={["Check the ready-to-print count.", "Use filters for printed or unprinted work.", "Start only from batches assigned to you."]}
            />
            <WorkflowScreenshotCard
              title="Create a print job"
              description="Choose quantity and printer profile from the controlled dialog."
              filename="manufacturer-create-print-job.png"
              alt="Create print job"
              caption="Create Print Job: quantity, printer profile, and readiness summary."
              highlights={["Enter the quantity to print.", "Confirm the selected printer profile.", "Select Start print only when the route is correct."]}
            />
            <WorkflowScreenshotCard
              title="Confirm print status"
              description="Review the live print progress and recent job state after dispatch."
              filename="manufacturer-printing-status.png"
              alt="Manufacturer printing status"
              caption="Print status: confirmed count and printer route status."
              highlights={["Confirm the printer name.", "Watch printed counts update.", "Refresh readiness before retrying failed work."]}
            />
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Printer readiness</h2>
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline">
              <Link to="/connector-download">Install Connector</Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/printer-setup">Open Printing</Link>
            </Button>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">LOCAL_AGENT</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Use for USB, Wi-Fi, office, or workstation-managed printers that the operating system already sees.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">NETWORK_DIRECT</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Use for approved LAN label printers saved as registered factory printer profiles.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">NETWORK_IPP</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Use for approved AirPrint or IPP printers that accept standards-based PDF jobs.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">What to do if something looks wrong</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Factory className="h-4 w-4 text-primary" />
                  Batch not visible
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Ask your Licensee Admin to confirm the batch is assigned to your manufacturer account.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Wrench className="h-4 w-4 text-primary" />
                  Printer not ready
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Open <Badge variant="outline">Printing</Badge>, refresh readiness, and confirm the physical printer matches the selected profile.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
