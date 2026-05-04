import React from "react";
import { Link } from "react-router-dom";
import { HelpShell } from "@/pages/help/HelpShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { WorkflowScreenshotCard } from "@/components/help/WorkflowScreenshotCard";
import { Flag, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";

export default function CustomerHelp() {
  return (
    <HelpShell
      title="Verify a Garment"
      subtitle="Scan or enter a garment QR label, read the result, and report a concern when something looks suspicious."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ScanLine className="h-4 w-4 text-primary" />
              What you can do
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc space-y-1 pl-5">
              <li>Scan the QR label or enter the printed code manually.</li>
              <li>Read whether MSCQR verified the garment or needs review.</li>
              <li>Review brand, manufacturer, status, scan summary, and support details.</li>
              <li>Report a concern if the result, product, seller, or label looks suspicious.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>Privacy and scan records</AlertTitle>
          <AlertDescription>
            MSCQR records scan events to detect unusual repeated use and support investigations. Camera capture depends on browser support;
            manual code entry works on every device.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Core workflow</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <WorkflowScreenshotCard
              title="Start verification"
              description="Open the verify page, scan the QR label, or enter the printed code manually."
              filename="customer-verify-start.png"
              alt="Customer verify start"
              caption="Verify: scan a label or enter a garment code."
              highlights={["Use Scan QR label when your browser supports it.", "Use manual entry on any device.", "Select Check garment to open the result."]}
              eager
            />
            <WorkflowScreenshotCard
              title="Read a verified result"
              description="A successful check shows the current customer-facing verified result."
              filename="customer-result-verified.png"
              alt="Customer verified result"
              caption="Result: this garment is genuine and verified by MSCQR."
              highlights={["Read the banner first.", "Review brand and manufacturer details.", "Check the scan summary and support contact."]}
            />
            <WorkflowScreenshotCard
              title="Understand repeat checks"
              description="A repeat scan can still be normal when the scan pattern looks consistent."
              filename="customer-result-verified-again.png"
              alt="Customer repeat verification"
              caption="Result: a previously checked code can still be shown as verified when context is normal."
              highlights={["Repeat checks can happen when you scan again.", "Review scan timing if unsure.", "Report a concern if the item or seller looks suspicious."]}
            />
            <WorkflowScreenshotCard
              title="Read a review-needed result"
              description="MSCQR uses this state when scan details need review before you rely on the item."
              filename="customer-result-review-required.png"
              alt="Customer review-needed result"
              caption="Result: MSCQR could not fully verify the item."
              highlights={["Review the warning carefully.", "Check product and seller details.", "Use Report a concern if something looks wrong."]}
            />
            <WorkflowScreenshotCard
              title="Report a concern"
              description="Send the brand useful context when the label, product, seller, or result seems suspicious."
              filename="customer-report-concern.png"
              alt="Customer report concern"
              caption="Report: choose a reason, add details, and submit the concern."
              highlights={["Choose the closest reason.", "Describe what happened.", "Keep any support reference shown after submit."]}
            />
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Result states</h2>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldCheck className="h-4 w-4 text-emerald-600" />
                  This garment is genuine
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                MSCQR found the brand record and the available verification checks passed.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  We could not fully verify this item
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Scan details need review. Check the page details and report a concern if the item looks suspicious.
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Flag className="h-4 w-4 text-red-600" />
                  QR label blocked or not found
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                Do not rely on the item until you check the code, review the page guidance, or contact the brand.
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">What to do if something looks wrong</h2>
          <Card>
            <CardContent className="space-y-2 pt-6 text-sm text-muted-foreground">
              <p>Use manual code entry if camera scan fails. If the result is review-needed, blocked, or not found, check the tag and product details before relying on the item.</p>
              <p>When in doubt, use Report a concern or the brand support contact shown on the result page.</p>
              <Button asChild variant="outline">
                <Link to="/verify">Open Verify</Link>
              </Button>
            </CardContent>
          </Card>
        </section>
      </div>
    </HelpShell>
  );
}
