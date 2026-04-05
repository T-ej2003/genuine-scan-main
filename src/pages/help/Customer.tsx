import React from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DocScreenshot } from "@/components/help/DocScreenshot";
import { ScreenshotChecklist } from "@/components/help/ScreenshotChecklist";
import { ScanLine, ShieldCheck, ShieldAlert, Flag } from "lucide-react";

export default function CustomerHelp() {
  return (
    <HelpShell
      title="Verify Product"
      subtitle="Check a product, understand the result, and report a suspected issue."
    >
      <div className="space-y-6">
        <Card>
          <CardHeader className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ScanLine className="h-4 w-4 text-primary" />
              What you can do
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            <ul className="list-disc pl-5">
              <li>Scan the code and start a secure verification session.</li>
              <li>Sign in, answer purchase-context questions, and then reveal the locked label decision.</li>
              <li>See a clear separation between label authenticity, your purchase context, and next actions.</li>
              <li>Report suspected counterfeit with contact details and purchase evidence.</li>
            </ul>
          </CardContent>
        </Card>

        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>Privacy</AlertTitle>
          <AlertDescription>
            The verify page stores scan events to detect duplicates. Location is stored as <strong>coarse city/country</strong> only, and IP is hashed server-side.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Result states</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldCheck className="h-4 w-4 text-emerald-600" />
                  Verified Authentic
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>First-time verification completed successfully.</p>
                <p className="text-xs">Tip: keep this screen as proof if asked.</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldCheck className="h-4 w-4 text-emerald-600" />
                  Verified Again
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>Repeat scans by the same buyer are normal.</p>
                <p className="text-xs">You can safely show this screen again if someone asks for proof.</p>
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  Possible Duplicate
                  <Badge variant="outline">Review</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                <p>This code shows unusual scan patterns that may indicate label copying.</p>
                <ul className="list-disc pl-5">
                  <li>Check the scan history summary and the “Why this was flagged” reasons.</li>
                  <li>If anything looks wrong, report it so the brand can investigate.</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Step-by-step</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Verify a product</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Scan the code on the product label.</li>
                <li>Sign in with email OTP or an enabled identity provider.</li>
                <li>Answer the purchase and packaging questions shown in the verify flow.</li>
                <li>Reveal the locked label decision and review the proof tier, lifecycle state, and next actions.</li>
              </ol>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="flex items-center gap-2 text-base">
                <Flag className="h-4 w-4 text-red-600" />
                Report suspected counterfeit
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <ol className="list-decimal pl-5">
                <li>Select <Badge variant="outline">Report suspected counterfeit</Badge>.</li>
                <li>Choose an incident type and describe what you observed.</li>
                <li>Add optional photos and purchase details if you have them.</li>
                <li>If you want updates, consent to contact and leave an email.</li>
              </ol>
            </CardContent>
          </Card>
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Screenshots</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <DocScreenshot
              filename="customer-first-verification.png"
              alt="Verified Authentic (first scan)"
              caption="First-time verification."
              eager
            />
            <DocScreenshot
              filename="customer-verified-again.png"
              alt="Verified Again (repeat scan)"
              caption="Repeat verification by the same buyer."
            />
            <DocScreenshot
              filename="customer-possible-duplicate.png"
              alt="Possible Duplicate"
              caption="Possible duplicate label warning and reasons."
            />
            <DocScreenshot
              filename="customer-report-dialog.png"
              alt="Report dialog"
              caption="Report suspected counterfeit form."
            />
          </div>
          <ScreenshotChecklist
            items={[
              {
                filename: "customer-first-verification.png",
                whereToCapture: "Public verify page showing Verified Authentic (first scan).",
              },
              {
                filename: "customer-verified-again.png",
                whereToCapture: "Public verify page showing Verified Again (repeat scan).",
              },
              {
                filename: "customer-possible-duplicate.png",
                whereToCapture: "Public verify page showing Possible Duplicate with reasons.",
              },
              {
                filename: "customer-report-dialog.png",
                whereToCapture: "Public verify page with Report suspected counterfeit dialog open.",
              },
            ]}
          />
        </section>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Troubleshooting</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">“Verification service unavailable”</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                The service may be temporarily down. Retry, or try again later. If it persists, contact the brand support shown on the page.
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="space-y-1">
                <CardTitle className="text-base">Code not registered / invalid</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">
                The code may be damaged, tampered, or not issued by the brand. Report it if you suspect counterfeit.
              </CardContent>
            </Card>
          </div>
        </section>
      </div>
    </HelpShell>
  );
}
