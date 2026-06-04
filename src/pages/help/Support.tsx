import React, { type FormEvent, useState } from "react";
import { HelpShell } from "@/pages/help/HelpShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Bell, CheckCircle2, Loader2, ShieldCheck, Ticket } from "lucide-react";
import apiClient from "@/lib/api-client";

type PublicSupportFormValues = {
  name: string;
  email: string;
  issueType: "verification_result" | "scan_problem" | "product_concern" | "platform_access" | "privacy" | "other";
  title: string;
  verificationCode: string;
  productReference: string;
  message: string;
};

const initialSupportValues: PublicSupportFormValues = {
  name: "",
  email: "",
  issueType: "verification_result",
  title: "",
  verificationCode: "",
  productReference: "",
  message: "",
};

export default function SupportHelp() {
  return (
    <HelpShell
      title="Support and Response"
      subtitle="Public guidance for getting help, plus the super admin workflow for ticket handling, SLA monitoring, and ticket-to-incident response."
    >
      <div className="space-y-6">
        <PublicSupportForm />

        <Alert>
          <ShieldCheck className="h-4 w-4" />
          <AlertTitle>How support works</AlertTitle>
          <AlertDescription>
            Public users can verify products and contact the MSCQR team for help. Authenticated users can also submit in-app issue reports. Support workflow handling and SLA ownership stay with Super Admin.
          </AlertDescription>
        </Alert>

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">How to get help</h2>
          <Card>
            <CardHeader className="space-y-1">
              <CardTitle className="text-base">Support entry points</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              <ul className="list-disc pl-5">
                <li>Use the public verifier first to confirm the QR code result and capture the exact issue.</li>
                <li>Authenticated users can submit an in-app support report with diagnostics and screenshots.</li>
                <li>For onboarding or platform administration queries, contact `administration@mscqr.com`.</li>
                <li>Super Admin replies are returned through system notifications and email.</li>
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
                <li>The top-right bell shows only the notifications that belong to your own role and system scope.</li>
                <li>
                  A green status dot indicates active live stream connection to the notification event channel.
                </li>
                <li>
                  The feed scrolls vertically like a normal inbox so you can review older items without using a slider control.
                </li>
                <li>
                  Click a notification to open the linked page (for example <Badge variant="outline">QR Requests</Badge> or{" "}
                  <Badge variant="outline">Incident Response</Badge>).
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

function PublicSupportForm() {
  const [values, setValues] = useState<PublicSupportFormValues>(initialSupportValues);
  const [errors, setErrors] = useState<Partial<Record<keyof PublicSupportFormValues, string>>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [result, setResult] = useState<{ referenceCode: string; message: string } | null>(null);
  const [submitError, setSubmitError] = useState("");

  const setField = (field: keyof PublicSupportFormValues, value: string) => {
    setValues((current) => ({ ...current, [field]: value }));
    setErrors((current) => ({ ...current, [field]: undefined }));
    setResult(null);
    setSubmitError("");
  };

  const validate = () => {
    const next: Partial<Record<keyof PublicSupportFormValues, string>> = {};
    if (!values.name.trim()) next.name = "Enter your name.";
    if (!values.email.trim()) next.email = "Enter your email.";
    if (values.email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) next.email = "Enter a valid email.";
    if (!values.title.trim()) next.title = "Add a short subject.";
    if (!values.message.trim() || values.message.trim().length < 10) next.message = "Describe the issue in at least 10 characters.";
    return next;
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextErrors = validate();
    setErrors(nextErrors);
    setSubmitError("");
    setResult(null);
    if (Object.keys(nextErrors).length > 0) return;

    setIsSubmitting(true);
    try {
      const response = await apiClient.submitPublicSupportIssue({
        name: values.name.trim(),
        email: values.email.trim(),
        issueType: values.issueType,
        title: values.title.trim(),
        verificationCode: values.verificationCode.trim(),
        productReference: values.productReference.trim(),
        message: values.message.trim(),
        sourcePath: "/help/support",
        pageUrl: typeof window !== "undefined" ? window.location.href : "",
        website: "",
      });
      if (!response.success || !response.data) throw new Error(response.error || "Could not submit support request.");
      setResult({
        referenceCode: response.data.referenceCode,
        message: response.data.message || "Support request received. Keep this reference for follow-up.",
      });
      setValues(initialSupportValues);
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Could not submit support request. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Card>
      <CardHeader className="space-y-2">
        <Badge variant="outline" className="w-fit">Public support</Badge>
        <CardTitle>Report a product verification or platform support issue</CardTitle>
        <p className="text-sm leading-6 text-muted-foreground">
          Tell MSCQR what happened. We will store the report, notify the support team, and return a reference number.
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} noValidate className="grid gap-4 md:grid-cols-2">
          <SupportField label="Name" id="support-name" error={errors.name}>
            <Input
              id="support-name"
              value={values.name}
              onChange={(event) => setField("name", event.target.value)}
              autoComplete="name"
              aria-invalid={Boolean(errors.name)}
            />
          </SupportField>
          <SupportField label="Email" id="support-email" error={errors.email}>
            <Input
              id="support-email"
              type="email"
              value={values.email}
              onChange={(event) => setField("email", event.target.value)}
              autoComplete="email"
              aria-invalid={Boolean(errors.email)}
            />
          </SupportField>
          <SupportField label="Issue type" id="support-issue-type">
            <Select
              value={values.issueType}
              onValueChange={(value) => setField("issueType", value as PublicSupportFormValues["issueType"])}
            >
              <SelectTrigger id="support-issue-type">
                <SelectValue placeholder="Choose issue type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="verification_result">Verification result</SelectItem>
                <SelectItem value="scan_problem">Scan problem</SelectItem>
                <SelectItem value="product_concern">Product concern</SelectItem>
                <SelectItem value="platform_access">Platform access</SelectItem>
                <SelectItem value="privacy">Privacy</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>
          </SupportField>
          <SupportField label="Subject" id="support-title" error={errors.title}>
            <Input
              id="support-title"
              value={values.title}
              onChange={(event) => setField("title", event.target.value)}
              placeholder="Example: Scan result does not match my garment"
              aria-invalid={Boolean(errors.title)}
            />
          </SupportField>
          <SupportField label="Verification code or QR token" id="support-verification-code">
            <Input
              id="support-verification-code"
              value={values.verificationCode}
              onChange={(event) => setField("verificationCode", event.target.value)}
              placeholder="Optional"
            />
          </SupportField>
          <SupportField label="Product or order reference" id="support-product-reference">
            <Input
              id="support-product-reference"
              value={values.productReference}
              onChange={(event) => setField("productReference", event.target.value)}
              placeholder="Optional"
            />
          </SupportField>
          <SupportField label="What happened?" id="support-message" error={errors.message} className="md:col-span-2">
            <Textarea
              id="support-message"
              rows={5}
              value={values.message}
              onChange={(event) => setField("message", event.target.value)}
              placeholder="Include the scan result, where you saw it, and what you expected."
              aria-invalid={Boolean(errors.message)}
            />
          </SupportField>
          <div className="md:col-span-2">
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Sending...
                </>
              ) : (
                "Send support request"
              )}
            </Button>
          </div>
          {result ? (
            <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800 md:col-span-2">
              <p className="flex items-center gap-2 font-semibold">
                <CheckCircle2 className="h-4 w-4" />
                Support request received
              </p>
              <p className="mt-1">{result.message}</p>
              <p className="mt-2 font-mono text-xs">Reference: {result.referenceCode}</p>
            </div>
          ) : null}
          {submitError ? (
            <p className="rounded-xl border border-destructive/20 bg-destructive/5 p-4 text-sm text-destructive md:col-span-2">
              {submitError}
            </p>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}

function SupportField({
  label,
  id,
  error,
  children,
  className,
}: {
  label: string;
  id: string;
  error?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <Label htmlFor={id}>{label}</Label>
      <div className="mt-2">{children}</div>
      {error ? (
        <p id={`${id}-error`} className="mt-2 text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
