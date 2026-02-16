import React from "react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { HelpShell } from "@/pages/help/HelpShell";
import { ScreenshotChecklist, type ScreenshotNeed } from "@/components/help/ScreenshotChecklist";
import { Shield, Users, Factory, ScanLine, KeyRound, Siren, ClipboardList, Gavel, Mail } from "lucide-react";

const SCREENSHOTS: ScreenshotNeed[] = [
  { filename: "access-super-admin-login.png", whereToCapture: "Login page with Super Admin credentials entered.", usedIn: "Getting Access, Setting Your Password" },
  { filename: "password-accept-invite.png", whereToCapture: "Accept Invite page with password fields visible.", usedIn: "Setting Your Password" },
  { filename: "password-forgot-password.png", whereToCapture: "Forgot Password page with email filled.", usedIn: "Setting Your Password" },
  { filename: "password-reset-password.png", whereToCapture: "Reset Password page with new password fields visible.", usedIn: "Setting Your Password" },
  { filename: "superadmin-create-licensee.png", whereToCapture: "Licensees page with Add Licensee modal open.", usedIn: "Super Admin" },
  { filename: "superadmin-approve-qr-request.png", whereToCapture: "QR Requests page with Approve Request modal open.", usedIn: "Super Admin" },
  { filename: "licensee-request-qr-inventory.png", whereToCapture: "Licensee Admin QR Requests page with quantity filled and Submit highlighted.", usedIn: "Licensee/Admin" },
  { filename: "licensee-assign-batch.png", whereToCapture: "Batches page with Assign Manufacturer dialog open.", usedIn: "Licensee/Admin" },
  { filename: "licensee-create-manufacturer.png", whereToCapture: "Manufacturers page with Add Manufacturer modal open (Invite mode shown).", usedIn: "Licensee/Admin" },
  { filename: "manufacturer-create-print-job.png", whereToCapture: "Manufacturer Batches page with Create Print Job dialog open.", usedIn: "Manufacturer" },
  { filename: "manufacturer-download-print-pack.png", whereToCapture: "Create Print Job dialog showing Download ZIP action.", usedIn: "Manufacturer" },
  { filename: "manufacturer-print-status.png", whereToCapture: "Manufacturer Batches list showing Printed status updated.", usedIn: "Manufacturer" },
  { filename: "customer-first-verification.png", whereToCapture: "Public verify page showing Verified Authentic (first scan).", usedIn: "Customer" },
  { filename: "customer-verified-again.png", whereToCapture: "Public verify page showing Verified Again (repeat scan).", usedIn: "Customer" },
  { filename: "customer-possible-duplicate.png", whereToCapture: "Public verify page showing Possible Duplicate with reasons.", usedIn: "Customer" },
  { filename: "customer-report-dialog.png", whereToCapture: "Public verify page with Report suspected counterfeit dialog open.", usedIn: "Customer" },
  { filename: "ir-dashboard.png", whereToCapture: "IR Center page (Incidents/Alerts/Policies) as Super Admin.", usedIn: "Incident Response" },
  { filename: "ir-incident-actions.png", whereToCapture: "Incident detail page with containment actions dialog open.", usedIn: "Incident Actions" },
  { filename: "ir-policy-create.png", whereToCapture: "Policies tab with Create Policy dialog open.", usedIn: "Policy Alerts" },
  { filename: "ir-communication-compose.png", whereToCapture: "Incident detail page Communications section (compose email).", usedIn: "Communications" },
];

function HubCard({
  title,
  description,
  icon: Icon,
  href,
  badge,
}: {
  title: string;
  description: string;
  icon: React.ElementType;
  href: string;
  badge?: string;
}) {
  return (
    <Card className="h-full">
      <CardHeader className="space-y-1">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
              <Icon className="h-5 w-5 text-primary" />
            </span>
            <CardTitle className="text-lg">{title}</CardTitle>
          </div>
          {badge ? <Badge variant="outline">{badge}</Badge> : null}
        </div>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild variant="secondary" className="w-full">
          <Link to={href}>Open</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

export default function HelpHub() {
  return (
    <HelpShell
      title="Help Center"
      subtitle="Controlled operating procedures for Super Admin, Licensee/Admin, Manufacturer, and Customer workflows."
    >
      <div className="space-y-8">
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Start here</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <HubCard
              title="Auth overview"
              description="Authentication controls, session handling, and baseline security requirements."
              icon={KeyRound}
              href="/help/auth-overview"
            />
            <HubCard
              title="Getting access"
              description="Role onboarding and access provisioning using invite-based controls."
              icon={Users}
              href="/help/getting-access"
            />
            <HubCard
              title="Setting your password"
              description="First-time password setup, reset procedure, and lockout recovery path."
              icon={KeyRound}
              href="/help/setting-password"
            />
            <HubCard
              title="Roles & permissions"
              description="Role authorization matrix and tenant data visibility boundaries."
              icon={Gavel}
              href="/help/roles-permissions"
            />
          </div>
        </section>

        <Separator />

        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-foreground">By role</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <HubCard
              title="Super Admin"
              description="Platform governance: tenant administration, inventory approvals, and IR operations."
              icon={Shield}
              href="/help/superadmin"
              badge="Admin"
            />
            <HubCard
              title="Licensee/Admin (brand/company)"
              description="Organization-scoped operations: manufacturer onboarding, inventory requests, and batch assignment."
              icon={ClipboardList}
              href="/help/licensee"
            />
            <HubCard
              title="Manufacturer (factory user)"
              description="Factory execution procedure: print job creation, secure ZIP handling, and print validation."
              icon={Factory}
              href="/help/manufacturer"
            />
            <HubCard
              title="Customer (scanner / verification page)"
              description="Public verification workflow, repeat-scan interpretation, and counterfeit reporting."
              icon={ScanLine}
              href="/help/customer"
              badge="Public"
            />
          </div>
        </section>

        <Separator />

        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Incident Response</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <HubCard
              title="Incident Response overview"
              description="IR lifecycle control, triage procedure, and case ownership model."
              icon={Siren}
              href="/help/incident-response"
              badge="Super Admin"
            />
            <HubCard
              title="Policy alerts"
              description="Policy-rule design, alert triggers, and incident auto-creation behavior."
              icon={ClipboardList}
              href="/help/policy-alerts"
              badge="Super Admin"
            />
            <HubCard
              title="Incident actions"
              description="Containment controls, reinstatement process, and required justification records."
              icon={Gavel}
              href="/help/incident-actions"
              badge="Super Admin"
            />
            <HubCard
              title="Communications"
              description="Incident communications protocol, message logging, and traceability requirements."
              icon={Mail}
              href="/help/communications"
              badge="Super Admin"
            />
          </div>
        </section>

        <Separator />

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Documentation Assets</h2>
          <p className="text-sm text-muted-foreground">
            Screenshot validation runs automatically. Capture reminders appear only when a required documentation image is unavailable.
          </p>
          <ScreenshotChecklist items={SCREENSHOTS} />
        </section>
      </div>
    </HelpShell>
  );
}
