import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { HelpShell } from "@/pages/help/HelpShell";
import { ScreenshotChecklist, type ScreenshotNeed } from "@/components/help/ScreenshotChecklist";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, Users, Factory, ScanLine, KeyRound, Siren, ClipboardList, Gavel, Mail, CircleHelp, SlidersHorizontal } from "lucide-react";
import type { UserRole } from "@/types";

type ViewerRole = UserRole | "customer";

type HubCardConfig = {
  title: string;
  description: string;
  icon: React.ElementType;
  href: string;
  badge?: string;
  roles: Array<ViewerRole | "all">;
};

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
  { filename: "manufacturer-create-print-job.png", whereToCapture: "Illustrative Create Print Job dialog showing the saved printer profile, readiness note, and Start print action.", usedIn: "Manufacturer" },
  { filename: "manufacturer-printer-diagnostics.png", whereToCapture: "Illustrative Printer Setup & Support page showing the compatibility matrix, setup guidance, and profile validation actions.", usedIn: "Manufacturer" },
  { filename: "manufacturer-print-status.png", whereToCapture: "Illustrative print progress view showing current status and recent print confirmations.", usedIn: "Manufacturer" },
  { filename: "customer-first-verification.png", whereToCapture: "Public verify page showing Verified Authentic (first scan).", usedIn: "Customer" },
  { filename: "customer-verified-again.png", whereToCapture: "Public verify page showing Verified Again (repeat scan).", usedIn: "Customer" },
  { filename: "customer-possible-duplicate.png", whereToCapture: "Public verify page showing Possible Duplicate with reasons.", usedIn: "Customer" },
  { filename: "customer-report-dialog.png", whereToCapture: "Public verify page with Report suspected counterfeit dialog open.", usedIn: "Customer" },
  { filename: "ir-dashboard.png", whereToCapture: "IR Center page (Incidents/Alerts/Policies) as Super Admin.", usedIn: "Incident Response" },
  { filename: "ir-incident-actions.png", whereToCapture: "Incident detail page with containment actions dialog open.", usedIn: "Incident Actions" },
  { filename: "ir-policy-create.png", whereToCapture: "Policies tab with Create Policy dialog open.", usedIn: "Policy Alerts" },
  { filename: "ir-communication-compose.png", whereToCapture: "Incident detail page Communications section (compose email).", usedIn: "Communications" },
];

const START_CARDS: HubCardConfig[] = [
  {
    title: "Auth overview",
    description: "Simple explanation of sign-in, session, and account security basics.",
    icon: KeyRound,
    href: "/help/auth-overview",
    roles: ["all"],
  },
  {
    title: "Getting access",
    description: "How users are invited and activated safely.",
    icon: Users,
    href: "/help/getting-access",
    roles: ["all"],
  },
  {
    title: "Setting your password",
    description: "First-time setup and reset steps in plain language.",
    icon: KeyRound,
    href: "/help/setting-password",
    roles: ["all"],
  },
  {
    title: "Roles & permissions",
    description: "Who can do what, and what data each role can see.",
    icon: Gavel,
    href: "/help/roles-permissions",
    roles: ["all"],
  },
];

const ROLE_CARDS: HubCardConfig[] = [
  {
    title: "Super Admin",
    description: "Platform governance, tenant setup, approvals, and full incident response.",
    icon: Shield,
    href: "/help/super-admin",
    badge: "Admin",
    roles: ["super_admin"],
  },
  {
    title: "Licensee/Admin",
    description: "Brand-level operations: requests, batches, and manufacturer onboarding.",
    icon: ClipboardList,
    href: "/help/licensee-admin",
    roles: ["licensee_admin"],
  },
  {
    title: "Manufacturer",
    description: "Factory-side print workflow and assigned batch execution.",
    icon: Factory,
    href: "/help/manufacturer",
    roles: ["manufacturer"],
  },
  {
    title: "Customer",
    description: "Public verification meanings, repeat scans, and fraud report steps.",
    icon: ScanLine,
    href: "/help/customer",
    badge: "Public",
    roles: ["customer"],
  },
];

const INCIDENT_CARDS: HubCardConfig[] = [
  {
    title: "Incidents",
    description: "Queue-first incident triage, assignment, evidence, and closure quality checks.",
    icon: ClipboardList,
    href: "/help/incidents",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Incident Response overview",
    description: "How to triage, contain, document, and resolve incidents.",
    icon: Siren,
    href: "/help/incident-response",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Policy alerts",
    description: "How policy alerts are created, reviewed, and actioned.",
    icon: Shield,
    href: "/help/policy-alerts",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Incident actions",
    description: "Containment and reinstatement actions with audit-safe justification.",
    icon: Gavel,
    href: "/help/incident-actions",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Communications",
    description: "Customer and admin communication guidance with traceability.",
    icon: Mail,
    href: "/help/communications",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Support tickets",
    description: "Support queue operations, SLA handling, and ticket updates linked to incidents.",
    icon: CircleHelp,
    href: "/help/support",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
  {
    title: "Governance & Reliability",
    description: "Feature flags, retention lifecycle, compliance reporting, and route telemetry.",
    icon: SlidersHorizontal,
    href: "/help/governance",
    badge: "Super Admin",
    roles: ["super_admin"],
  },
];

const roleLabel = (role: ViewerRole) => {
  if (role === "super_admin") return "Super Admin";
  if (role === "licensee_admin") return "Licensee Admin";
  if (role === "manufacturer") return "Manufacturer";
  return "Customer";
};

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
  const { user } = useAuth();

  const viewerRole: ViewerRole = user?.role || "customer";
  const isSuperAdmin = viewerRole === "super_admin";

  const visibleCards = useMemo(() => {
    const includeCard = (card: HubCardConfig) => {
      if (isSuperAdmin) return true;
      return card.roles.includes("all") || card.roles.includes(viewerRole);
    };

    return {
      start: START_CARDS.filter(includeCard),
      role: ROLE_CARDS.filter(includeCard),
      incident: INCIDENT_CARDS.filter(includeCard),
    };
  }, [isSuperAdmin, viewerRole]);

  return (
    <HelpShell
      title="Help Center"
      subtitle="Role-based, plain-language guides so users can complete tasks without prior technical knowledge."
    >
      <div className="space-y-8">
        <section className="rounded-lg border border-slate-200 bg-slate-50 p-4">
          <p className="text-sm text-slate-700">
            Showing guidance for <span className="font-semibold">{roleLabel(viewerRole)}</span>
            {isSuperAdmin ? " (full access)." : "."}
          </p>
        </section>

        {visibleCards.start.length > 0 ? (
          <section className="space-y-4">
            <h2 className="text-lg font-semibold text-foreground">Start here</h2>
            <div className="grid gap-4 md:grid-cols-2">
              {visibleCards.start.map((card) => (
                <HubCard key={card.href} {...card} />
              ))}
            </div>
          </section>
        ) : null}

        {visibleCards.role.length > 0 ? (
          <>
            <Separator />
            <section className="space-y-4">
              <h2 className="text-lg font-semibold text-foreground">Your role guides</h2>
              <div className="grid gap-4 md:grid-cols-2">
                {visibleCards.role.map((card) => (
                  <HubCard key={card.href} {...card} />
                ))}
              </div>
            </section>
          </>
        ) : null}

        {visibleCards.incident.length > 0 ? (
          <>
            <Separator />
            <section className="space-y-4">
              <h2 className="text-lg font-semibold text-foreground">Incident Response</h2>
              <div className="grid gap-4 md:grid-cols-2">
                {visibleCards.incident.map((card) => (
                  <HubCard key={card.href} {...card} />
                ))}
              </div>
            </section>
          </>
        ) : null}

        <Separator />

        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Documentation Assets</h2>
          {isSuperAdmin ? (
            <>
              <p className="text-sm text-muted-foreground">
                Screenshot validation runs automatically. Capture reminders appear only when a required documentation image is unavailable.
              </p>
              <ScreenshotChecklist items={SCREENSHOTS} />
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              Documentation asset management is available to Super Admin only.
            </p>
          )}
        </section>
      </div>
    </HelpShell>
  );
}
