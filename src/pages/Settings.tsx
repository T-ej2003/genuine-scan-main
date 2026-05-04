import React from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  CircleHelp,
  Cog,
  Printer,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import {
  PageSection,
  SettingsPagePattern,
} from "@/components/page-patterns/PagePatterns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/contexts/AuthContext";
import { APP_PATHS } from "@/app/route-metadata";

type SettingsCard = {
  id: string;
  title: string;
  description: string;
  href: string;
  actionLabel: string;
  icon: typeof UserRound;
  badge?: string;
};

const cardStyles = "rounded-[24px] border border-border/80 bg-white/90 p-5 shadow-[0_20px_44px_-40px_rgba(15,23,42,0.5)]";

export default function SettingsPage() {
  const { user } = useAuth();

  const personalCards: SettingsCard[] = [
    {
      id: "account",
      title: "Account details",
      description: "Update your name, email, password, and sign-in safety in one place.",
      href: APP_PATHS.account,
      actionLabel: "Open account settings",
      icon: UserRound,
    },
  ];

  const printerCards: SettingsCard[] =
    user?.role === "manufacturer"
      ? [
          {
            id: "printer-setup",
            title: "Printer setup",
            description: "Connect the printer on this computer, save it, and run a live test label.",
            href: APP_PATHS.printerSetup,
            actionLabel: "Open printer setup",
            icon: Printer,
            badge: "Recommended",
          },
          {
            id: "printer-helper",
            title: "Printer helper download",
            description: "Install or update the printer helper on the Mac or Windows computer that prints labels.",
            href: APP_PATHS.connectorDownload,
            actionLabel: "Open helper downloads",
            icon: Printer,
          },
        ]
      : [];

  const systemCards: SettingsCard[] =
    user?.role === "super_admin"
      ? [
          {
            id: "governance",
            title: "System controls",
            description: "Manage retention, rollout controls, approvals, and other platform-wide settings.",
            href: APP_PATHS.governance,
            actionLabel: "Open system settings",
            icon: Cog,
          },
        ]
      : [];

  return (
    <DashboardLayout>
      <SettingsPagePattern
        eyebrow="Settings"
        title="Settings home"
        description="Choose the area you want to update. Account, printer, and system controls now start here instead of being scattered around the workspace."
        actions={
          <Button asChild variant="outline">
            <Link to={APP_PATHS.dashboard}>
              Back to dashboard
              <ArrowRight className="h-4 w-4" />
            </Link>
          </Button>
        }
      >
        <PageSection
          title="Personal settings"
          description="Keep your profile and sign-in details current."
        >
          <div className="grid gap-4 lg:grid-cols-2">
            {personalCards.map((item) => (
              <Card key={item.id} className={cardStyles}>
                <CardContent className="p-0">
                  <div className="flex items-start justify-between gap-3">
                    <div className="rounded-2xl bg-emerald-100 p-3 text-emerald-700">
                      <item.icon className="h-5 w-5" />
                    </div>
                    {item.badge ? <Badge className="bg-emerald-100 text-emerald-800 hover:bg-emerald-100">{item.badge}</Badge> : null}
                  </div>
                  <div className="mt-5 space-y-2">
                    <h2 className="text-xl font-semibold text-foreground">{item.title}</h2>
                    <p className="text-sm leading-6 text-muted-foreground">{item.description}</p>
                  </div>
                  <div className="mt-5">
                    <Button asChild data-testid="settings-open-account">
                      <Link to={item.href}>
                        {item.actionLabel}
                        <ArrowRight className="h-4 w-4" />
                      </Link>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </PageSection>

        {printerCards.length > 0 ? (
          <PageSection
            title="Printer settings"
            description="Use this section when you need to connect, save, check, or update the printer on this computer."
          >
            <div className="grid gap-4 lg:grid-cols-2">
              {printerCards.map((item) => (
                <Card key={item.id} className={cardStyles}>
                  <CardContent className="p-0">
                    <div className="flex items-start justify-between gap-3">
                      <div className="rounded-2xl bg-sky-100 p-3 text-sky-700">
                        <item.icon className="h-5 w-5" />
                      </div>
                      {item.badge ? <Badge className="bg-emerald-100 text-emerald-800 hover:bg-emerald-100">{item.badge}</Badge> : null}
                    </div>
                    <div className="mt-5 space-y-2">
                      <h2 className="text-xl font-semibold text-foreground">{item.title}</h2>
                      <p className="text-sm leading-6 text-muted-foreground">{item.description}</p>
                    </div>
                    <div className="mt-5">
                      <Button
                        asChild
                        variant={item.id === "printer-setup" ? "default" : "outline"}
                        data-testid={item.id === "printer-setup" ? "settings-open-printer-setup" : undefined}
                      >
                        <Link to={item.href}>
                          {item.actionLabel}
                          <ArrowRight className="h-4 w-4" />
                        </Link>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </PageSection>
        ) : null}

        {systemCards.length > 0 ? (
          <PageSection
            title="System settings"
            description="Platform-wide controls stay here so governance changes are separated from day-to-day operations."
          >
            <div className="grid gap-4 lg:grid-cols-2">
              {systemCards.map((item) => (
                <Card key={item.id} className={cardStyles}>
                  <CardContent className="p-0">
                    <div className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-amber-100 text-amber-700">
                      <item.icon className="h-5 w-5" />
                    </div>
                    <div className="mt-5 space-y-2">
                      <h2 className="text-xl font-semibold text-foreground">{item.title}</h2>
                      <p className="text-sm leading-6 text-muted-foreground">{item.description}</p>
                    </div>
                    <div className="mt-5">
                      <Button asChild data-testid="settings-open-system-settings">
                        <Link to={item.href}>
                          {item.actionLabel}
                          <ArrowRight className="h-4 w-4" />
                        </Link>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </PageSection>
        ) : null}

        <PageSection
          title="Need help?"
          description="Get the right guidance page for your role before you change a setting."
        >
          <div className="flex flex-wrap gap-3">
            <Button asChild variant="outline">
              <Link to="/help/setting-password">
                <CircleHelp className="h-4 w-4" />
                Sign-in help
              </Link>
            </Button>
            {user?.role === "manufacturer" ? (
              <Button asChild variant="outline">
                <Link to="/help/manufacturer">
                  <Printer className="h-4 w-4" />
                  Printer help
                </Link>
              </Button>
            ) : null}
            {user?.role === "super_admin" ? (
              <Button asChild variant="outline">
                <Link to="/help/governance">
                  <ShieldCheck className="h-4 w-4" />
                  System help
                </Link>
              </Button>
            ) : null}
          </div>
        </PageSection>
      </SettingsPagePattern>
    </DashboardLayout>
  );
}
