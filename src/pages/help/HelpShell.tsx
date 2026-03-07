import React from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Shield, ScanLine } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";
import { ComplianceStatements } from "@/components/help/ComplianceStatements";
import { getRoleHelpHome } from "@/help/contextual-help";
import { HELP_SITE_CONFIG } from "@/help/site-config";

export function HelpShell({
  title,
  subtitle,
  children,
  className,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  className?: string;
}) {
  const { isAuthenticated, user } = useAuth();
  const roleHelpHome = getRoleHelpHome(user?.role);
  const secondaryHelpLink =
    user?.role === "super_admin"
      ? { href: "/help/incident-response", label: "Incident Response" }
      : user?.role === "licensee_admin"
      ? { href: "/help/licensee-admin", label: "Licensee/Admin guide" }
      : user?.role === "manufacturer"
      ? { href: "/help/manufacturer", label: "Manufacturer guide" }
      : { href: "/help/customer", label: "Customer guide" };

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-30 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-3 px-4 py-3">
          <Link to="/help" className="flex items-center gap-2">
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </span>
            <div className="leading-tight">
              <p className="text-sm font-semibold text-foreground">Help Center</p>
              <p className="text-xs text-muted-foreground">{HELP_SITE_CONFIG.appName} documentation</p>
            </div>
          </Link>

          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <Link to={isAuthenticated ? "/dashboard" : "/login"}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                {isAuthenticated ? "Back to dashboard" : "Sign in"}
              </Link>
            </Button>
            <Button asChild size="sm" className="hidden sm:inline-flex">
              <Link to="/verify">
                <ScanLine className="mr-2 h-4 w-4" />
                Verify a product
              </Link>
            </Button>
            <Button asChild size="sm" className="sm:hidden">
              <Link to="/verify">
                <ScanLine className="h-4 w-4" />
                <span className="sr-only">Verify a product</span>
              </Link>
            </Button>
          </div>
        </div>
      </header>

      <main className={cn("mx-auto w-full max-w-5xl px-4 py-8", className)}>
        <div className="mb-8 space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight text-foreground">{title}</h1>
          {subtitle ? <p className="text-sm text-muted-foreground">{subtitle}</p> : null}
        </div>
        {children}
        <div className="mt-10">
          <ComplianceStatements />
        </div>
      </main>

      <footer className="border-t bg-muted/30">
        <div className="mx-auto flex max-w-5xl flex-col gap-2 px-4 py-6 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <p>Need something else? Open your role-specific help hub.</p>
          <div className="flex items-center gap-3">
            <Link to={roleHelpHome} className="hover:text-foreground">
              Help hub
            </Link>
            <span className="text-muted-foreground/50">|</span>
            <Link to={secondaryHelpLink.href} className="hover:text-foreground">
              {secondaryHelpLink.label}
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
