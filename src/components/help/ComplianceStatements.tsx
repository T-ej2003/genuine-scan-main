import React from "react";
import { HELP_COMPLIANCE_COPY, HELP_SITE_CONFIG } from "@/help/site-config";

type ComplianceStatement = {
  id: string;
  title: string;
  body: React.ReactNode;
};

const STATEMENTS: ComplianceStatement[] = [
  {
    id: "uk-gdpr",
    title: "UK GDPR & Data Protection",
    body: <>{HELP_COMPLIANCE_COPY.ukGdpr}</>,
  },
  {
    id: "security-access",
    title: "Security & Access Control",
    body: <>{HELP_COMPLIANCE_COPY.security}</>,
  },
  {
    id: "incident-response",
    title: "Incident Response & Fraud Reporting",
    body: <>{HELP_COMPLIANCE_COPY.incidentResponse}</>,
  },
  {
    id: "qr-usage",
    title: "QR Code Usage & Non-Duplication",
    body: <>{HELP_COMPLIANCE_COPY.qrUsage}</>,
  },
  {
    id: "audit-retention",
    title: "Audit Logging Notice",
    body: <>{HELP_COMPLIANCE_COPY.auditRetention}</>,
  },
  {
    id: "acceptable-use",
    title: "Acceptable Use",
    body: <>{HELP_COMPLIANCE_COPY.acceptableUse}</>,
  },
  {
    id: "hosting-disclaimer",
    title: "Hosting & Disclaimer",
    body: <>{HELP_COMPLIANCE_COPY.hosting}</>,
  },
];

export function ComplianceStatements() {
  return (
    <section className="space-y-3 rounded-xl border border-slate-300 bg-slate-50 p-4">
      <div className="space-y-1">
        <h2 className="text-lg font-semibold text-foreground">Compliance Statements</h2>
        <p className="text-xs text-muted-foreground">
          Active deployment values: <span className="font-semibold">{HELP_SITE_CONFIG.appName}</span>,{" "}
          <span className="font-mono">{HELP_SITE_CONFIG.dpoEmail}</span>,{" "}
          <span className="font-mono">{HELP_SITE_CONFIG.superAdminEmail}</span>,{" "}
          <span className="font-mono">{HELP_SITE_CONFIG.retentionDays}</span> day retention, hosted on{" "}
          <span className="font-semibold">{HELP_SITE_CONFIG.hostingProvider}</span>.
        </p>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {STATEMENTS.map((statement) => (
          <div key={statement.id} className="rounded-lg border border-slate-300 bg-white p-3">
            <p className="text-sm font-semibold text-slate-900">{statement.title}</p>
            <p className="mt-1 text-xs leading-5 text-slate-700">{statement.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
