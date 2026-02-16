import React from "react";

type ComplianceStatement = {
  id: string;
  title: string;
  body: React.ReactNode;
};

const STATEMENTS: ComplianceStatement[] = [
  {
    id: "uk-gdpr",
    title: "UK GDPR & Data Protection",
    body: (
      <>
        <span className="font-semibold">{"{{APP_NAME}}"}</span> processes personal data in accordance with UK GDPR
        and the Data Protection Act 2018. Data protection queries shall be directed to{" "}
        <span className="font-mono">{"{{DPO_EMAIL}}"}</span> or{" "}
        <span className="font-mono">{"{{SUPER_ADMIN_EMAIL}}"}</span>.
      </>
    ),
  },
  {
    id: "security-access",
    title: "Security & Access Control",
    body: (
      <>
        Access control is role-based (Super Admin, Licensee, Manufacturer). Communication is encrypted over HTTPS,
        passwords are handled using secure controls, and critical actions are captured in audit logs.
      </>
    ),
  },
  {
    id: "incident-response",
    title: "Incident Response & Fraud Reporting",
    body: <>The controlled process is: report intake -&gt; review -&gt; containment -&gt; documentation -&gt; resolution.</>,
  },
  {
    id: "qr-usage",
    title: "QR Code Usage & Non-Duplication",
    body: (
      <>
        All QR codes are unique, traceable, and single-use where applicable. QR codes must not be duplicated,
        altered, or reused.
      </>
    ),
  },
  {
    id: "audit-retention",
    title: "Audit Logging Notice",
    body: (
      <>
        Administrative actions, QR allocations, fraud reports, and login attempts are logged and retained for{" "}
        <span className="font-mono">{"{{RETENTION_DAYS}}"}</span> days.
      </>
    ),
  },
  {
    id: "acceptable-use",
    title: "Acceptable Use",
    body: (
      <>
        Unauthorized access, reverse engineering, misuse of fraud reporting, or interference with system security is
        prohibited.
      </>
    ),
  },
  {
    id: "hosting-disclaimer",
    title: "Hosting & Disclaimer",
    body: (
      <>
        The platform is hosted via <span className="font-mono">{"{{HOSTING_PROVIDER}}"}</span> with reasonable
        security controls and is provided on a best-effort basis.
      </>
    ),
  },
];

export function ComplianceStatements() {
  return (
    <section className="space-y-3 rounded-xl border border-slate-300 bg-slate-50 p-4">
      <div className="space-y-1">
        <h2 className="text-lg font-semibold text-foreground">Compliance Statements</h2>
        <p className="text-xs text-muted-foreground">
          Deployment placeholders must be finalized before release: <span className="font-mono">{"{{APP_NAME}}"}</span>
          , <span className="font-mono">{"{{DPO_EMAIL}}"}</span>,{" "}
          <span className="font-mono">{"{{SUPER_ADMIN_EMAIL}}"}</span>,{" "}
          <span className="font-mono">{"{{RETENTION_DAYS}}"}</span>,{" "}
          <span className="font-mono">{"{{HOSTING_PROVIDER}}"}</span>.
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
