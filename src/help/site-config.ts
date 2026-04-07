const envString = (value: unknown, fallback: string) => {
  const normalized = String(value || "").trim();
  return normalized || fallback;
};

const envNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

export const HELP_SITE_CONFIG = {
  appName: envString(import.meta.env.VITE_APP_DISPLAY_NAME, "MSCQR"),
  dpoEmail: envString(import.meta.env.VITE_DPO_EMAIL, "administration@mscqr.com"),
  superAdminEmail: envString(import.meta.env.VITE_SUPER_ADMIN_EMAIL, "administration@mscqr.com"),
  retentionDays: envNumber(import.meta.env.VITE_RETENTION_DAYS, 180),
  hostingProvider: envString(import.meta.env.VITE_HOSTING_PROVIDER, "AWS Lightsail and Amazon RDS"),
} as const;

export const HELP_COMPLIANCE_COPY = {
  ukGdpr: `${HELP_SITE_CONFIG.appName} processes personal data in accordance with UK GDPR and the Data Protection Act 2018. Data protection queries should be directed to ${HELP_SITE_CONFIG.dpoEmail} or ${HELP_SITE_CONFIG.superAdminEmail}.`,
  security: "Access control is role-based (Super Admin, Licensee, Manufacturer). Communication is encrypted over HTTPS, passwords are handled using secure controls, and critical actions are captured in audit logs.",
  incidentResponse: "The controlled process is: report intake -> review -> containment -> documentation -> resolution.",
  qrUsage:
    "MSCQR codes are unique and traceable within the governed registry. Reuse, copying, or tampering is prohibited, but MSCQR should not be described as clone-proof or impossible to copy.",
  auditRetention: `Administrative actions, QR allocations, fraud reports, and login attempts are logged and retained for ${HELP_SITE_CONFIG.retentionDays} days.`,
  acceptableUse: "Unauthorized access, reverse engineering, misuse of fraud reporting, or interference with system security is prohibited.",
  hosting: `The platform is hosted via ${HELP_SITE_CONFIG.hostingProvider} with reasonable security controls and is provided on a best-effort basis.`,
} as const;
