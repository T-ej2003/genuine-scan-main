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
  hostingProvider: envString(import.meta.env.VITE_HOSTING_PROVIDER, "AWS-managed infrastructure"),
} as const;

export const HELP_COMPLIANCE_COPY = {
  ukGdpr: `${HELP_SITE_CONFIG.appName} processes account, invite, scan, QR allocation, audit, support, and operational diagnostic data in accordance with applicable privacy obligations, including UK GDPR and the Data Protection Act 2018 where relevant. Data protection queries should be directed to ${HELP_SITE_CONFIG.dpoEmail} or ${HELP_SITE_CONFIG.superAdminEmail}.`,
  security:
    "Access control is role-based for platform, brand/licensee, and manufacturer users. MSCQR is designed to use HTTPS, secure password handling, administrative controls, and audit logging for critical actions.",
  incidentResponse:
    "Support, fraud, and incident workflows are designed around report intake, review, containment, documentation, and resolution.",
  qrUsage:
    "MSCQR codes are unique and traceable within the governed registry. Reuse, copying, or tampering is prohibited, but MSCQR should not be described as clone-proof or impossible to copy.",
  auditRetention: `Administrative and security events may be logged for security, fraud prevention, troubleshooting, and auditability. Operational records may be retained for up to ${HELP_SITE_CONFIG.retentionDays} days unless a longer period is required for security, legal, operational, or dispute-resolution reasons.`,
  acceptableUse: "Unauthorized access, reverse engineering, misuse of fraud reporting, or interference with system security is prohibited.",
  hosting: `The platform is hosted on ${HELP_SITE_CONFIG.hostingProvider}, including application hosting, database, storage, monitoring, and security services. MSCQR applies reasonable security controls and is provided on a best-effort basis subject to applicable agreements.`,
} as const;
