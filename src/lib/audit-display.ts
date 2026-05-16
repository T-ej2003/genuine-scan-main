type AuditActor = {
  id?: string | null;
  name?: string | null;
  email?: string | null;
};

type AuditLike = {
  action?: string | null;
  entityType?: string | null;
  entityId?: string | null;
  userId?: string | null;
  user?: AuditActor | null;
  details?: unknown;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const maskEmail = (value?: string | null) => {
  const email = String(value || "").trim();
  const [name, domain] = email.split("@");
  if (!name || !domain) return email || "";
  const visible = name.length <= 2 ? name.slice(0, 1) : `${name.slice(0, 2)}${"*".repeat(Math.min(4, name.length - 2))}`;
  return `${visible}@${domain}`;
};

export const supportReferenceLabel = (value?: string | null, prefix = "Reference") => {
  const raw = String(value || "").trim();
  if (!raw) return "Not available";
  const compact = raw.replace(/[^a-z0-9]/gi, "").toUpperCase();
  if (!compact) return "Not available";
  return `${prefix} ${compact.slice(0, 4)}-${compact.slice(-4)}`;
};

export const humanRoleLabel = (value?: string | null) => {
  const role = String(value || "").trim().toUpperCase();
  if (role === "LICENSEE_ADMIN" || role === "ORG_ADMIN") return "Brand admin";
  if (role === "MANUFACTURER" || role === "MANUFACTURER_ADMIN" || role === "MANUFACTURER_USER") return "Manufacturer";
  if (role === "SUPER_ADMIN" || role === "PLATFORM_SUPER_ADMIN") return "Platform admin";
  return value || "Team member";
};

export const humanStatusLabel = (value?: string | null) => {
  const status = String(value || "").trim().toUpperCase();
  const labels: Record<string, string> = {
    DORMANT: "Ready for production",
    ACTIVE: "Ready for production",
    ALLOCATED: "Assigned",
    ACTIVATED: "Assigned",
    PRINTED: "Printed",
    REDEEMED: "Scanned",
    SCANNED: "Scanned",
    BLOCKED: "Blocked",
    PENDING: "Pending",
    APPROVED: "Approved",
    REJECTED: "Rejected",
    CONFIRMED: "Confirmed",
    FAILED: "Needs attention",
    LOCKED: "Print confirmed",
  };
  return labels[status] || titleCase(String(value || "Activity"));
};

export const titleCase = (value: string) =>
  String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());

const detailsObject = (value: unknown): Record<string, any> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, any>;
};

export const auditActorLabel = (log: AuditLike, options?: { maskEmail?: boolean }) => {
  const actor = log.user || null;
  if (actor?.name) return actor.name;
  if (actor?.email) return options?.maskEmail ? maskEmail(actor.email) : actor.email;
  if (log.userId && !UUID_RE.test(String(log.userId))) return supportReferenceLabel(log.userId, "User");
  return "MSCQR";
};

export const auditEntityLabel = (log: AuditLike) => {
  const entityType = titleCase(String(log.entityType || "Record"));
  const entityId = String(log.entityId || "").trim();
  if (!entityId) return entityType;
  return `${entityType} ${supportReferenceLabel(entityId, "")}`.trim();
};

export const auditActionLabel = (action?: string | null) => {
  const code = String(action || "").trim().toUpperCase();
  const labels: Record<string, string> = {
    AUTH_MFA_ENROLLED: "Extra sign-in protection enabled",
    AUTH_LOGIN_MFA_SETUP_REQUIRED: "Extra sign-in protection setup requested",
    AUTH_LOGIN_MFA_CHALLENGE_REQUIRED: "Extra sign-in protection requested",
    AUTH_INVITE_ACCEPTED: "Admin invite accepted",
    RESEND_LICENSEE_ADMIN_INVITE: "Admin invite resent",
    CREATE_LICENSEE: "Brand created",
    CREATE_LICENSEE_WITH_ADMIN: "Brand admin created",
    CREATE_LICENSEE_WITH_ADMIN_INVITE: "Brand admin invited",
    CREATE_BATCH: "Batch created",
    CREATE_PRODUCT_BATCH: "Batch created",
    ASSIGN_MANUFACTURER: "Manufacturer assigned",
    ASSIGN_PRODUCT_BATCH_MANUFACTURER: "Manufacturer assigned",
    ALLOCATE_QR_RANGE: "QR labels added",
    ALLOCATE_QR_RANGE_LICENSEE: "QR labels added",
    CONFIRM_PRINT: "Print confirmed",
    PRINT_CONFIRMED: "Print confirmed",
    DOWNLOAD_PRINT_PACK: "Print pack downloaded",
    DOWNLOAD_BATCH_PRINT_PACK: "Print pack downloaded",
    DIRECT_PRINT_TOKEN_ISSUED: "Print run prepared",
    PRINTED: "Labels printed",
    VERIFY_SUCCESS: "Customer scan verified",
    VERIFY_FAILED: "Customer scan needs review",
    CUSTOMER_FRAUD_REPORT: "Customer concern submitted",
    CUSTOMER_FRAUD_REPORT_RESPONSE: "Customer concern updated",
    CUSTOMER_PRODUCT_FEEDBACK: "Customer feedback received",
    INCIDENT_CREATED: "Investigation opened",
    INCIDENT_UPDATED: "Investigation updated",
    INCIDENT_NOTE_ADDED: "Investigation note added",
    INCIDENT_EVIDENCE_ADDED: "Evidence attached",
    INCIDENT_EMAIL_SENT: "Investigation email sent",
    PRINTER_CONNECTION_COMPAT_MODE_ONLINE: "Printer connected in recovery mode",
    PRINTER_CONNECTION_TRUSTED_ONLINE: "Printer connected",
    PRINTER_CONNECTION_UNTRUSTED_OR_OFFLINE: "Printer needs attention",
  };
  return labels[code] || titleCase(code || "Activity");
};

export const auditChangeSummary = (log: AuditLike) => {
  const details = detailsObject(log.details);
  const action = String(log.action || "").trim().toUpperCase();
  const actor = auditActorLabel(log, { maskEmail: true });
  const user = details.userName || details.name || details.email || actor;
  const brandName = details.brandName || details.licenseeName || details.licensee?.name;
  const maskedEmail = maskEmail(details.email || details.to || details.toAddress || details.adminEmail);

  switch (action) {
    case "AUTH_MFA_ENROLLED":
      return `Extra sign-in protection was enabled for ${user}.`;
    case "AUTH_LOGIN_MFA_SETUP_REQUIRED":
      return `Extra sign-in protection setup was requested for ${user}.`;
    case "AUTH_LOGIN_MFA_CHALLENGE_REQUIRED":
      return `Extra sign-in protection was requested for ${user}.`;
    case "AUTH_INVITE_ACCEPTED":
      return `${user} accepted an admin invite.`;
    case "RESEND_LICENSEE_ADMIN_INVITE":
      return `${actor} resent an invite${maskedEmail ? ` to ${maskedEmail}` : ""}${brandName ? ` for ${brandName}` : ""}.`;
    case "CREATE_LICENSEE":
    case "CREATE_LICENSEE_WITH_ADMIN":
    case "CREATE_LICENSEE_WITH_ADMIN_INVITE":
      return `Brand workspace ${details.name || brandName || ""} was prepared.`.replace(/\s+was/, " was");
    case "CREATE_BATCH":
    case "CREATE_PRODUCT_BATCH":
      return `Batch ${details.name || details.batchName || ""} was created${details.quantity ? ` with ${Number(details.quantity).toLocaleString()} labels` : ""}.`.replace(/\s+was/, " was");
    case "ASSIGN_MANUFACTURER":
    case "ASSIGN_PRODUCT_BATCH_MANUFACTURER":
      return `${details.manufacturerName || "A manufacturer"} was assigned${details.quantity ? ` ${Number(details.quantity).toLocaleString()} labels` : ""}.`;
    case "ALLOCATE_QR_RANGE":
    case "ALLOCATE_QR_RANGE_LICENSEE":
      return `${Number(details.created || details.quantity || 0).toLocaleString()} QR labels were added.`;
    case "DIRECT_PRINT_TOKEN_ISSUED":
      return `A secure print run was prepared${details.issuedCount || details.count ? ` for ${Number(details.issuedCount || details.count).toLocaleString()} labels` : ""}.`;
    case "PRINTED":
    case "CONFIRM_PRINT":
    case "PRINT_CONFIRMED":
      return `Print progress was confirmed${details.printedCodes ? ` for ${Number(details.printedCodes).toLocaleString()} labels` : ""}.`;
    case "VERIFY_SUCCESS":
      return details.isFirstScan ? "A customer completed the first scan for a label." : "A customer scan was verified.";
    case "VERIFY_FAILED":
      return "A customer scan needs review.";
    case "CUSTOMER_FRAUD_REPORT":
      return `A customer concern was submitted${details.code ? ` for label ${details.code}` : ""}.`;
    case "CUSTOMER_FRAUD_REPORT_RESPONSE":
      return `A customer concern was marked ${humanStatusLabel(details.status || "reviewed").toLowerCase()}.`;
    case "INCIDENT_CREATED":
      return "An investigation was opened.";
    case "INCIDENT_UPDATED":
      return "An investigation was updated.";
    case "INCIDENT_NOTE_ADDED":
      return "An investigation note was added.";
    case "INCIDENT_EVIDENCE_ADDED":
      return "Evidence was attached to an investigation.";
    case "INCIDENT_EMAIL_SENT":
      return "An investigation email update was sent.";
    default:
      if (details.quantity) return `${Number(details.quantity).toLocaleString()} labels updated.`;
      if (details.name || details.batchName) return `${details.name || details.batchName} was updated.`;
      return "Workspace activity was recorded.";
  }
};
