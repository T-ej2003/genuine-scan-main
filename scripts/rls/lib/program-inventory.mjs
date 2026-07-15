import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import assert from "node:assert/strict";

export const repoRoot = path.resolve(new URL("../../..", import.meta.url).pathname);
export const programDir = path.join(repoRoot, "documents/security/rls-program");
export const schemaPath = path.join(repoRoot, "backend/prisma/schema.prisma");
export const tableManifestPath = path.join(programDir, "tables.json");
export const workflowManifestPath = path.join(programDir, "workflows.json");
export const identityManifestPath = path.join(programDir, "runtime-identities.json");
export const decisionManifestPath = path.join(programDir, "decisions.json");
export const policyDependencyGraphPath = path.join(programDir, "policy-dependency-graph.json");
export const tableOwnershipReviewPath = path.join(programDir, "TABLE_OWNERSHIP_REVIEW.md");
export const commandSemanticsPath = path.join(programDir, "command-semantics.json");
export const commandSemanticsReviewPath = path.join(programDir, "COMMAND_SEMANTICS_REVIEW.md");
export const blockedApplyPath = "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql";

export const commands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT", "COUNT", "RAW_SQL"]);
export const surfaces = new Set(["http", "worker", "scheduled", "startup", "cli", "internal"]);
export const boundaries = new Set(["authenticated-context", "pre-auth-security-function", "tenant-admin", "platform-admin", "actor-owned", "restricted-worker", "append-only", "migration-owner", "operator-break-glass", "unresolved"]);
export const categories = new Set(["tenant-root", "tenant-owned", "actor-owned", "parent-inherited", "security-sensitive", "append-only-audit", "platform-reference", "operational-system", "migration-only", "intentionally-non-rls"]);
export const actorClasses = new Set(["anonymous", "authenticated-user", "manufacturer", "operator", "checker", "licensee-admin", "platform-admin", "restricted-read", "pre-auth-runtime", "worker", "scheduled-job", "migration", "operator-admin", "break-glass"]);
export const assuranceLevels = new Set(["none", "password-verified", "mfa-bootstrap", "mfa-verified", "step-up-verified", "system-verified", "operator-approved", "dual-approved-break-glass"]);
export const policyCommands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE"]);

const CATEGORY_MODELS = Object.freeze({
  "tenant-root": ["Organization"],
  "tenant-owned": ["Licensee", "ManufacturerLicenseeLink", "QRRange", "Batch", "InventoryStatusRollup", "QRCode", "QrAllocationRequest", "PolicyAlert", "TenantFeatureFlag", "EvidenceRetentionPolicy"],
  "actor-owned": ["PrinterRegistration", "Notification"],
  "parent-inherited": ["PrintJob", "PrintSession", "PrinterAgentSession", "PrintJobChunk", "PrintItem", "PrinterProfile", "PrinterProfileSnapshot", "PrintReissueRequest", "PrinterAttestation", "Ownership", "OwnershipTransfer", "ReplacementChain", "IncidentHandoff", "SupportTicket", "SupportTicketMessage"],
  "security-sensitive": ["User", "Printer", "VerificationDecision", "VerificationEvidenceSnapshot", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerTrustIntake", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "AdminMfaCredential", "AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal", "SensitiveActionApproval", "SecurityPolicy", "PolicyRule", "Incident", "RequestAccess", "SupportIssueReport"],
  "append-only-audit": ["PrintItemEvent", "PrintAuditEvent", "QrScanLog", "AuditLog", "AllocationEvent", "TraceEvent", "IncidentEvent", "IncidentCommunication", "IncidentEvidence", "ForensicEventChain", "RouteTransitionMetric"],
  "platform-reference": [],
  "operational-system": ["ScanMetricsHourlyRollup", "AuditLogOutbox", "SystemCheckpoint", "SecurityEventOutbox", "CompliancePackJob", "EvidenceRetentionJob", "IncidentEvidenceFingerprint", "ActionIdempotencyKey", "DegradationEvent"],
  "migration-only": ["PrintRenderToken", "BatchPrintPackToken"],
  "intentionally-non-rls": [],
});
const CATEGORY_BY_MODEL = new Map(Object.entries(CATEGORY_MODELS).flatMap(([category, models]) => models.map((model) => [model, category])));

const REVIEW_GROUP_MODELS = Object.freeze({
  A: ["User", "PrintRenderToken", "BatchPrintPackToken", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerTrustIntake", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "AdminMfaCredential", "AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal", "SensitiveActionApproval"],
  B: ["Organization", "Licensee", "ManufacturerLicenseeLink"],
  C: ["QRRange", "Batch", "InventoryStatusRollup", "QRCode", "Ownership", "OwnershipTransfer", "QrScanLog", "VerificationDecision", "VerificationEvidenceSnapshot", "ReplacementChain", "DegradationEvent", "QrAllocationRequest", "AllocationEvent", "TraceEvent", "ScanMetricsHourlyRollup"],
  D: ["PrintJob", "PrintSession", "PrinterAgentSession", "PrintJobChunk", "PrintItem", "PrintItemEvent", "PrintAuditEvent", "PrinterRegistration", "Printer", "PrinterProfile", "PrinterProfileSnapshot", "PrintReissueRequest", "PrinterAttestation"],
  E: ["AuditLog", "SecurityPolicy", "PolicyRule", "PolicyAlert", "Incident", "IncidentEvent", "IncidentCommunication", "IncidentEvidence", "IncidentHandoff", "SupportTicket", "SupportTicketMessage", "RequestAccess", "SupportIssueReport", "Notification", "TenantFeatureFlag", "EvidenceRetentionPolicy", "IncidentEvidenceFingerprint", "ForensicEventChain"],
  F: ["AuditLogOutbox", "SystemCheckpoint", "SecurityEventOutbox", "CompliancePackJob", "EvidenceRetentionJob", "ActionIdempotencyKey", "RouteTransitionMetric"],
  G: [],
});
const REVIEW_GROUP_BY_MODEL = new Map(Object.entries(REVIEW_GROUP_MODELS).flatMap(([group, models]) => models.map((model) => [model, group])));

const DEPENDENCY_RULES = Object.freeze({
  PrintJob: ["Batch", ["batchId"], ["id"]],
  PrintSession: ["PrintJob", ["printJobId"], ["id"]],
  PrinterAgentSession: ["PrinterRegistration", ["registrationId"], ["id"]],
  PrintJobChunk: ["PrintJob", ["printJobId"], ["id"]],
  PrintItem: ["PrintSession", ["printSessionId"], ["id"]],
  PrintItemEvent: ["PrintItem", ["printItemId"], ["id"]],
  PrintAuditEvent: ["Batch", ["batchId"], ["id"]],
  PrinterProfile: ["Printer", ["printerId"], ["id"]],
  PrinterProfileSnapshot: ["PrinterProfile", ["printerProfileId"], ["id"]],
  PrintReissueRequest: ["PrintJob", ["originalPrintJobId"], ["id"]],
  PrinterAttestation: ["PrinterRegistration", ["printerRegistrationId"], ["id"]],
  Ownership: ["QRCode", ["qrCodeId"], ["id"]],
  OwnershipTransfer: ["Ownership", ["ownershipId"], ["id"]],
  VerificationEvidenceSnapshot: ["VerificationDecision", ["verificationDecisionId"], ["id"]],
  ReplacementChain: ["QRCode", ["originalQrCodeId"], ["id"]],
  DegradationEvent: ["QRCode", ["code"], ["code"]],
  CustomerTrustCredential: ["QRCode", ["qrCodeId"], ["id"]],
  CustomerVerificationSession: ["VerificationDecision", ["verificationDecisionId"], ["id"]],
  CustomerTrustIntake: ["CustomerVerificationSession", ["sessionId"], ["id"]],
  Invite: ["Organization", ["orgId"], ["id"]],
  PasswordReset: ["User", ["userId"], ["id"]],
  EmailVerificationToken: ["User", ["userId"], ["id"]],
  RefreshToken: ["User", ["userId"], ["id"]],
  AdminMfaCredential: ["User", ["userId"], ["id"]],
  AdminWebAuthnCredential: ["User", ["userId"], ["id"]],
  UserMfaFactor: ["User", ["userId"], ["id"]],
  UserBackupCode: ["User", ["userId"], ["id"]],
  MfaLoginChallenge: ["User", ["userId"], ["id"]],
  AuthMfaChallenge: ["User", ["userId"], ["id"]],
  AuthWebAuthnChallenge: ["User", ["userId"], ["id"]],
  AuthSessionRiskSignal: ["User", ["userId"], ["id"]],
  IncidentEvent: ["Incident", ["incidentId"], ["id"]],
  IncidentCommunication: ["Incident", ["incidentId"], ["id"]],
  IncidentEvidence: ["Incident", ["incidentId"], ["id"]],
  IncidentHandoff: ["Incident", ["incidentId"], ["id"]],
  SupportTicket: ["Incident", ["incidentId"], ["id"]],
  SupportTicketMessage: ["SupportTicket", ["ticketId"], ["id"]],
  IncidentEvidenceFingerprint: ["IncidentEvidence", ["incidentEvidenceId"], ["id"]],
});

const NULL_SEMANTICS = Object.freeze({
  User: "orgId/licenseeId NULL denotes a platform user; NULL never grants tenant-wide access and only actor-self or explicit platform-admin commands may reach the row.",
  PrinterRegistration: "orgId/licenseeId may be NULL during actor-owned connector setup; userId remains authoritative and NULL never makes a registration globally readable.",
  Printer: "orgId/licenseeId may be NULL for discovery or unassigned gateway records; access then requires the printer-trust repository using registration/assigned-actor proof, never a NULL-is-global policy.",
  AuditLog: "NULL tenant keys denote platform/system audit evidence and require the restricted audit/platform boundary; tenant projections require a matching non-NULL key.",
  VerificationDecision: "licenseeId may be NULL for not-found or public verification outcomes; access remains inside the public-verification/review boundary and NULL is not a wildcard.",
  CustomerTrustCredential: "customerUserId may be NULL for device-bound anonymous trust; the QR parent plus hashed device proof is authoritative and no broad anonymous table access is allowed.",
  CustomerVerificationSession: "customerUserId/qrCodeId may be NULL during staged public verification; the non-NULL verificationDecisionId and proof-binding boundary remain authoritative.",
  CustomerTrustIntake: "customerUserId may be NULL for anonymous intake; the non-NULL sessionId parent is authoritative.",
  Invite: "licenseeId may be NULL for an organization-wide invite; non-NULL orgId remains authoritative and NULL never grants cross-organization access.",
  PasswordReset: "orgId may be NULL for platform users; non-NULL userId is authoritative and access is only through the named recovery boundary.",
  RefreshToken: "orgId may be NULL for platform users; non-NULL userId is authoritative and actor/session commands remain required.",
  SensitiveActionApproval: "orgId/licenseeId may be NULL only for platform-scoped commands; requestedByUserId and the exact approval command remain authoritative.",
  SecurityPolicy: "licenseeId NULL is the single platform-default policy row; only the restricted policy engine and platform-admin command may use it.",
  PolicyRule: "Nullable orgId/licenseeId/manufacturerId encode an explicitly reviewed rule scope; an all-NULL row is platform-scoped and never ordinary tenant access.",
  Incident: "licenseeId may be NULL for public intake before product-to-tenant resolution; the incident repository restricts that row until a tenant is resolved.",
  SupportTicket: "licenseeId may be NULL when inherited from a public incident; incidentId remains authoritative.",
  SupportIssueReport: "licenseeId/reporterUserId may be NULL for public support intake; access is restricted to the intake token/reporter or platform support boundary.",
  Notification: "userId/orgId/licenseeId are selected by the audience discriminator; all NULL is an explicit system broadcast, not an unrestricted tenant row.",
  CompliancePackJob: "licenseeId NULL is allowed only for an explicitly approved platform-wide compliance job under the scheduled/operator boundary.",
  EvidenceRetentionJob: "licenseeId NULL is allowed only for an explicitly approved platform-wide retention job under the scheduled/operator boundary.",
  ForensicEventChain: "licenseeId NULL denotes platform audit evidence and requires the restricted forensic/system boundary.",
  RouteTransitionMetric: "userId/licenseeId NULL denotes anonymous platform telemetry; only append and aggregated system reads are permitted.",
});

const PREAUTH_NAMED_FUNCTION_MODELS = new Set(["User", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal"]);
const PUBLIC_BOUNDARY_MODELS = new Set(["VerificationDecision", "VerificationEvidenceSnapshot", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerTrustIntake", "Incident", "IncidentEvent", "IncidentCommunication", "IncidentEvidence", "SupportTicket", "SupportTicketMessage", "RequestAccess", "SupportIssueReport", "Ownership", "OwnershipTransfer"]);
const READ_ROLE_MODELS = new Set(["Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot"]);
const RETENTION_DELETE_MODELS = new Set(["QrScanLog", "IncidentEvidence"]);

export const readJson = (file, fallback = null) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback;
export const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
};
export const rel = (file) => path.relative(repoRoot, file).split(path.sep).join("/");
export const slug = (value) => value.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase();
export const hashId = (prefix, value) => `${prefix}-${crypto.createHash("sha256").update(value).digest("hex").slice(0, 16)}`;

const stripComments = (value) => value.replace(/\/\/.*$/gm, "");
export const parseSchema = (source = fs.readFileSync(schemaPath, "utf8")) => {
  const models = [];
  const modelPattern = /^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm;
  for (const match of stripComments(source).matchAll(modelPattern)) {
    const [, name, body] = match;
    const fields = [];
    let physicalTable = name;
    for (const raw of body.split("\n")) {
      const line = raw.trim();
      const map = line.match(/^@@map\("([^"]+)"\)/);
      if (map) { physicalTable = map[1]; continue; }
      const field = line.match(/^(\w+)\s+([^\s]+)(?:\s+.*)?$/);
      if (!field || line.startsWith("@@")) continue;
      const [, fieldName, rawType] = field;
      const type = rawType.replace(/[?\[\]]/g, "");
      fields.push({ name: fieldName, type, optional: rawType.includes("?"), list: rawType.includes("[]"), relation: /@relation\b/.test(line), attributes: line.slice(field[0].indexOf(rawType) + rawType.length).trim() });
    }
    models.push({ name, physicalTable, fields });
  }
  return models;
};

const sensitivityFor = (model, category) => category === "security-sensitive" ? "restricted"
  : category === "append-only-audit" ? "high"
    : model.fields.some((field) => /email|phone|ip|address|secret|token|hash|credential/i.test(field.name)) ? "high" : "internal";

const ACTOR_KEYS = Object.freeze({
  User: ["id"], ManufacturerLicenseeLink: ["manufacturerId"], Batch: ["manufacturerId"], InventoryStatusRollup: ["manufacturerId"], PrinterRegistration: ["userId"], Printer: ["assignedUserId"], Notification: ["userId"], Ownership: ["userId"], PolicyRule: ["manufacturerId"], PolicyAlert: ["manufacturerId"],
  CustomerTrustCredential: ["customerUserId"], CustomerWebAuthnCredential: ["customerUserId"], CustomerWebAuthnChallenge: ["customerUserId"], CustomerVerificationSession: ["customerUserId"], CustomerTrustIntake: ["customerUserId"],
  PasswordReset: ["userId"], EmailVerificationToken: ["userId"], RefreshToken: ["userId"], AdminMfaCredential: ["userId"], AdminWebAuthnCredential: ["userId"], UserMfaFactor: ["userId"], UserBackupCode: ["userId"], MfaLoginChallenge: ["userId"], AuthMfaChallenge: ["userId"], AuthWebAuthnChallenge: ["userId"], AuthSessionRiskSignal: ["userId"], SensitiveActionApproval: ["requestedByUserId"], SupportIssueReport: ["reporterUserId"],
});

const TENANT_KEYS = Object.freeze({
  User: ["orgId", "licenseeId"], Licensee: ["orgId"], ManufacturerLicenseeLink: ["licenseeId"], QRRange: ["licenseeId"], Batch: ["licenseeId"], InventoryStatusRollup: ["licenseeId"], QRCode: ["licenseeId"],
  PrinterRegistration: ["orgId", "licenseeId"], Printer: ["orgId", "licenseeId"], QrScanLog: ["licenseeId"], AuditLog: ["orgId", "licenseeId"], Invite: ["orgId", "licenseeId"], SensitiveActionApproval: ["orgId", "licenseeId"],
  QrAllocationRequest: ["licenseeId"], AllocationEvent: ["licenseeId"], TraceEvent: ["licenseeId"], ScanMetricsHourlyRollup: ["licenseeId"], SecurityPolicy: ["licenseeId"], PolicyRule: ["orgId", "licenseeId"], PolicyAlert: ["licenseeId"], Incident: ["licenseeId"], SupportIssueReport: ["licenseeId"], Notification: ["orgId", "licenseeId"], TenantFeatureFlag: ["licenseeId"], EvidenceRetentionPolicy: ["licenseeId"], EvidenceRetentionJob: ["licenseeId"], CompliancePackJob: ["licenseeId"], ForensicEventChain: ["licenseeId"], RouteTransitionMetric: ["licenseeId"],
});

const rowOwnershipModelFor = (model, category, tenantKeys, actorKeys, dependency) => {
  if (category === "tenant-root") return "Organization.id is the canonical tenant identifier; ordinary actors may read only app.organization_id, while create/update/delete require explicit platform-admin commands.";
  if (category === "tenant-owned") return `Direct transaction-context scope using ${tenantKeys.join(" + ")}; platform-admin access remains command-specific.`;
  if (category === "actor-owned") return `Direct actor scope using ${actorKeys.join(" + ")}; tenant/platform administration requires an explicit reviewed command boundary.`;
  if (category === "parent-inherited") return `Single-parent authorization inherited from ${dependency[0]} through ${dependency[1].join("+")}=${dependency[2].join("+")}.`;
  if (category === "append-only-audit") return dependency
    ? `Append-only evidence inherits read scope from ${dependency[0]} through ${dependency[1].join("+")}=${dependency[2].join("+")}; writes use the append boundary.`
    : tenantKeys.length ? `Append-only evidence is scoped directly by ${tenantKeys.join(" + ")}; NULL/platform events require the restricted audit boundary.` : "Append-only evidence is written and read only through its approved audit/system boundary.";
  if (category === "operational-system") return tenantKeys.length ? `Restricted worker/scheduled coordination scoped by ${tenantKeys.join(" + ")}; no platform-global bypass.` : dependency ? `Restricted system coordination inherited from ${dependency[0]}.` : "Restricted system coordination boundary with no human broad-table access.";
  if (category === "security-sensitive") {
    if (dependency) return `Special repository/function boundary with row scope inherited from ${dependency[0]} through ${dependency[1].join("+")}=${dependency[2].join("+")}.`;
    if (actorKeys.length) return `Special actor-owned repository/function boundary using ${actorKeys.join(" + ")}; administrator access is command-specific and audited.`;
    if (tenantKeys.length) return `Special security repository using explicit ${tenantKeys.join(" + ")} scope and command-specific platform administration.`;
    return "Special named function, restricted repository, or operator boundary; ordinary authenticated broad-table access is forbidden.";
  }
  if (category === "platform-reference") return "Read-only global low-sensitivity reference data; writes are migration/operator controlled.";
  if (category === "migration-only") return "No production runtime row access; migration identity only.";
  return "No tenant or actor data is possible; GRANT-only exception documented separately.";
};

const terminalBoundaryFor = (modelName, category, dependency, tenantKeys, actorKeys) => {
  if (dependency) return null;
  if (category === "tenant-root") return "tenant-root";
  if (tenantKeys.length) return "tenant-key";
  if (actorKeys.length) return "actor-key";
  if (category === "operational-system") return "approved-system";
  if (category === "platform-reference") return "approved-platform-reference";
  if (category === "migration-only") return "migration-only";
  if (category === "intentionally-non-rls") return "grant-only-exception";
  return "approved-special-boundary";
};

const preAuthModeFor = (modelName) => PREAUTH_NAMED_FUNCTION_MODELS.has(modelName) ? "exact-named-security-definer-function-only"
  : PUBLIC_BOUNDARY_MODELS.has(modelName) ? "restricted-public-service-boundary; no direct preauth table grants"
    : "denied; actor or system context required";

const sensitiveColumnsFor = (model) => model.fields.filter((field) => !field.relation && /(?:password|secret|token|hash|credential|challenge|email|phone|ipAddress|ipHash|userAgent|publicKey|privateKey|payload|metadata|details|evidence|screenshot|diagnostic|photos|location|internalNote|bodyPreview)/i.test(field.name)).map((field) => field.name).sort();

export const buildTableManifest = () => {
  const existing = readJson(tableManifestPath, { schemaVersion: 1, tables: [] });
  const previous = new Map(existing.tables.map((table) => [table.id, table]));
  const models = parseSchema();
  assert.equal(CATEGORY_BY_MODEL.size, models.length, "classification catalogue must contain every Prisma model exactly once");
  assert.equal(REVIEW_GROUP_BY_MODEL.size, models.length, "review groups must contain every Prisma model exactly once");
  const modelNames = new Set(models.map((model) => model.name));
  const tables = models.map((model) => {
    const id = `table-${slug(model.physicalTable)}`;
    const old = previous.get(id) || {};
    const fieldNames = new Set(model.fields.map((field) => field.name));
    const relations = model.fields.filter((field) => field.relation && modelNames.has(field.type)).map((field) => ({ field: field.name, model: field.type }));
    const likelyParents = relations.filter((relation) => !model.fields.find((field) => field.name === relation.field)?.list).map((relation) => `table-${slug(models.find((item) => item.name === relation.model)?.physicalTable || relation.model)}`);
    const category = CATEGORY_BY_MODEL.get(model.name);
    assert(category, `${model.name} lacks a primary category`);
    const dependency = DEPENDENCY_RULES[model.name] || null;
    const parentModel = dependency ? models.find((item) => item.name === dependency[0]) : null;
    assert(!dependency || parentModel, `${model.name} has an unknown authorization parent`);
    const parentTableId = parentModel ? `table-${slug(parentModel.physicalTable)}` : null;
    const tenantColumns = (TENANT_KEYS[model.name] || []).filter((name) => fieldNames.has(name) && category !== "parent-inherited");
    const actorColumns = (ACTOR_KEYS[model.name] || []).filter((name) => fieldNames.has(name) || (model.name === "User" && name === "id"));
    const nullableTenantColumns = tenantColumns.filter((name) => model.fields.find((field) => field.name === name)?.optional);
    assert(!nullableTenantColumns.length || NULL_SEMANTICS[model.name], `${model.name} nullable tenant keys require explicit NULL semantics`);
    const sensitiveColumns = sensitiveColumnsFor(model);
    const forceRlsTarget = !["migration-only", "intentionally-non-rls"].includes(category);
    const terminalBoundary = terminalBoundaryFor(model.name, category, dependency, tenantColumns, actorColumns);
    return {
      ...old,
      id,
      prismaModel: model.name,
      physicalTable: model.physicalTable,
      category,
      primaryCategory: category,
      reviewGroup: REVIEW_GROUP_BY_MODEL.get(model.name),
      physicalOwnerRole: "identity-table-owner",
      rowOwnershipModel: rowOwnershipModelFor(model, category, tenantColumns, actorColumns, dependency),
      tenantKeyColumns: tenantColumns,
      actorKeyColumns: actorColumns,
      tenantKeyNullSemantics: nullableTenantColumns.length ? NULL_SEMANTICS[model.name] : null,
      authorizationParentTable: parentTableId,
      authorizationParentColumns: dependency ? { child: dependency[1], parent: dependency[2] } : null,
      policyDependencyTables: parentTableId ? [parentTableId] : [],
      forceRlsTarget,
      allowedRuntimeReaders: old.allowedRuntimeReaders || [],
      allowedRuntimeWriters: old.allowedRuntimeWriters || [],
      allowedCommandsByIdentity: old.allowedCommandsByIdentity || [],
      preAuthAccessMode: preAuthModeFor(model.name),
      workerAccessMode: category === "operational-system" ? "restricted worker/scheduled identity with durable job and tenant scope; no queue-payload-only trust" : "transaction-local tenant/actor scope or exact approved function; no global bypass",
      appendOnly: category === "append-only-audit",
      hardDeleteAllowed: RETENTION_DELETE_MODELS.has(model.name) ? "retention-only" : "never",
      sensitiveColumns,
      policyRecursionRisk: "none",
      policyRecursionReason: dependency ? `Single directed dependency to ${dependency[0]}; the generated DAG validator proves no path returns to ${model.name}.` : "Terminal context/function/system boundary; policy performs no table-reading dependency.",
      nonRlsJustification: category === "intentionally-non-rls" ? old.nonRlsJustification || "" : null,
      ownershipConfidence: nullableTenantColumns.length || ["security-sensitive", "operational-system"].includes(category) && !dependency && !tenantColumns.length && !actorColumns.length ? "medium" : "high",
      terminalBoundary,
      unresolvedDecisionIds: [],
      classificationEvidence: [
        `backend/prisma/schema.prisma model ${model.name}: ${tenantColumns.length ? `tenant keys ${tenantColumns.join(", ")}` : "no direct tenant key"}; ${actorColumns.length ? `actor keys ${actorColumns.join(", ")}` : "no direct actor key"}.`,
        dependency ? `Schema/access lineage uses one parent ${dependency[0]} on ${dependency[1].join("+")}=${dependency[2].join("+")}.` : `No table-reading parent dependency; terminal boundary is ${terminalBoundary}.`,
        `Production commands and canonical workflows are regenerated by scripts/rls/scan-production-access.mjs.`,
      ],
      classificationStatus: "resolved",
      sensitivity: sensitivityFor(model, category),
      tenantOwnershipColumns: tenantColumns,
      parentAuthorizationTable: parentTableId,
      actorOwnershipColumn: actorColumns[0] || null,
      productionRuntimeReaders: old.productionRuntimeReaders || [],
      productionRuntimeWriters: old.productionRuntimeWriters || [],
      requiredCommands: old.requiredCommands || [],
      intendedDatabaseRoles: old.intendedDatabaseRoles || [],
      rlsApplicability: forceRlsTarget ? "force-rls-target" : "not-applicable",
      currentRlsState: old.currentRlsState || "not-verified-for-production",
      currentForceRlsState: old.currentForceRlsState || "not-verified-for-production",
      policyStatus: old.policyStatus || "not-designed",
      recursionDependencies: parentTableId ? [parentTableId] : [],
      unresolvedDecisions: [...new Set((old.unresolvedDecisions || ["decision-policy-command-semantics"]).filter((decisionId) => decisionId !== "decision-table-ownership-classification"))],
      implementationStatus: old.implementationStatus || "inventory-only",
      verificationStatus: old.verificationStatus || "schema-represented-only",
      nonRlsSecurityJustification: category === "intentionally-non-rls" ? old.nonRlsSecurityJustification || "" : null,
      schemaEvidence: { fields: model.fields, likelyParentChains: likelyParents },
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const result = { schemaVersion: 2, generatedFrom: "backend/prisma/schema.prisma", generatedModelCount: models.length, classificationAuthority: "scripts/rls/lib/program-inventory.mjs", tables };
  writeJson(tableManifestPath, result);
  return result;
};

const require = createRequire(import.meta.url);
const methodNames = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "create", "createMany", "createManyAndReturn", "update", "updateMany", "updateManyAndReturn", "delete", "deleteMany", "upsert", "count", "aggregate", "groupBy"]);
const rawMethods = new Set(["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"]);
const excludedDirs = new Set(["dist", "node_modules", "tests", "__tests__", "coverage", ".terraform", "generated"]);
const sourceExtensions = /\.(?:[cm]?js|ts)$/;

const walk = (directory, result = []) => {
  if (!fs.existsSync(directory)) return result;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirs.has(entry.name)) continue;
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(file, result);
    else if (sourceExtensions.test(entry.name)) result.push(file);
  }
  return result;
};
const resolveImport = (from, specifier) => {
  if (!specifier.startsWith(".")) return null;
  const base = path.resolve(path.dirname(from), specifier);
  for (const candidate of [base, ...[".ts", ".js", ".mjs", ".cjs"].map((extension) => base + extension), ...["index.ts", "index.js", "index.mjs"].map((name) => path.join(base, name))]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
};
const scriptEntrypoints = () => {
  const entries = new Set([path.join(repoRoot, "backend/prisma/seed.ts")]);
  for (const [prefix, packageFile] of [[repoRoot, "package.json"], [path.join(repoRoot, "backend"), "backend/package.json"]]) {
    const pkg = readJson(path.join(repoRoot, packageFile), {});
    for (const command of Object.values(pkg.scripts || {})) {
      for (const match of command.matchAll(/(?:^|[\s;])(?:node|tsx)\s+([^\s"']+\.(?:[cm]?js|ts))/g)) {
        const file = path.resolve(prefix, match[1]);
        if (fs.existsSync(file) && !/(?:^|[\\/])tests?(?:[\\/]|$)/.test(file)) entries.add(file);
      }
    }
  }
  return entries;
};
const reachableSourceFiles = () => {
  const all = [...walk(path.join(repoRoot, "backend/src")), ...walk(path.join(repoRoot, "backend/scripts")), path.join(repoRoot, "backend/prisma/seed.ts")];
  const allowed = new Set(all);
  const roots = [path.join(repoRoot, "backend/src/index.ts"), path.join(repoRoot, "backend/src/worker.ts"), ...scriptEntrypoints()];
  const reachable = new Set();
  const visit = (file) => {
    if (!file || reachable.has(file) || !fs.existsSync(file)) return;
    reachable.add(file);
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(/(?:import\s+(?:[^"'()]*?\s+from\s+)?|export\s+(?:\*|\{[^}]*\})\s+from\s+|import\s*\(|require\s*\()\s*["']([^"']+)["']/g)) {
      const resolved = resolveImport(file, match[1]);
      if (resolved && (allowed.has(resolved) || scriptEntrypoints().has(resolved))) visit(resolved);
    }
  };
  roots.forEach(visit);
  return { reachable, all, roots: new Set(roots) };
};
const detectRegistrations = () => {
  const routes = [];
  for (const file of [...walk(path.join(repoRoot, "backend/src/routes")), path.join(repoRoot, "backend/src/app.ts")]) {
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(/\b(?:router|app)\.(get|post|put|patch|delete|use)\s*\(\s*(["'`])([^"'`]+)\2/g)) {
      routes.push({ method: match[1].toUpperCase(), path: match[3], source: `${rel(file)}:${source.slice(0, match.index).split("\n").length}` });
    }
  }
  const packageScripts = [];
  for (const packageFile of ["package.json", "backend/package.json"]) {
    const pkg = readJson(path.join(repoRoot, packageFile), {});
    for (const [name, command] of Object.entries(pkg.scripts || {})) packageScripts.push({ packageFile, name, command });
  }
  return { routes: routes.sort((a, b) => a.source.localeCompare(b.source) || a.method.localeCompare(b.method)), packageScripts: packageScripts.sort((a, b) => `${a.packageFile}:${a.name}`.localeCompare(`${b.packageFile}:${b.name}`)), startupEntrypoints: ["backend/src/index.ts", "backend/src/worker.ts"] };
};
const functionName = (ts, node) => {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionDeclaration(current) && current.name) return current.name.text;
    if ((ts.isArrowFunction(current) || ts.isFunctionExpression(current)) && ts.isVariableDeclaration(current.parent)) return current.parent.name.getText();
    if (ts.isMethodDeclaration(current) && current.name) return current.name.getText();
  }
  return "module";
};
const operationFor = (method) => method === "upsert" ? "UPSERT" : method === "count" ? "COUNT" : method.startsWith("create") ? "INSERT" : method.startsWith("update") ? "UPDATE" : method.startsWith("delete") ? "DELETE" : "SELECT";
const rawCommandsFor = (method, sql) => {
  if (/queryraw/i.test(method)) return ["SELECT"];
  const matches = [...sql.matchAll(/\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/gi)].map((match) => match[1].split(/\s/)[0].toUpperCase());
  return [...new Set(matches.length ? matches : ["UPDATE"])];
};
const surfaceFor = (file, fn) => {
  const value = `${rel(file)}:${fn}`;
  if (file === path.join(repoRoot, "backend/src/worker.ts") || /(?:worker|processor|consumer|queue)/i.test(value)) return "worker";
  if (/(?:scheduler|scheduled|cron|startCompliancePackScheduler)/i.test(value)) return "scheduled";
  if (file === path.join(repoRoot, "backend/src/index.ts") || /(?:bootstrap|startup|superAdminBootstrap)/i.test(value)) return "startup";
  if (rel(file).startsWith("backend/scripts/") || rel(file) === "backend/prisma/seed.ts" || rel(file).startsWith("scripts/")) return "cli";
  if (/backend\/src\/(?:controllers|routes|middleware)\//.test(rel(file))) return "http";
  return "internal";
};
const boundaryFor = (file, fn, surface) => {
  const value = `${rel(file)}:${fn}`;
  if (/(?:login|passwordReset|emailVerification|acceptInvite|getInvitePreview|authBootstrap)/i.test(value)) return "pre-auth-security-function";
  if (surface === "worker" || surface === "scheduled") return "restricted-worker";
  if (surface === "startup") return "migration-owner";
  if (surface === "cli" && /(?:break-glass|repair|reset|create-super-admin)/i.test(value)) return "operator-break-glass";
  if (/(?:platform|superAdmin|licenseeController)/i.test(value)) return "platform-admin";
  if (/(?:account|self|My)/i.test(value)) return "actor-owned";
  if (surface === "http") return "authenticated-context";
  return "unresolved";
};

export const scanProductionAccess = () => {
  const ts = require(path.join(repoRoot, "backend/node_modules/typescript"));
  const models = parseSchema();
  const delegates = new Map(models.map((model) => [model.name[0].toLowerCase() + model.name.slice(1), model]));
  const physical = new Map(models.map((model) => [model.physicalTable.toLowerCase(), model]));
  const { reachable, all, roots } = reachableSourceFiles();
  const active = [...new Set([...reachable, ...scriptEntrypoints()])].sort();
  const accesses = [];
  const scanFile = (file, production) => {
    const source = fs.readFileSync(file, "utf8");
    const ast = ts.createSourceFile(rel(file), source, ts.ScriptTarget.Latest, true);
    const recorded = new Set();
    const record = (node, model, method, command, evidence) => {
      const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
      const fn = functionName(ts, node);
      const surface = surfaceFor(file, fn);
      const locator = `${rel(file)}:${line}:${model.name}:${method}:${command}`;
      if (recorded.has(locator)) return;
      recorded.add(locator);
      accesses.push({ id: hashId("access", locator), sourceFile: rel(file), line, function: fn, tableId: `table-${slug(model.physicalTable)}`, prismaModel: model.name, command, method, executionSurface: surface, production, registrationEvidence: roots.has(file) ? "registered-entrypoint" : reachable.has(file) ? "reachable-from-registered-entrypoint" : "unregistered", evidence: evidence.replace(/\s+/g, " ").slice(0, 350) });
    };
    const delegateCandidates = (node, result = new Set()) => {
      if (ts.isPropertyAccessExpression(node) && delegates.has(node.name.text)) result.add(delegates.get(node.name.text));
      ts.forEachChild(node, (child) => delegateCandidates(child, result));
      return result;
    };
    const callableAliases = new Map();
    const collectCallables = (node) => {
      let name = null;
      let body = null;
      if (ts.isFunctionDeclaration(node) && node.name) { name = node.name.text; body = node.body; }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) { name = node.name.text; body = node.initializer.body; }
      if (name && body) {
        const candidates = [...delegateCandidates(body)];
        if (candidates.length === 1) callableAliases.set(name, candidates[0]);
      }
      ts.forEachChild(node, collectCallables);
    };
    collectCallables(ast);
    const variableAliases = [];
    const containingScope = (node) => {
      for (let current = node.parent; current; current = current.parent) if (ts.isFunctionLike(current)) return current;
      return ast;
    };
    const resolveVariable = (name, position) => variableAliases.filter((alias) => alias.name === name && alias.start < position && alias.scopeStart <= position && alias.scopeEnd >= position).sort((a, b) => b.start - a.start)[0]?.model || null;
    const modelForExpression = (expression, position) => {
      if (!expression) return null;
      const candidates = [...delegateCandidates(expression)];
      if (candidates.length === 1) return candidates[0];
      if (ts.isIdentifier(expression)) return resolveVariable(expression.text, position);
      if (ts.isCallExpression(expression)) {
        const callee = expression.expression;
        if (ts.isIdentifier(callee)) return callableAliases.get(callee.text) || resolveVariable(callee.text, position);
      }
      return null;
    };
    const declarations = [];
    const collectDeclarations = (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && !ts.isArrowFunction(node.initializer) && !ts.isFunctionExpression(node.initializer)) declarations.push(node);
      ts.forEachChild(node, collectDeclarations);
    };
    collectDeclarations(ast);
    for (const declaration of declarations.sort((a, b) => a.getStart(ast) - b.getStart(ast))) {
      const model = modelForExpression(declaration.initializer, declaration.getStart(ast));
      if (!model) continue;
      const scope = containingScope(declaration);
      variableAliases.push({ name: declaration.name.text, model, start: declaration.getStart(ast), scopeStart: scope.getStart(ast), scopeEnd: scope.getEnd() });
    }
    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const target = node.expression.expression;
        if (methodNames.has(method) && ts.isPropertyAccessExpression(target) && delegates.has(target.name.text)) record(node, delegates.get(target.name.text), method, operationFor(method), node.getText(ast));
        else if (methodNames.has(method)) {
          const aliasModel = modelForExpression(target, node.getStart(ast));
          if (aliasModel) record(node, aliasModel, method, operationFor(method), node.getText(ast));
        }
        if (rawMethods.has(method)) {
          const raw = node.getText(ast);
          for (const [name, model] of physical) if (new RegExp(`(?:\\b|[\"'])${name}(?:\\b|[\"'])`, "i").test(raw)) for (const command of rawCommandsFor(method, raw)) record(node, model, method, command, raw);
        }
      }
      if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) && rawMethods.has(node.tag.name.text)) {
        const raw = node.getText(ast);
        for (const [name, model] of physical) if (new RegExp(`(?:\\b|[\"'])${name}(?:\\b|[\"'])`, "i").test(raw)) for (const command of rawCommandsFor(node.tag.name.text, raw)) record(node, model, node.tag.name.text, command, raw);
      }
      ts.forEachChild(node, visit);
    };
    visit(ast);
  };
  active.forEach((file) => scanFile(file, true));
  const unregistered = all.filter((file) => !reachable.has(file));
  unregistered.forEach((file) => scanFile(file, false));
  return { accesses: accesses.filter((item) => item.production).sort((a, b) => a.id.localeCompare(b.id)), unregisteredAccesses: accesses.filter((item) => !item.production).sort((a, b) => a.id.localeCompare(b.id)), activeFiles: active.map(rel), unregisteredFiles: unregistered.map(rel), registrations: detectRegistrations() };
};

const displayName = (fn) => fn === "module" ? "Module database access" : fn.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/^./, (letter) => letter.toUpperCase());
const identityForWorkflow = (workflow) => workflow.authorizationBoundaryType === "pre-auth-security-function" ? "identity-pre-auth-app"
  : workflow.executionSurface === "worker" ? "identity-worker"
    : workflow.executionSurface === "scheduled" ? "identity-scheduled-job"
      : ["cli", "startup"].includes(workflow.executionSurface) ? "identity-staging-operator-admin"
        : "identity-authenticated-app";
const expandCommands = (commandsToExpand) => [...new Set(commandsToExpand.flatMap((command) => command === "COUNT" ? ["SELECT"] : command === "UPSERT" ? ["INSERT", "UPDATE"] : [command]))].sort();
const commandCondition = (identityId, table) => identityId === "identity-pre-auth-app" ? "EXECUTE only an exact named function signature; no direct table grant"
  : identityId === "identity-auth-function-owner" ? "Exact function-required column privileges only; NOLOGIN owner"
    : identityId === "identity-worker" ? "Durably verified job and tenant scope; queue payload is not authority"
      : identityId === "identity-scheduled-job" ? "Approved schedule and durable tenant/job scope"
        : identityId === "identity-staging-operator-admin" ? "Broker-controlled command allowlist with immutable audit"
          : table.appendOnly ? "Scoped projection or append command; mutation of existing evidence is denied" : "Reviewed canonical workflow with transaction-local actor/tenant context";

const applyRuntimeCommandMatrix = (table, workflows) => {
  const touching = workflows.filter((workflow) => workflow.tablesTouched.includes(table.id));
  const entries = new Map();
  const readers = new Set();
  const writers = new Set();
  const add = (identityId, commandsToAdd, condition = commandCondition(identityId, table)) => {
    if (!entries.has(identityId)) entries.set(identityId, { identityId, commands: new Set(), conditions: new Set() });
    const entry = entries.get(identityId);
    for (const command of expandCommands(commandsToAdd)) entry.commands.add(command);
    entry.conditions.add(condition);
  };
  for (const workflow of touching) {
    const commandsForTable = workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands || [];
    const identityId = identityForWorkflow(workflow);
    const hasRead = commandsForTable.some((command) => ["SELECT", "COUNT", "RAW_SQL"].includes(command));
    const hasWrite = commandsForTable.some((command) => ["INSERT", "UPDATE", "DELETE", "UPSERT", "RAW_SQL"].includes(command));
    if (identityId === "identity-pre-auth-app") {
      add(identityId, ["EXECUTE"]);
      add("identity-auth-function-owner", commandsForTable, "Exact named function-required column privileges only; no generic query authority");
    } else add(identityId, commandsForTable);
    if (hasRead) readers.add(identityId);
    if (hasWrite) writers.add(identityId);
  }
  if (READ_ROLE_MODELS.has(table.prismaModel)) {
    add("identity-restricted-read", ["SELECT"], "Explicitly approved read-only RLS projection/canary table");
    readers.add("identity-restricted-read");
  }
  if (table.appendOnly) {
    for (const entry of entries.values()) {
      if (entry.commands.has("UPDATE")) entry.commands.delete("UPDATE");
      if (entry.commands.has("DELETE") && !RETENTION_DELETE_MODELS.has(table.prismaModel)) entry.commands.delete("DELETE");
      if (entry.commands.has("DELETE")) entry.conditions.add("DELETE is limited to the approved retention lifecycle; ordinary callers are denied");
    }
  }
  table.allowedCommandsByIdentity = [...entries.values()].map((entry) => ({ identityId: entry.identityId, commands: [...entry.commands].sort(), conditions: [...entry.conditions].sort() })).filter((entry) => entry.commands.length).sort((a, b) => a.identityId.localeCompare(b.identityId));
  table.allowedRuntimeReaders = [...readers].sort();
  table.allowedRuntimeWriters = [...writers].sort();
  table.intendedDatabaseRoles = [...new Set(table.allowedCommandsByIdentity.map((entry) => entry.identityId))].sort();
};

export const buildPolicyDependencyGraph = (tableManifest) => {
  const tablesById = new Map(tableManifest.tables.map((table) => [table.id, table]));
  const edges = [];
  for (const table of tableManifest.tables) {
    if (!table.authorizationParentTable) continue;
    const dependency = tablesById.get(table.authorizationParentTable);
    const join = table.authorizationParentColumns;
    edges.push({
      sourceTable: table.id,
      dependencyTable: dependency.id,
      reason: `${table.prismaModel} authorization inherits from ${dependency.prismaModel}; no alternative parent is evaluated.`,
      helperFunctionUsed: "none; direct equality join in the future generated predicate",
      dependencyRlsProtected: dependency.forceRlsTarget,
      recursionRisk: "none",
      requiredIndexOrJoinKey: `${table.prismaModel}.${join.child.join("+")} -> ${dependency.prismaModel}.${join.parent.join("+")}; referenced key must be unique/indexed and the child key must be indexed before policy certification`,
      joinKey: { sourceColumns: join.child, dependencyColumns: join.parent },
      plannerSensitiveHiddenDependency: false,
      unrestrictedRuntimeOwnedDependency: false,
    });
  }
  const visiting = new Set();
  const depths = new Map();
  const depth = (id) => {
    if (depths.has(id)) return depths.get(id);
    assert(!visiting.has(id), `policy dependency cycle includes ${id}`);
    visiting.add(id);
    const dependencies = edges.filter((edge) => edge.sourceTable === id);
    const value = dependencies.length ? 1 + Math.max(...dependencies.map((edge) => depth(edge.dependencyTable))) : 0;
    visiting.delete(id);
    depths.set(id, value);
    return value;
  };
  tableManifest.tables.forEach((table) => depth(table.id));
  const nodes = tableManifest.tables.map((table) => ({ id: table.id, prismaModel: table.prismaModel, primaryCategory: table.primaryCategory, reviewGroup: table.reviewGroup, physicalOwnerRole: table.physicalOwnerRole, forceRlsTarget: table.forceRlsTarget, terminalBoundary: table.terminalBoundary, dependencyLayer: depths.get(table.id) })).sort((a, b) => a.id.localeCompare(b.id));
  const reviewGroups = Object.fromEntries(Object.keys(REVIEW_GROUP_MODELS).map((group) => {
    const groupTables = tableManifest.tables.filter((table) => table.reviewGroup === group);
    return [group, { tableCount: groupTables.length, resolvedCount: groupTables.filter((table) => table.classificationStatus === "resolved").length, unresolvedCount: groupTables.filter((table) => table.classificationStatus !== "resolved").length, dependencyEdges: edges.filter((edge) => groupTables.some((table) => table.id === edge.sourceTable)).length, blockingDecisions: [...new Set(groupTables.flatMap((table) => table.unresolvedDecisionIds))], ownershipConfidence: Object.fromEntries(["high", "medium", "low"].map((confidence) => [confidence, groupTables.filter((table) => table.ownershipConfidence === confidence).length])) }];
  }));
  const graph = { schemaVersion: 1, generatedFrom: "documents/security/rls-program/tables.json", direction: "source policy table -> table read by its authorization predicate", nodes, edges: edges.sort((a, b) => a.sourceTable.localeCompare(b.sourceTable)), acyclic: true, selfRecursivePolicies: 0, plannerSensitiveHiddenDependencies: 0, unrestrictedRuntimeOwnedDependencies: 0, reviewGroups };
  writeJson(policyDependencyGraphPath, graph);
  return graph;
};

const markdownCell = (value) => String(value ?? "—").replaceAll("|", "\\|").replaceAll("\n", " ");
export const writeTableOwnershipReview = (tableManifest, graph) => {
  const lines = [
    "# MSCQR full-database table ownership review",
    "",
    "This is the compact human review of the machine-readable classification in `tables.json`. It changes no policy, database owner, role, runtime behavior, or RLS state. All 77 Prisma tables remain policy-generation candidates owned logically by `identity-table-owner`; implementation and disposable PostgreSQL proof are separate work.",
    "",
    `Dependency graph: ${graph.nodes.length} nodes, ${graph.edges.length} directed edges, acyclic=${graph.acyclic}, recursion risks=${graph.edges.filter((edge) => edge.recursionRisk !== "none").length}.`,
    "",
  ];
  for (const [group, names] of Object.entries({ A: "Security-sensitive and identity", B: "Tenant roots and membership", C: "Batch and QR lifecycle", D: "Printing and printers", E: "Audit, incident and governance", F: "Operational/system", G: "Reference and remaining" })) {
    const tables = tableManifest.tables.filter((table) => table.reviewGroup === group).sort((a, b) => a.prismaModel.localeCompare(b.prismaModel));
    const summary = graph.reviewGroups[group];
    lines.push(`## Group ${group} — ${names}`, "", `Tables: ${summary.tableCount}; resolved: ${summary.resolvedCount}; unresolved: ${summary.unresolvedCount}; dependency edges: ${summary.dependencyEdges}; confidence high/medium/low: ${summary.ownershipConfidence.high}/${summary.ownershipConfidence.medium}/${summary.ownershipConfidence.low}; blockers: ${summary.blockingDecisions.join(", ") || "none"}.`, "", "| Table | Category | Row scope | Parent | FORCE RLS | Readers | Writers | Confidence | Blocker |", "|---|---|---|---|---:|---|---|---|---|");
    for (const table of tables) lines.push(`| ${[table.prismaModel, table.primaryCategory, table.rowOwnershipModel, table.authorizationParentTable || "—", table.forceRlsTarget ? "yes" : "no", table.allowedRuntimeReaders.join(", ") || "none", table.allowedRuntimeWriters.join(", ") || "none", table.ownershipConfidence, table.unresolvedDecisionIds.join(", ") || "none"].map(markdownCell).join(" | ")} |`);
    lines.push("");
  }
  fs.writeFileSync(tableOwnershipReviewPath, `${lines.join("\n")}\n`);
};

const routeSource = () => fs.readFileSync(path.join(repoRoot, "backend/src/routes/index.ts"), "utf8");
const routeEvidenceFor = (functionName, source = routeSource()) => {
  const lines = source.split("\n");
  const index = lines.findLastIndex((line) => new RegExp(`\\b${functionName}\\b`).test(line));
  if (index < 0) return null;
  const excerpt = lines.slice(Math.max(0, index - 14), index + 2).join(" ").replace(/\s+/g, " ");
  const guards = ["authenticate", "requirePlatformAdmin", "requireLicenseeAdmin", "requireAnyAdmin", "requireManufacturer", "requireRecentAdminMfa", "requireRecentSensitiveAuth", "requireCustomerVerifyAuth", "optionalCustomerVerifyAuth", "enforceTenantIsolation", "requireCsrf"].filter((guard) => new RegExp(`\\b${guard}\\b`).test(excerpt));
  const route = excerpt.match(/(?:get|post|put|patch|delete)\(\s*["']([^"']+)/)?.[1] || null;
  return { source: `backend/src/routes/index.ts:${index + 1}`, route, guards };
};

const commandActorsFor = (workflow, table, routeEvidence) => {
  const text = `${workflow.id} ${workflow.canonicalSourceFiles.join(" ")}`.toLowerCase();
  const guards = new Set(routeEvidence?.guards || []);
  if (workflow.authorizationBoundaryType === "operator-break-glass") return ["break-glass"];
  if (workflow.authorizationBoundaryType === "pre-auth-security-function") return ["anonymous", "pre-auth-runtime"];
  if (workflow.executionSurface === "worker") return ["worker"];
  if (workflow.executionSurface === "scheduled") return ["scheduled-job"];
  if (workflow.authorizationBoundaryType === "migration-owner") return ["migration"];
  if (["cli", "startup"].includes(workflow.executionSurface)) return ["operator-admin"];
  if (guards.has("requirePlatformAdmin") || workflow.authorizationBoundaryType === "platform-admin") return ["platform-admin"];
  if (guards.has("requireLicenseeAdmin")) return ["licensee-admin"];
  if (guards.has("requireManufacturer")) return ["manufacturer"];
  if (/release|checker|approve/.test(text) && ["Batch", "QrAllocationRequest", "SensitiveActionApproval", "PrintReissueRequest"].includes(table.prismaModel)) return ["checker"];
  if (guards.has("requireAnyAdmin")) return ["licensee-admin", "platform-admin"];
  if (workflow.authorizationBoundaryType === "actor-owned" || /auth|account|customer/.test(text)) return ["authenticated-user"];
  if (/manufacturer|print|printer/.test(text)) return ["manufacturer"];
  if (/incident|governance|policy|audit|forensic|support/.test(text)) return ["operator", "licensee-admin", "platform-admin"];
  if (/licensee|allocation|qr-request/.test(text)) return ["licensee-admin", "platform-admin"];
  return ["authenticated-user"];
};

const runtimeIdentityForCommand = (workflow) => workflow.authorizationBoundaryType === "operator-break-glass" ? "identity-production-break-glass"
  : workflow.authorizationBoundaryType === "pre-auth-security-function" ? "identity-pre-auth-app"
    : workflow.executionSurface === "worker" ? "identity-worker"
      : workflow.executionSurface === "scheduled" ? "identity-scheduled-job"
        : workflow.authorizationBoundaryType === "migration-owner" ? "identity-migration"
          : ["cli", "startup"].includes(workflow.executionSurface) ? "identity-staging-operator-admin"
            : "identity-authenticated-app";

const assuranceForCommand = (workflow, actors, command, table, routeEvidence) => {
  const guards = new Set(routeEvidence?.guards || []);
  if (actors.includes("break-glass")) return "dual-approved-break-glass";
  if (actors.includes("operator-admin")) return "operator-approved";
  if (actors.includes("worker") || actors.includes("scheduled-job") || actors.includes("migration")) return "system-verified";
  if (actors.includes("pre-auth-runtime")) return /mfa|webauthn|challenge/.test(workflow.id) ? "mfa-bootstrap" : "none";
  if (guards.has("requireRecentSensitiveAuth")) return "step-up-verified";
  if (guards.has("requireRecentAdminMfa")) return "mfa-verified";
  if (command !== "SELECT" && (actors.some((actor) => ["platform-admin", "licensee-admin", "checker"].includes(actor)) || table.primaryCategory === "security-sensitive")) return "mfa-verified";
  return "password-verified";
};

const scalarColumnsFor = (table) => {
  const modelNames = new Set(parseSchema().map((model) => model.name));
  return table.schemaEvidence.fields.filter((field) => !modelNames.has(field.type)).map((field) => field.name).sort();
};
const lifecycleColumnsFor = (table) => scalarColumnsFor(table).filter((column) => /(?:status|state|stage|enabled|disabledAt|deletedAt|revokedAt|consumedAt|expiresAt|releasedAt|confirmedAt|approvedAt|rejectedAt|usedAt|readAt)$/i.test(column));
const schemaEnumValues = new Map([...fs.readFileSync(schemaPath, "utf8").matchAll(/^enum\s+(\w+)\s*\{([\s\S]*?)^\}/gm)].map((match) => [match[1], match[2].split("\n").map((line) => line.replace(/\/\/.*$/, "").trim()).filter(Boolean)]));
const lifecycleValuesFor = (table, column) => {
  const field = table.schemaEvidence.fields.find((item) => item.name === column);
  const values = schemaEnumValues.get(field?.type);
  if (values) return values.map((value) => `${column}=${value}`);
  if (field?.type === "Boolean") return [`${column}=false`, `${column}=true`];
  return [`${column}=NULL`, `${column}=SERVER_TIMESTAMP_SET`];
};
const protectedColumnsFor = (table) => [...new Set([
  "id", "createdAt", "updatedAt",
  ...table.tenantKeyColumns,
  ...table.actorKeyColumns,
  ...(table.authorizationParentColumns?.child || []),
  ...table.sensitiveColumns,
  ...scalarColumnsFor(table).filter((column) => /(?:^role$|platformAdmin|createdBy|updatedBy|approvedBy|reviewedBy|executedBy|requestedBy|actorUser|auditActor|makerUser|checkerUser|code$|publicCode|qrCodeValue|serial|token|hash|secret|credential|challenge|evidence|attestation|signature|releasedAt|releaseEvidence|confirmedAt)$/i.test(column)),
  ...lifecycleColumnsFor(table),
])].filter((column) => scalarColumnsFor(table).includes(column)).sort();

const lifecycleFor = (table, command, workflow) => {
  const columns = lifecycleColumnsFor(table);
  if (!columns.length) return { columns: [], allowed: [], forbidden: [] };
  const states = columns.flatMap((column) => lifecycleValuesFor(table, column));
  if (command === "SELECT") return { columns, allowed: states, forbidden: [] };
  if (table.prismaModel === "Batch") {
    const allowed = ["DRAFT", "CODES_GENERATED", "PRINT_ACKNOWLEDGED", "PRINT_CONFIRMED", "SAMPLE_VERIFIED"];
    const text = workflow.id.toLowerCase();
    if (/release/.test(text)) return { columns, allowed: ["SAMPLE_VERIFIED"], forbidden: ["RELEASED", "FAILED", "VOIDED"] };
    if (/sample/.test(text)) return { columns, allowed: ["PRINT_CONFIRMED"], forbidden: ["RELEASED", "FAILED", "VOIDED"] };
    if (/confirm/.test(text)) return { columns, allowed: ["PRINT_ACKNOWLEDGED"], forbidden: ["RELEASED", "FAILED", "VOIDED"] };
    if (/print|ack/.test(text)) return { columns, allowed: ["CODES_GENERATED"], forbidden: ["RELEASED", "FAILED", "VOIDED"] };
    return { columns, allowed, forbidden: ["RELEASED", "FAILED", "VOIDED"] };
  }
  if (command === "INSERT") {
    const defaults = columns.flatMap((column) => {
      const field = table.schemaEvidence.fields.find((item) => item.name === column);
      const value = field?.attributes.match(/@default\(([^)]+)\)/)?.[1];
      return value ? [`${column}=${value}`] : [`${column}=NULL_OR_SERVER_INITIALIZED`];
    });
    return { columns, allowed: defaults, forbidden: ["CLIENT_SELECTED_INITIAL_STATE"] };
  }
  if (command === "DELETE") return { columns, allowed: states, forbidden: ["LEGAL_HOLD_OR_UNSATISFIED_PARENT_LIFECYCLE"] };
  return { columns, allowed: states, forbidden: ["ANY_STATE_CHANGE_NOT_ACCEPTED_ATOMICALLY_BY_THE_CANONICAL_SERVICE"] };
};

const deleteSemanticsFor = (table, workflow = null) => {
  if (!workflow) return "prohibited";
  const text = `${workflow.id} ${workflow.canonicalSourceFiles.join(" ")}`.toLowerCase();
  if (/seed|prisma/.test(text)) return "migration-only";
  if (["QrScanLog", "IncidentEvidence", "IncidentEvidenceFingerprint", "ActionIdempotencyKey"].includes(table.prismaModel)) return "retention delete";
  if (["AdminWebAuthnCredential", "CustomerWebAuthnCredential", "UserMfaFactor", "UserBackupCode"].includes(table.prismaModel)) return "actor self-delete";
  if (["Batch", "QRCode", "ManufacturerLicenseeLink", "User", "Printer"].includes(table.prismaModel)) return "tenant-admin delete";
  if (table.authorizationParentTable) return "cascade through approved parent lifecycle";
  return "operator-approved";
};

const scopeRuleFor = (table, actors) => {
  if (actors.some((actor) => ["worker", "scheduled-job"].includes(actor))) return "Durably verified job identity plus persisted job and tenant scope; queue payload scope is never authoritative.";
  if (actors.includes("break-glass")) return "Ephemeral command allowlist, exact incident scope, expiry, dual approval, and immutable transcript.";
  if (table.authorizationParentTable) return `${table.id} row must join through ${table.authorizationParentTable} on ${table.authorizationParentColumns.child.join("+")}=${table.authorizationParentColumns.parent.join("+")}; no alternative parent.`;
  if (table.tenantKeyColumns.length) return `Every non-NULL ${table.tenantKeyColumns.join("/")} must equal trusted transaction tenant context; NULL semantics follow tables.json and never mean global.`;
  if (table.actorKeyColumns.length) return `${table.actorKeyColumns.join("/")} must equal trusted actor context; administrator access is command-specific and audited.`;
  return `${table.terminalBoundary} boundary from tables.json; empty or forged context is denied.`;
};

const buildCommandRule = ({ table, workflow, command, actors, identityId, assurance, routeEvidence }) => {
  const scalarColumns = scalarColumnsFor(table);
  const protectedColumns = protectedColumnsFor(table);
  const lifecycle = lifecycleFor(table, command, workflow);
  const securityFunction = table.primaryCategory === "security-sensitive" && (command !== "SELECT" || table.sensitiveColumns.length > 0);
  const preAuthFunction = actors.includes("pre-auth-runtime");
  const workerBoundary = actors.some((actor) => ["worker", "scheduled-job"].includes(actor));
  const operatorApproval = actors.some((actor) => ["operator-admin", "break-glass"].includes(actor));
  const rawEvidence = workflow.supportingEvidence.some((evidence) => evidence.method?.startsWith("$"));
  const allowedColumns = command === "DELETE" ? [] : command === "SELECT"
    ? scalarColumns.filter((column) => !(table.primaryCategory === "security-sensitive" && table.sensitiveColumns.includes(column)))
    : scalarColumns.filter((column) => !protectedColumns.includes(column));
  const hardDeleteSemantics = command === "DELETE" ? deleteSemanticsFor(table, workflow) : "not-applicable";
  const approvalClass = actors.includes("break-glass") ? "dual-approved-break-glass"
    : actors.includes("operator-admin") ? "operator-approved"
      : actors.includes("checker") && /release|approve/.test(workflow.id) ? "maker-checker-separation"
        : hardDeleteSemantics === "retention delete" ? "retention-authorization"
          : "none";
  const requiresApproval = approvalClass !== "none";
  const requiresNamedFunction = preAuthFunction || securityFunction || rawEvidence;
  const boundaryMode = workerBoundary ? "restricted-worker" : operatorApproval ? "operator-approval" : requiresNamedFunction ? "named-function" : "ordinary-rls";
  return {
    id: `command-${slug(table.prismaModel)}-${command.toLowerCase()}-${crypto.createHash("sha256").update(workflow.id).digest("hex").slice(0, 12)}`,
    tableId: table.id,
    command,
    actorClasses: actors,
    runtimeIdentities: [identityId],
    minimumAssurance: assurance,
    scopeRule: scopeRuleFor(table, actors),
    allowedColumns,
    protectedColumns,
    allowedLifecycleStates: lifecycle.allowed,
    forbiddenLifecycleStates: lifecycle.forbidden,
    lifecycleColumns: lifecycle.columns,
    withCheckRule: command === "SELECT" || command === "DELETE" ? "not-applicable" : `New row preserves ${scopeRuleFor(table, actors)} Ownership, actor, approval, audit-attribution, identity, token/hash, and lifecycle fields come only from trusted server context or the named boundary.`,
    requiresNamedFunction,
    namedFunctionClass: requiresNamedFunction ? (preAuthFunction ? "narrow-pre-auth-security-definer" : rawEvidence ? "exact-reviewed-query-function" : "authenticated-security-repository-function") : "none",
    requiresRestrictedWorkerBoundary: workerBoundary,
    requiresAuditEvent: command !== "SELECT" || actors.some((actor) => ["platform-admin", "operator", "operator-admin", "break-glass"].includes(actor)),
    requiresApproval,
    approvalClass,
    authorizationBoundary: boundaryMode,
    hardDeleteSemantics,
    dependentDataBehavior: command === "DELETE" ? (table.authorizationParentTable ? "Only the schema-defined parent cascade and reviewed retention lifecycle may affect dependent rows." : "Dependent rows must be enumerated and certified before execution; implicit cross-tenant cascades are denied.") : "not-applicable",
    retentionLegalConsequences: command === "DELETE" ? "Legal hold, retention policy, tenant scope, and immutable audit evidence must be checked before deletion." : "not-applicable",
    supportingWorkflowIds: [workflow.id],
    supportingEvidence: [...workflow.canonicalSourceFiles, ...(routeEvidence ? [`${routeEvidence.source} guards=${routeEvidence.guards.join(",") || "none"}`] : [])],
    allowScenarios: [`${actors.join(" or ")} using ${identityId} at ${assurance} performs ${command} within the recorded scope, column set, lifecycle, and boundary.`],
    denyScenarios: ["Anonymous, empty-context, foreign-tenant, wrong-actor, lower-assurance, forbidden-state, protected-column, role-elevation, ownership-transfer, or unapproved execution is denied."],
    confidence: routeEvidence || workerBoundary || preAuthFunction || operatorApproval ? "high" : "medium",
    status: "architecture-resolved",
  };
};

export const buildCommandSemantics = (tableManifest, workflowManifest) => {
  const tablesById = new Map(tableManifest.tables.map((table) => [table.id, table]));
  const rules = [];
  for (const workflow of workflowManifest.workflows) {
    const routeEvidence = workflow.executionSurface === "http" ? routeEvidenceFor(workflow.entryPoint.split(":").at(-1)) : null;
    workflow.commandRuleIds = [];
    workflow.commandActorClasses = [];
    workflow.requiredAssurance = [];
    workflow.runtimeIdentities = [];
    for (const item of workflow.commandsPerTable) {
      const table = tablesById.get(item.tableId);
      if (!table?.forceRlsTarget) continue;
      for (const command of item.commands) {
        const actors = commandActorsFor(workflow, table, routeEvidence);
        const identityId = runtimeIdentityForCommand(workflow);
        const assurance = assuranceForCommand(workflow, actors, command, table, routeEvidence);
        const rule = buildCommandRule({ table, workflow, command, actors, identityId, assurance, routeEvidence });
        rules.push(rule);
        workflow.commandRuleIds.push(rule.id);
        workflow.commandActorClasses.push(...actors);
        workflow.requiredAssurance.push(assurance);
        workflow.runtimeIdentities.push(identityId);
      }
    }
    workflow.commandRuleIds.sort();
    workflow.commandActorClasses = [...new Set(workflow.commandActorClasses)].sort();
    workflow.actorClasses = workflow.commandActorClasses;
    workflow.requiredAssurance = [...new Set(workflow.requiredAssurance)].sort();
    workflow.runtimeIdentities = [...new Set(workflow.runtimeIdentities)].sort();
    workflow.semanticStatus = workflow.commandRuleIds.length || workflow.tablesTouched.every((id) => !tablesById.get(id)?.forceRlsTarget) ? "mapped" : "unresolved";
    workflow.expectedAllowedScenarios = ["Every database command matches one referenced command rule, including its actor, identity, assurance, scope, columns, lifecycle, and special boundary."];
    workflow.expectedDeniedScenarios = ["Any command without a matching rule, or with foreign scope, missing assurance, protected-column assignment, forbidden lifecycle state, or role elevation is denied."];
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== "decision-policy-command-semantics");
  }
  for (const table of tableManifest.tables.filter((item) => item.forceRlsTarget)) {
    if (table.allowedCommandsByIdentity.some((entry) => entry.identityId === "identity-restricted-read" && entry.commands.includes("SELECT"))) {
      const restrictedWorkflow = { id: `runtime-restricted-read-${table.id}`, canonicalSourceFiles: ["documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql"], supportingEvidence: [], authorizationBoundaryType: "authenticated-context", executionSurface: "internal" };
      const restricted = buildCommandRule({ table, workflow: restrictedWorkflow, command: "SELECT", actors: ["restricted-read"], identityId: "identity-restricted-read", assurance: "system-verified", routeEvidence: null });
      restricted.id = `command-${slug(table.prismaModel)}-select-restricted-read`;
      restricted.supportingWorkflowIds = [];
      restricted.supportingEvidence = ["tables.json explicitly approves this table for the SELECT-only RLS read/canary identity."];
      restricted.confidence = "high";
      rules.push(restricted);
    }
    const prohibited = {
      id: `command-${slug(table.prismaModel)}-delete-prohibited`, tableId: table.id, command: "DELETE", actorClasses: [], runtimeIdentities: [], minimumAssurance: "none",
      scopeRule: "No general hard-delete scope exists.", allowedColumns: [], protectedColumns: scalarColumnsFor(table), allowedLifecycleStates: [], forbiddenLifecycleStates: ["ALL_STATES"], lifecycleColumns: lifecycleColumnsFor(table),
      withCheckRule: "not-applicable", requiresNamedFunction: false, namedFunctionClass: "none", requiresRestrictedWorkerBoundary: false, requiresAuditEvent: false, requiresApproval: false, approvalClass: "none", authorizationBoundary: "prohibited", hardDeleteSemantics: "prohibited",
      dependentDataBehavior: "No cascade is authorized by this rule.", retentionLegalConsequences: "Deletion requires a separate explicit workflow rule; absence of one is denial.", supportingWorkflowIds: [], supportingEvidence: ["Default-deny hard-delete architecture rule in ARCHITECTURE.md."],
      allowScenarios: ["None; this rule records the default prohibition."], denyScenarios: ["Every direct or cascaded DELETE lacking a separate exact command rule is denied."], confidence: "high", status: "architecture-resolved",
    };
    rules.push(prohibited);
    table.commandRuleIds = rules.filter((rule) => rule.tableId === table.id).map((rule) => rule.id).sort();
    table.commandSemanticsAuthority = "documents/security/rls-program/command-semantics.json";
    table.deleteSemantics = [...new Set(rules.filter((rule) => rule.tableId === table.id && rule.command === "DELETE").map((rule) => rule.hardDeleteSemantics))].sort();
    table.unresolvedDecisions = table.unresolvedDecisions.filter((id) => id !== "decision-policy-command-semantics");
  }
  const manifest = { schemaVersion: 1, generatedFrom: ["backend/prisma/schema.prisma", "documents/security/rls-program/tables.json", "documents/security/rls-program/workflows.json", "backend/src/routes/index.ts"], actorClasses: [...actorClasses], assuranceLevels: [...assuranceLevels], commandVocabulary: [...policyCommands], rules: rules.sort((a, b) => a.id.localeCompare(b.id)) };
  writeJson(commandSemanticsPath, manifest);
  return manifest;
};

export const writeCommandSemanticsReview = (manifest, tableManifest, workflowManifest) => {
  const count = (key, value) => manifest.rules.filter((rule) => Array.isArray(rule[key]) ? rule[key].includes(value) : rule[key] === value).length;
  const lines = ["# MSCQR full-database command semantics review", "", "This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.", "", `Rules: ${manifest.rules.length}; workflows mapped: ${workflowManifest.workflows.filter((workflow) => workflow.semanticStatus === "mapped").length}/${workflowManifest.workflows.length}.`, "", "## Review groups", "", "| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |", "|---|---:|---:|---:|---:|---:|---:|"];
  for (const group of "ABCDEFG") {
    const ids = new Set(tableManifest.tables.filter((table) => table.reviewGroup === group).map((table) => table.id));
    const groupRules = manifest.rules.filter((rule) => ids.has(rule.tableId));
    lines.push(`| ${group} | ${ids.size} | ${groupRules.length} | ${groupRules.filter((rule) => rule.command === "SELECT").length} | ${groupRules.filter((rule) => rule.command === "INSERT").length} | ${groupRules.filter((rule) => rule.command === "UPDATE").length} | ${groupRules.filter((rule) => rule.command === "DELETE").length} |`);
  }
  for (const [heading, key, values] of [["Actor classes", "actorClasses", actorClasses], ["Assurance levels", "minimumAssurance", assuranceLevels], ["Commands", "command", policyCommands]]) {
    lines.push("", `## ${heading}`, "", "| Value | Rules |", "|---|---:|");
    for (const value of values) lines.push(`| ${value} | ${count(key, value)} |`);
  }
  lines.push("", "## Boundary and deletion summary", "", `Named-function rules: ${manifest.rules.filter((rule) => rule.requiresNamedFunction).length}.`, `Restricted-worker rules: ${manifest.rules.filter((rule) => rule.requiresRestrictedWorkerBoundary).length}.`, `Approval-gated rules: ${manifest.rules.filter((rule) => rule.requiresApproval).length}.`, "", "| Hard-delete classification | Rules |", "|---|---:|");
  for (const value of [...new Set(manifest.rules.map((rule) => rule.hardDeleteSemantics))].sort()) lines.push(`| ${value} | ${count("hardDeleteSemantics", value)} |`);
  lines.push("", "Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.", "");
  fs.writeFileSync(commandSemanticsReviewPath, `${lines.join("\n")}\n`);
};

export const buildWorkflowManifest = () => {
  const scan = scanProductionAccess();
  const existing = readJson(workflowManifestPath, { schemaVersion: 1, workflows: [] });
  const previous = new Map(existing.workflows.map((workflow) => [workflow.id, workflow]));
  const groups = new Map();
  for (const access of scan.accesses) {
    const key = `${access.executionSurface}:${access.sourceFile}:${access.function}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(access);
  }
  const workflows = [...groups.entries()].map(([key, accesses]) => {
    const first = accesses[0];
    const id = `workflow-${slug(key)}`;
    const old = previous.get(id) || {};
    const boundary = old.authorizationBoundaryType || boundaryFor(path.join(repoRoot, first.sourceFile), first.function, first.executionSurface);
    const tableCommands = [...new Set(accesses.flatMap((access) => expandCommands([access.command]).map((command) => `${access.tableId}:${command}`)))].sort().map((value) => { const index = value.lastIndexOf(":"); return { tableId: value.slice(0, index), commands: [value.slice(index + 1)] }; });
    const mergedCommands = [...new Map(tableCommands.map((item) => [item.tableId, { tableId: item.tableId, commands: tableCommands.filter((candidate) => candidate.tableId === item.tableId).flatMap((candidate) => candidate.commands).sort() }])).values()];
    const preAuth = boundary === "pre-auth-security-function";
    const background = ["worker", "scheduled"].includes(first.executionSurface);
    const systemSurface = ["startup", "cli"].includes(first.executionSurface);
    return {
      ...old,
      id,
      name: old.name || displayName(first.function),
      entryPoint: old.entryPoint || `${first.executionSurface}:${first.function}`,
      executionSurface: first.executionSurface,
      authenticationStage: old.authenticationStage || (preAuth ? "pre-authentication" : background || ["cli", "startup"].includes(first.executionSurface) ? "system" : "authenticated"),
      actorClasses: old.actorClasses || (background ? ["system-job"] : preAuth ? ["anonymous-or-partially-authenticated"] : first.executionSurface === "cli" ? ["operator"] : ["authenticated-user"]),
      canonicalSourceFiles: [...new Set(accesses.map((access) => access.sourceFile))].sort(),
      tablesTouched: mergedCommands.map((item) => item.tableId),
      commandsPerTable: mergedCommands,
      tenantScopeRule: old.tenantScopeRule || "unresolved; must be approved before implementation",
      contextRequirements: old.contextRequirementsSource === "human-reviewed" ? old.contextRequirements : (preAuth ? ["named narrow SECURITY DEFINER function or approved empty-context denial"] : background ? ["approved restricted system identity", "job-bound tenant scope"] : systemSurface ? ["approved non-owning system or operator identity", "command-bound scope"] : ["transaction-local canonical actor context"]),
      contextRequirementsSource: old.contextRequirementsSource || "generated-conservative",
      authorizationBoundaryType: boundary,
      expectedAllowedScenarios: old.expectedAllowedScenarios || ["Approved actor or system identity performs the named command within its recorded scope."],
      expectedDeniedScenarios: old.expectedDeniedScenarios || ["Missing, forged, stale, or cross-tenant context is denied."],
      preAuthSystemRequirements: old.preAuthSystemRequirements || (preAuth ? ["No direct table fallback; exact function grants and owner must be certified."] : background || systemSurface ? ["No superuser, ownership execution, or BYPASSRLS."] : []),
      currentDirectPrismaUsage: accesses.map((access) => access.id),
      currentCompatibilityStatus: old.currentCompatibilityStatus || "blocked-until-context-and-policy-proof",
      implementationStatus: old.implementationStatus || "inventory-only",
      requiredUnitTests: old.requiredUnitTests || ["Allowed and denied command contract for this canonical workflow."],
      requiredDisposablePostgresqlTests: old.requiredDisposablePostgresqlTests || ["Exact role, context, command, cross-tenant denial, and empty-context denial."],
      unresolvedDecisions: old.unresolvedDecisions || [background ? "decision-worker-identity-model" : preAuth ? "decision-pre-auth-boundary" : "decision-policy-command-semantics"],
      supportingEvidence: accesses.map((access) => ({ accessId: access.id, source: `${access.sourceFile}:${access.line}`, registration: access.registrationEvidence, method: access.method })),
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const result = { schemaVersion: 1, groupingRule: "One workflow per execution surface, canonical source file, and containing function; repeated table calls within that function remain one functional workflow.", generatedEvidence: { productionAccessSites: scan.accesses.length, testPathsExcluded: ["backend/tests", "scripts/tests"], registrations: scan.registrations, unregisteredPotentiallyDeadAccesses: scan.unregisteredAccesses, unregisteredFiles: scan.unregisteredFiles }, workflows };
  const tableManifest = readJson(tableManifestPath);
  for (const table of tableManifest.tables) {
    const touching = workflows.filter((workflow) => workflow.tablesTouched.includes(table.id));
    table.productionRuntimeReaders = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.some((command) => ["SELECT", "COUNT", "RAW_SQL"].includes(command))).map((workflow) => workflow.id);
    table.productionRuntimeWriters = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.some((command) => ["INSERT", "UPDATE", "DELETE", "UPSERT", "RAW_SQL"].includes(command))).map((workflow) => workflow.id);
    table.requiredCommands = [...new Set(touching.flatMap((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands || []))].sort();
    applyRuntimeCommandMatrix(table, workflows);
    table.classificationEvidence = table.classificationEvidence.filter((evidence) => !evidence.startsWith("Production inventory:") && !evidence.startsWith("Canonical production sources:") && !evidence.startsWith("Registration proof:") && !evidence.startsWith("Existing read-role evidence:"));
    table.classificationEvidence.push(`Production inventory: ${touching.length} canonical workflows, ${table.productionRuntimeReaders.length} reader workflows, ${table.productionRuntimeWriters.length} writer workflows, commands ${table.requiredCommands.join(", ") || "none"}.`);
    const canonicalSources = [...new Set(touching.flatMap((workflow) => workflow.canonicalSourceFiles))].sort();
    if (canonicalSources.length) table.classificationEvidence.push(`Canonical production sources: ${canonicalSources.slice(0, 8).join(", ")}${canonicalSources.length > 8 ? ` (+${canonicalSources.length - 8} more in workflows.json)` : ""}.`);
    else {
      const unregistered = scan.unregisteredAccesses.filter((access) => access.tableId === table.id);
      table.classificationEvidence.push(`Registration proof: no active production workflow or registered package/startup entry accesses this table; ${unregistered.length} unregistered access site(s) are retained separately in workflows.json.`);
    }
    if (READ_ROLE_MODELS.has(table.prismaModel)) table.classificationEvidence.push("Existing read-role evidence: documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql includes this table in the reviewed SELECT-only baseline.");
  }
  const commandManifest = buildCommandSemantics(tableManifest, result);
  writeCommandSemanticsReview(commandManifest, tableManifest, result);
  writeJson(workflowManifestPath, result);
  writeJson(tableManifestPath, tableManifest);
  const graph = buildPolicyDependencyGraph(tableManifest);
  writeTableOwnershipReview(tableManifest, graph);

  const decisionManifest = readJson(decisionManifestPath);
  if (decisionManifest) {
    for (const decision of decisionManifest.decisions) {
      if (decision.id === "decision-policy-command-semantics") {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.affectedWorkflows = workflows.map((workflow) => workflow.id);
        decision.affectedTables = tableManifest.tables.filter((table) => table.forceRlsTarget).map((table) => table.id);
        decision.resolution = {
          authority: "documents/security/rls-program/command-semantics.json",
          rules: commandManifest.rules.length,
          forceRlsTables: tableManifest.tables.filter((table) => table.forceRlsTarget).length,
          workflowsMapped: workflows.filter((workflow) => workflow.semanticStatus === "mapped").length,
          commandVocabulary: [...policyCommands],
          guarantees: ["No wildcard command, actor, or runtime identity", "INSERT and UPDATE have allowed/protected columns and WITH CHECK semantics", "Every DELETE records a default prohibition and any exact exception", "Lifecycle, assurance, named-function, worker, approval, and audit boundaries are explicit"],
        };
        continue;
      }
      decision.affectedWorkflows = workflows.filter((workflow) => workflow.unresolvedDecisions.includes(decision.id)
        || decision.id === "decision-runtime-role-split"
        || (decision.id === "decision-operator-administration" && workflow.authorizationBoundaryType === "operator-break-glass")).map((workflow) => workflow.id);
      decision.affectedTables = tableManifest.tables.filter((table) => table.unresolvedDecisions.includes(decision.id)
        || decision.id === "decision-table-ownership-classification"
        || decision.id === "decision-object-ownership-chain"
        || decision.affectedWorkflows.some((workflowId) => table.productionRuntimeReaders.includes(workflowId) || table.productionRuntimeWriters.includes(workflowId))).map((table) => table.id);
    }
    writeJson(decisionManifestPath, decisionManifest);
  }
  return result;
};

export const manifests = () => ({ tables: readJson(tableManifestPath), workflows: readJson(workflowManifestPath), identities: readJson(identityManifestPath), decisions: readJson(decisionManifestPath), commandSemantics: readJson(commandSemanticsPath) });
export const validateRuntimeIdentities = (manifest, decisionManifest) => {
  const identities = manifest.identities;
  const byId = new Map(identities.map((identity) => [identity.id, identity]));
  const suffixes = new Map([
    ["identity-authenticated-app", "app"],
    ["identity-restricted-read", "rls_read"],
    ["identity-pre-auth-app", "preauth"],
    ["identity-worker", "worker"],
    ["identity-scheduled-job", "scheduled"],
    ["identity-migration", "migration"],
    ["identity-table-owner", "owner"],
    ["identity-auth-function-owner", "auth_owner"],
    ["identity-staging-operator-admin", "operator"],
  ]);
  assert.equal(identities.length, 10, "exactly ten logical runtime identities are required");
  for (const [id, suffix] of suffixes) {
    const identity = byId.get(id);
    assert(identity, `${id} is missing`);
    assert.equal(identity.environmentRoleNames?.development, `mscqr_dev_${suffix}`, `${id} development role name is invalid`);
    assert.equal(identity.environmentRoleNames?.staging, `mscqr_staging_${suffix}`, `${id} staging role name is invalid`);
    assert.equal(identity.environmentRoleNames?.production, `mscqr_prod_${suffix}`, `${id} production role name is invalid`);
  }
  for (const identity of identities) {
    assert.equal(identity.superuser, false, `${identity.id} requests superuser`);
    assert.equal(identity.mayUseBypassRls, false, `${identity.id} requests BYPASSRLS`);
    assert.equal(identity.maySetRole, false, `${identity.id} may SET ROLE`);
    assert(identity.credentialSource?.trim(), `${identity.id} credential source is missing`);
    assert(identity.rotationExpectation?.trim(), `${identity.id} rotation expectation is missing`);
    assert(identity.securityDefinerExecution?.trim(), `${identity.id} SECURITY DEFINER rule is missing`);
    assert(identity.environmentRoleNames && ["development", "staging", "production"].every((environment) => identity.environmentRoleNames[environment]?.trim()), `${identity.id} environment role-name patterns are incomplete`);
    if (identity.loginExpectation !== "NOLOGIN") assert.equal(identity.mayOwnProtectedTables, false, `${identity.id} runtime identity may own protected tables`);
  }
  for (const id of ["identity-table-owner", "identity-auth-function-owner"]) assert.equal(byId.get(id).loginExpectation, "NOLOGIN", `${id} owner role must be NOLOGIN`);
  assert.equal(byId.get("identity-table-owner").mayOwnProtectedTables, true, "table owner must own protected tables");
  assert.equal(byId.get("identity-auth-function-owner").mayOwnProtectedTables, false, "auth_owner must not own application tables");

  const credentialIds = ["identity-authenticated-app", "identity-pre-auth-app", "identity-worker", "identity-migration"];
  assert.equal(new Set(credentialIds.map((id) => byId.get(id).credentialSource)).size, credentialIds.length, "app, pre-auth, worker, and migration must not share credential sources");
  assert.notEqual(byId.get("identity-worker").credentialSource, byId.get("identity-scheduled-job").credentialSource, "worker and scheduled credentials must remain distinct");

  const preauth = byId.get("identity-pre-auth-app");
  assert.equal(preauth.tablePrivilegeMode, "none", "pre-auth must have no direct table privileges");
  assert.deepEqual([...preauth.allowedCommands].sort(), ["CONNECT", "EXECUTE", "USAGE"], "pre-auth may only CONNECT, use app_auth, and execute exact functions");
  assert.deepEqual(preauth.allowedSchemas, ["app_auth"], "pre-auth may not receive unrestricted public schema access");
  const restrictedRead = byId.get("identity-restricted-read");
  assert(!restrictedRead.allowedCommands.some((command) => ["INSERT", "UPDATE", "DELETE", "UPSERT", "CREATE", "ALTER", "DROP"].includes(command)), "restricted read has write or DDL privileges");

  const app = byId.get("identity-authenticated-app");
  assert(!app.allowedSchemas.includes("app_auth"), "authenticated app must not receive unrestricted app_auth access");
  assert.match(app.securityDefinerExecution, /authenticated helper signatures only/i, "authenticated app helper execution is too broad");

  const breakGlass = byId.get("identity-production-break-glass");
  assert(breakGlass, "production break-glass identity is missing");
  assert.equal(breakGlass.environmentRoleNames.development, "not-applicable-production-only");
  assert.equal(breakGlass.environmentRoleNames.staging, "not-applicable-production-only");
  assert.match(breakGlass.environmentRoleNames.production, /^mscqr_prod_breakglass_<incident>_<nonce>$/, "production break-glass must use an ephemeral role-name pattern");
  assert.equal(breakGlass.loginExpectation, "EPHEMERAL_LOGIN", "production break-glass must not be a standing LOGIN role");
  assert.equal(breakGlass.standingCredential, false, "production break-glass must not have a standing credential");
  assert.match(breakGlass.credentialSource, /ephemeral.*broker/i, "production break-glass must be broker-issued and ephemeral");
  for (const requirement of ["dual approval", "strong MFA", "incident or ticket", "explicit expiry", "command allowlist", "immutable audit transcript", "automatic revocation"]) assert(breakGlass.approvalRequirements.includes(requirement), `production break-glass lacks ${requirement}`);

  const decision = decisionManifest.decisions.find((item) => item.id === "decision-runtime-role-split");
  assert.equal(decision?.status, "resolved", "decision-runtime-role-split may be resolved only after the complete role model validates");
};
export const sharedApplyIsBlocked = () => {
  const source = fs.readFileSync(path.join(repoRoot, blockedApplyPath), "utf8");
  return source.indexOf("RAISE EXCEPTION 'Shared batch RLS apply blocked") >= 0 && source.indexOf("RAISE EXCEPTION 'Shared batch RLS apply blocked") < source.indexOf("BEGIN;");
};
