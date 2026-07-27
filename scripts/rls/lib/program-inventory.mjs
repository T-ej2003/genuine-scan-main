import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { canonicalWorkflowKey, delegationKey, resolveWorkflowDelegation, validateWorkflowDelegations, WORKFLOW_DELEGATIONS } from "./workflow-delegation-registry.mjs";
import { namedFunctionContractFor, validateNamedSqlFunctionContracts } from "./named-sql-function-contracts.mjs";
import {
  applyApplicationPathCertificationEvidence,
  BATCH_OPERATIONAL_READ_WORKFLOW_IDS,
  DASHBOARD_SNAPSHOT_WORKFLOW_IDS,
  RISK_ANALYTICS_WORKFLOW_ID,
} from "./application-path-certifications.mjs";

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
export const preAuthFunctionsPath = path.join(programDir, "pre-auth-functions.json");
export const preAuthBoundaryReviewPath = path.join(programDir, "PRE_AUTH_BOUNDARY_REVIEW.md");
export const workerBoundariesPath = path.join(programDir, "worker-boundaries.json");
export const workerIdentityReviewPath = path.join(programDir, "WORKER_IDENTITY_REVIEW.md");
export const objectOwnershipChainPath = path.join(programDir, "object-ownership-chain.json");
export const objectOwnershipReviewPath = path.join(programDir, "OBJECT_OWNERSHIP_REVIEW.md");
export const operatorBoundariesPath = path.join(programDir, "operator-boundaries.json");
export const operatorAdministrationReviewPath = path.join(programDir, "OPERATOR_ADMINISTRATION_REVIEW.md");
export const systemBoundariesPath = path.join(programDir, "system-boundaries.json");
export const manufacturerBootstrapBoundaryPath = path.join(programDir, "manufacturer-bootstrap-boundary.json");
export const manufacturerBootstrapReviewPath = path.join(programDir, "MANUFACTURER_BOOTSTRAP_REVIEW.md");
export const platformReadScopeBoundaryPath = path.join(programDir, "platform-read-scope-boundary.json");
export const platformReadScopeReviewPath = path.join(programDir, "PLATFORM_READ_SCOPE_REVIEW.md");
export const policyAlertActorCeilingPath = path.join(programDir, "policy-alert-actor-ceiling.json");
export const policyAlertActorCeilingReviewPath = path.join(programDir, "POLICY_ALERT_ACTOR_CEILING_REVIEW.md");
export const publicReadContractPath = path.join(programDir, "public-read-contract.json");
export const publicReadContractReviewPath = path.join(programDir, "PUBLIC_READ_CONTRACT_REVIEW.md");
export const blockedApplyPath = "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql";

export const commands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT", "COUNT", "RAW_SQL"]);
export const surfaces = new Set(["http", "worker", "scheduled", "startup", "cli", "internal"]);
export const boundaries = new Set(["authenticated-context", "pre-auth-security-function", "public-proof-boundary", "tenant-admin", "platform-admin", "actor-owned", "restricted-worker", "append-only", "migration-owner", "operator-break-glass", "unresolved"]);
export const categories = new Set(["tenant-root", "tenant-owned", "actor-owned", "parent-inherited", "security-sensitive", "append-only-audit", "platform-reference", "operational-system", "migration-only", "intentionally-non-rls"]);
export const actorClasses = new Set(["anonymous", "authenticated-user", "manufacturer", "operator", "checker", "licensee-admin", "platform-admin", "restricted-read", "pre-auth-runtime", "worker", "scheduled-job", "migration", "operator-admin", "break-glass"]);
export const assuranceLevels = new Set(["none", "password-verified", "mfa-bootstrap", "mfa-verified", "step-up-verified", "system-verified", "operator-approved", "dual-approved-break-glass"]);
export const policyCommands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE"]);

const CATEGORY_MODELS = Object.freeze({
  "tenant-root": ["Organization"],
  "tenant-owned": ["Licensee", "ManufacturerLicenseeLink", "QRRange", "Batch", "InventoryStatusRollup", "QRCode", "QrAllocationRequest", "PolicyAlert", "TenantFeatureFlag", "EvidenceRetentionPolicy"],
  "actor-owned": ["PrinterRegistration", "Notification"],
  "parent-inherited": ["PrintJob", "PrintSession", "PrinterAgentSession", "PrintJobChunk", "PrintItem", "PrinterProfile", "PrinterProfileSnapshot", "PrintReissueRequest", "PrinterAttestation", "Ownership", "OwnershipTransfer", "ReplacementChain", "IncidentCommunication", "IncidentHandoff", "SupportTicket", "SupportTicketMessage"],
  "security-sensitive": ["User", "Printer", "VerificationDecision", "VerificationEvidenceSnapshot", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerAuthSession", "CustomerTrustIntake", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "ScheduledJobCredential", "AdminMfaCredential", "AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal", "SensitiveActionApproval", "SecurityPolicy", "PolicyRule", "Incident", "RequestAccess", "SupportIssueReport"],
  "append-only-audit": ["PrintItemEvent", "PrintAuditEvent", "QrScanLog", "AuditLog", "AllocationEvent", "TraceEvent", "IncidentEvent", "IncidentEvidence", "ForensicEventChain", "RouteTransitionMetric"],
  "platform-reference": [],
  "operational-system": ["ScanMetricsHourlyRollup", "AuditLogOutbox", "SystemCheckpoint", "SecurityEventOutbox", "CompliancePackJob", "EvidenceRetentionJob", "IncidentEvidenceFingerprint", "ActionIdempotencyKey", "DegradationEvent"],
  "migration-only": ["PrintRenderToken", "BatchPrintPackToken"],
  "intentionally-non-rls": [],
});
const CATEGORY_BY_MODEL = new Map(Object.entries(CATEGORY_MODELS).flatMap(([category, models]) => models.map((model) => [model, category])));

const REVIEW_GROUP_MODELS = Object.freeze({
  A: ["User", "PrintRenderToken", "BatchPrintPackToken", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerAuthSession", "CustomerTrustIntake", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "ScheduledJobCredential", "AdminMfaCredential", "AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal", "SensitiveActionApproval"],
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
export const workflowIdFor = (workflow) => `workflow-${slug(`${workflow.executionSurface}:${workflow.sourceFile}:${workflow.function}`)}`;
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
    for (const match of source.matchAll(/\b(?:app|router|[A-Za-z_$][\w$]*Router)\.(get|post|put|patch|delete|use)\s*\(\s*(["'`])([^"'`]+)\2/g)) {
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
const rawTableNamesFor = (sql) => [...sql.matchAll(
  /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|JOIN)\s+(?:ONLY\s+)?(?:(?:"(?:[^"]|"")*"|[a-z_][\w$]*)\s*\.\s*)?(?:"((?:[^"]|"")*)"|([a-z_][\w$]*))/gi
)].map((match) => (match[1] || match[2]).replaceAll('""', '"').toLowerCase());
const BATCH_OPERATIONAL_AUTH_ACCESSES = [
  ["AuditLog", "INSERT"],
  ["AuditLog", "SELECT"],
  ["Batch", "SELECT"],
  ["Licensee", "SELECT"],
  ["ManufacturerLicenseeLink", "SELECT"],
  ["Organization", "SELECT"],
  ["User", "SELECT"],
];
const DATABASE_FUNCTION_ACCESSES = new Map([
  ["app_rls.dashboard_snapshot_scope", [
    ["AuditLog", "INSERT"],
    ["AuditLog", "SELECT"],
    ["Licensee", "SELECT"],
    ["ManufacturerLicenseeLink", "SELECT"],
    ["Organization", "SELECT"],
    ["User", "SELECT"],
  ]],
  ["app_rls.dashboard_snapshot_data", [
    ["AuditLog", "INSERT"],
    ["AuditLog", "SELECT"],
    ["Batch", "SELECT"],
    ["InventoryStatusRollup", "SELECT"],
    ["Licensee", "SELECT"],
    ["ManufacturerLicenseeLink", "SELECT"],
    ["Organization", "SELECT"],
    ["QRCode", "SELECT"],
    ["User", "SELECT"],
  ]],
  ["app_rls.batch_operational_scope", BATCH_OPERATIONAL_AUTH_ACCESSES],
  ["app_rls.batch_operational_rows", [
    ...BATCH_OPERATIONAL_AUTH_ACCESSES,
    ["QRCode", "SELECT"],
  ]],
  ["app_rls.batch_operational_total", BATCH_OPERATIONAL_AUTH_ACCESSES],
  ["app_rls.batch_inventory_rollups", [...BATCH_OPERATIONAL_AUTH_ACCESSES, ["InventoryStatusRollup", "SELECT"]]],
  ["app_rls.batch_unassigned_ranges", [...BATCH_OPERATIONAL_AUTH_ACCESSES, ["QRCode", "SELECT"]]],
  ["app_rls.batch_status_fallback", [...BATCH_OPERATIONAL_AUTH_ACCESSES, ["QRCode", "SELECT"]]],
  ["app_rls.batch_reservable_qr_summaries", [
    ...BATCH_OPERATIONAL_AUTH_ACCESSES,
    ["PrintItem", "SELECT"],
    ["PrintJob", "SELECT"],
    ["PrintSession", "SELECT"],
    ["QRCode", "SELECT"],
  ]],
  ["app_rls.c03_get_incident_evidence_file_by_storage_key", [["IncidentEvidence", "SELECT"]]],
  ["app_rls.c03_list_ir_alerts", [["PolicyAlert", "SELECT"]]],
  ["app_rls.c03_link_ir_alert_incident", [["PolicyAlert", "SELECT"], ["PolicyAlert", "UPDATE"]]],
  ["app_rls.c02_respond_fraud_report", [
    ["User", "SELECT"], ["AuditLog", "SELECT"], ["AuditLog", "INSERT"], ["Licensee", "SELECT"], ["Organization", "SELECT"], ["SecurityEventOutbox", "INSERT"],
  ]],
  ["app_rls.c03_create_public_incident_report", [["Incident", "INSERT"]]],
  ["app_auth.lookup_password_user", [["User", "SELECT"]]],
  ["app_auth.record_password_failure", [["User", "UPDATE"]]],
  ["app_auth.request_password_reset", [["User", "SELECT"], ["PasswordReset", "INSERT"], ["AuditLogOutbox", "INSERT"]]],
  ["app_auth.consume_password_reset_token", [["PasswordReset", "SELECT"], ["PasswordReset", "UPDATE"], ["User", "SELECT"], ["User", "UPDATE"], ["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["AuditLogOutbox", "INSERT"]]],
  ["app_auth.consume_email_verification_token", [["EmailVerificationToken", "SELECT"], ["EmailVerificationToken", "UPDATE"], ["User", "SELECT"], ["User", "UPDATE"], ["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["AuditLogOutbox", "INSERT"]]],
  ["app_auth.lookup_invitation_token", [["Invite", "SELECT"], ["User", "SELECT"], ["Licensee", "SELECT"], ["Organization", "SELECT"]]],
  ["app_auth.consume_invitation_token", [["Invite", "SELECT"], ["Invite", "UPDATE"], ["User", "SELECT"], ["User", "UPDATE"], ["Licensee", "SELECT"], ["Organization", "SELECT"], ["AuditLogOutbox", "INSERT"]]],
  ...validateNamedSqlFunctionContracts().map((contract) => [
    `${contract.schema}.${contract.name}`,
    contract.tableCommands,
  ]),
]);
const WORKFLOW_SURFACE_OVERRIDES = new Map([
  ["backend/src/services/attentionQueueService.ts:getAttentionQueueSnapshotUncached", "http"],
  ["backend/src/services/auditLogOutboxService.ts:queueAuditLogOutbox", "internal"],
  ["backend/src/services/siemOutboxService.ts:queueSecurityEvent", "internal"],
  ["backend/src/services/auditLogOutboxService.ts:flushAuditLogOutbox", "worker"],
  ["backend/src/services/siemOutboxService.ts:flushSecurityEventOutbox", "worker"],
]);
// Stable semantic locators for the trace read migration. Access IDs remain tied to
// function/model/operation evidence instead of changing when context code shifts lines.
const ACCESS_ID_OVERRIDES = new Map([
  ["backend/src/controllers/tracePolicyController.ts:updatePolicyConfigController:SecurityPolicy:upsert", "access-cc65fa8e36dcd281"],
  ["backend/src/controllers/tracePolicyController.ts:getPolicyAlertsController:PolicyAlert:findMany", "access-cda286a36221c918"],
  ["backend/src/controllers/tracePolicyController.ts:getPolicyAlertsController:PolicyAlert:count", "access-9aba912d4d4e84ac"],
  ["backend/src/controllers/tracePolicyController.ts:acknowledgePolicyAlertController:PolicyAlert:findFirst", "access-77f8da454fc3882d"],
  ["backend/src/controllers/tracePolicyController.ts:acknowledgePolicyAlertController:PolicyAlert:update", "access-3600d8039296e7ac"],
  ["backend/src/controllers/tracePolicyController.ts:exportBatchAuditPackageController:Batch:findFirst", "access-53fbc3b78235ea52"],
  ["backend/src/services/traceEventService.ts:createTraceEvent:TraceEvent:create", "access-3c497ff2225a1169"],
  ["backend/src/services/traceEventService.ts:createTraceEventFromAuditLog:TraceEvent:findFirst", "access-3dbdad593f660835"],
  ["backend/src/services/traceEventService.ts:backfillTraceEventsFromAuditLogs:AuditLog:findMany", "access-dc407597d0c3fad8"],
  ["backend/src/services/traceEventService.ts:getTraceTimeline:TraceEvent:findMany", "access-85a7267ca4607825"],
  ["backend/src/services/traceEventService.ts:getTraceTimeline:TraceEvent:count", "access-d82b039104408003"],
]);
const surfaceFor = (file, fn) => {
  const value = `${rel(file)}:${fn}`;
  if (WORKFLOW_SURFACE_OVERRIDES.has(value)) return WORKFLOW_SURFACE_OVERRIDES.get(value);
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
  const ts = require("typescript");
  const models = parseSchema();
  const delegates = new Map(models.map((model) => [model.name[0].toLowerCase() + model.name.slice(1), model]));
  const modelsByName = new Map(models.map((model) => [model.name, model]));
  const physical = new Map(models.map((model) => [model.physicalTable.toLowerCase(), model]));
  const { reachable, all, roots } = reachableSourceFiles();
  const active = [...new Set([...reachable, ...scriptEntrypoints()])].sort();
  const accesses = [];
  const scanFile = (file, production) => {
    const source = fs.readFileSync(file, "utf8");
    const ast = ts.createSourceFile(rel(file), source, ts.ScriptTarget.Latest, true);
    const globalPrismaNames = new Set(ast.statements
      .filter((statement) => ts.isImportDeclaration(statement)
        && /(?:^|\/)config\/database$/.test(String(statement.moduleSpecifier.text || ""))
        && statement.importClause?.name)
      .map((statement) => statement.importClause.name.text));
    const recorded = new Set();
    const record = (node, model, method, command, evidence, clientKind = "unknown") => {
      const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
      const fn = functionName(ts, node);
      const surface = surfaceFor(file, fn);
      const locator = `${rel(file)}:${line}:${model.name}:${method}:${command}`;
      if (recorded.has(locator)) return;
      recorded.add(locator);
      const semanticLocator = `${rel(file)}:${fn}:${model.name}:${method}`;
      const semanticFunctionAccess = method.startsWith("$function:");
      accesses.push({ id: ACCESS_ID_OVERRIDES.get(semanticLocator) || hashId("access", semanticFunctionAccess ? `${semanticLocator}:${command}` : locator), sourceFile: rel(file), line, function: fn, tableId: `table-${slug(model.physicalTable)}`, prismaModel: model.name, command, method, clientKind, executionSurface: surface, production, registrationEvidence: roots.has(file) ? "registered-entrypoint" : reachable.has(file) ? "reachable-from-registered-entrypoint" : "unregistered", evidence: evidence.replace(/\s+/g, " ").slice(0, 350) });
    };
    const recordDatabaseFunctionAccesses = (node, raw, clientKind) => {
      for (const [functionName, entries] of DATABASE_FUNCTION_ACCESSES) {
        if (!new RegExp(`\\b${functionName.replaceAll(".", "\\.")}\\s*\\(`, "i").test(raw)) continue;
        for (const [modelName, command] of entries) {
          const model = modelsByName.get(modelName);
          assert(model, `${functionName} references unknown Prisma model ${modelName}`);
          record(node, model, `$function:${functionName}`, command, raw, clientKind);
        }
      }
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
    const resolveVariableAlias = (name, position) => variableAliases.filter((alias) => alias.name === name && alias.start < position && alias.scopeStart <= position && alias.scopeEnd >= position).sort((a, b) => b.start - a.start)[0] || null;
    const resolveVariable = (name, position) => resolveVariableAlias(name, position)?.model || null;
    const rootIdentifier = (expression) => {
      if (ts.isIdentifier(expression)) return expression.text;
      if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression) || ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isNonNullExpression(expression)) return rootIdentifier(expression.expression);
      return null;
    };
    const clientKindFor = (expression, node) => {
      if (ts.isIdentifier(expression)) {
        const alias = resolveVariableAlias(expression.text, node.getStart(ast));
        if (alias) return alias.clientKind;
      }
      const root = rootIdentifier(expression);
      if (globalPrismaNames.has(root)) return "global-prisma";
      let genericTransactionClient = false;
      for (let current = node; current; current = current.parent) {
        if (!ts.isFunctionLike(current)) continue;
        const parameter = current.parameters?.find((candidate) => ts.isIdentifier(candidate.name) && candidate.name.text === root);
        const type = parameter?.type?.getText(ast) || "";
        if (/\bCanonicalTransactionClient\b/.test(type)) return "canonical-transaction-client";
        if (/\bTransactionClient\b/.test(type)) genericTransactionClient = true;
        if (parameter && ts.isCallExpression(current.parent)
          && current.parent.arguments[2] === current
          && ts.isIdentifier(current.parent.expression)
          && current.parent.expression.text === "withCanonicalDbContext") return "canonical-transaction-client";
      }
      if (genericTransactionClient) return "transaction-client";
      return "unknown";
    };
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
      variableAliases.push({ name: declaration.name.text, model, clientKind: clientKindFor(declaration.initializer, declaration), start: declaration.getStart(ast), scopeStart: scope.getStart(ast), scopeEnd: scope.getEnd() });
    }
    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const target = node.expression.expression;
        if (methodNames.has(method) && ts.isPropertyAccessExpression(target) && delegates.has(target.name.text)) record(node, delegates.get(target.name.text), method, operationFor(method), node.getText(ast), clientKindFor(target, node));
        else if (methodNames.has(method)) {
          const aliasModel = modelForExpression(target, node.getStart(ast));
          if (aliasModel) record(node, aliasModel, method, operationFor(method), node.getText(ast), clientKindFor(target, node));
        }
        if (rawMethods.has(method)) {
          const raw = node.getText(ast);
          const clientKind = clientKindFor(node.expression.expression, node);
          recordDatabaseFunctionAccesses(node, raw, clientKind);
          for (const name of new Set(rawTableNamesFor(raw))) {
            const model = physical.get(name);
            if (model) for (const command of rawCommandsFor(method, raw)) record(node, model, method, command, raw, clientKind);
          }
        }
      }
      if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) && rawMethods.has(node.tag.name.text)) {
        const raw = node.getText(ast);
        const clientKind = clientKindFor(node.tag.expression, node);
        recordDatabaseFunctionAccesses(node, raw, clientKind);
        for (const name of new Set(rawTableNamesFor(raw))) {
          const model = physical.get(name);
          if (model) for (const command of rawCommandsFor(node.tag.name.text, raw)) record(node, model, node.tag.name.text, command, raw, clientKind);
        }
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

export const missingWorkflowDiagnostic = ({ scope, workflowId, classification = {}, workflowManifest, scan = scanProductionAccess() }) => {
  const delegated = WORKFLOW_DELEGATIONS.filter((entry) => workflowIdFor(entry.canonical) === workflowId);
  const tableIds = new Set((classification.tableProjections || classification.tableCommandProjections || []).map((item) => item.tableId));
  const candidateWorkflows = (workflowManifest.workflows || [])
    .filter((workflow) => workflow.id.includes(workflowId.split("-").slice(-3).join("-")))
    .map((workflow) => workflow.id).slice(0, 3);
  const delegatedKeys = new Set(delegated.map((entry) => delegationKey(entry.delegated)));
  const candidateAccesses = scan.accesses.filter((access) => tableIds.has(access.tableId) || delegatedKeys.has(delegationKey(access)))
    .map((access) => `${access.sourceFile}:${access.function} (${access.method})`).filter((value, index, values) => values.indexOf(value) === index).slice(0, 3);
  const namedFunctionCandidates = scan.accesses.filter((access) => tableIds.has(access.tableId) && access.method.startsWith("$function:"))
    .map((access) => access.method.slice("$function:".length)).filter((value, index, values) => values.indexOf(value) === index).slice(0, 3);
  const sources = delegated.map((entry) => `${entry.canonical.sourceFile}:${entry.canonical.function}`);
  const discovered = delegatedKeys.size > 0 && scan.accesses.some((access) => delegatedKeys.has(delegationKey(access)));
  return [
    `${scope} references missing workflow ${workflowId}.`,
    sources.length ? `Canonical source: ${sources.join(", ")}; delegation source discovered: ${discovered ? "yes" : "no"}.` : "No delegation registry entry matches this workflow ID.",
    candidateWorkflows.length ? `Similar workflows: ${candidateWorkflows.join(", ")}.` : "Similar workflows: none.",
    candidateAccesses.length ? `Related accesses: ${candidateAccesses.join("; ")}.` : "Related accesses: none.",
    namedFunctionCandidates.length ? `Named function candidates: ${namedFunctionCandidates.join(", ")}.` : "Named function candidates: none.",
    "Action: add or correct the source-level delegation and named-function table mapping; do not edit generated workflow JSON or the authority boundary.",
  ].join("\n");
};

export const validateProtectedTransactionClients = (workflowManifest, scan = scanProductionAccess()) => {
  const accessById = new Map(scan.accesses.map((access) => [access.id, access]));
  const protectedWorkflows = workflowManifest.workflows.filter((workflow) =>
    workflow.contextBoundaryStatus === "implemented" && workflow.sameTransactionGuarantee === true
  );
  let protectedAccesses = 0;
  for (const workflow of protectedWorkflows) {
    assert.equal(workflow.protectedQueryClient, "transaction-client-only", `${workflow.id} lacks the protected repository client contract`);
    assert(workflow.supportingEvidence?.length, `${workflow.id} lacks registered protected access evidence`);
    for (const evidence of workflow.supportingEvidence) {
      const access = accessById.get(evidence.accessId);
      assert(access, `${workflow.id} references missing protected access ${evidence.accessId}`);
      assert(
        access.clientKind === "canonical-transaction-client" || access.method.startsWith("$function:"),
        `${workflow.id} uses ${access.clientKind} at ${access.sourceFile}:${access.line}; protected access must use CanonicalTransactionClient or one exact named function`
      );
      protectedAccesses += 1;
    }
  }
  return { workflows: protectedWorkflows.length, accesses: protectedAccesses };
};

const displayName = (fn) => fn === "module" ? "Module database access" : fn.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/^./, (letter) => letter.toUpperCase());
const identityForWorkflow = (workflow) => ["pre-auth-security-function", "public-proof-boundary"].includes(workflow.authorizationBoundaryType) ? "identity-pre-auth-app"
  : workflow.executionSurface === "worker" ? "identity-worker"
    : workflow.executionSurface === "scheduled" ? "identity-scheduled-job"
      : ["cli", "startup"].includes(workflow.executionSurface) ? "identity-operator"
        : "identity-authenticated-app";
const expandCommands = (commandsToExpand) => [...new Set(commandsToExpand.flatMap((command) => command === "COUNT" ? ["SELECT"] : command === "UPSERT" ? ["INSERT", "UPDATE"] : [command]))].sort();
const commandCondition = (identityId, table) => identityId === "identity-pre-auth-app" ? "EXECUTE only an exact named function signature; no direct table grant"
  : identityId === "identity-auth-function-owner" ? "Exact function-required column privileges only; NOLOGIN owner"
    : identityId === "identity-worker" ? "Durably verified job and tenant scope; queue payload is not authority"
      : identityId === "identity-scheduled-job" ? "Approved schedule and durable tenant/job scope"
        : identityId === "identity-operator" ? "Broker-controlled command allowlist with immutable audit"
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
    "This is the compact human review of the machine-readable classification in `tables.json`. It changes no policy, database owner, role, runtime behavior, or RLS state. All 78 Prisma tables remain policy-generation candidates owned logically by `identity-table-owner`; implementation and disposable PostgreSQL proof are separate work.",
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

const ROUTE_GUARDS = ["authenticate", "requirePlatformAdmin", "requireLicenseeAdmin", "requireAnyAdmin", "requireManufacturer", "requireRecentAdminMfa", "requireRecentSensitiveAuth", "requireCustomerVerifyAuth", "optionalCustomerVerifyAuth", "enforceTenantIsolation", "requireCsrf"];
let routeEvidenceByHandler;
const routeEvidenceFor = (functionName) => {
  if (!routeEvidenceByHandler) {
    const ts = require("typescript");
    routeEvidenceByHandler = new Map();
    const files = [...walk(path.join(repoRoot, "backend/src/routes")), path.join(repoRoot, "backend/src/app.ts")];
    for (const file of files) {
      const source = fs.readFileSync(file, "utf8");
      const ast = ts.createSourceFile(rel(file), source, ts.ScriptTarget.Latest, true);
      const visit = (node) => {
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const method = node.expression.name.text.toUpperCase();
          const route = node.arguments[0];
          if (["GET", "POST", "PUT", "PATCH", "DELETE", "USE"].includes(method) && route && ts.isStringLiteralLike(route)) {
            const identifiers = new Set();
            const collect = (candidate) => {
              if (ts.isIdentifier(candidate)) identifiers.add(candidate.text);
              ts.forEachChild(candidate, collect);
            };
            node.arguments.slice(1).forEach(collect);
            const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
            const registration = {
              source: `${rel(file)}:${line}`,
              method,
              route: route.text,
              guards: ROUTE_GUARDS.filter((guard) => identifiers.has(guard)),
            };
            for (const handler of identifiers) routeEvidenceByHandler.set(handler, [...(routeEvidenceByHandler.get(handler) || []), registration]);
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(ast);
    }
  }
  const registrations = routeEvidenceByHandler.get(functionName) || [];
  if (!registrations.length) return null;
  return {
    source: registrations[0].source,
    route: registrations[0].route,
    guards: [...new Set(registrations.flatMap((registration) => registration.guards))],
    registrations,
  };
};

const TRACE_TIMELINE_WORKFLOW_ID = "workflow-internal-backend-src-services-trace-event-service-ts-get-trace-timeline";
const RISK_ANALYTICS_FUNCTION_SIGNATURE = "app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone)";
const DASHBOARD_SNAPSHOT_WORKFLOW_ID_SET = new Set(DASHBOARD_SNAPSHOT_WORKFLOW_IDS);
const BATCH_OPERATIONAL_READ_WORKFLOW_ID_SET = new Set(BATCH_OPERATIONAL_READ_WORKFLOW_IDS);
const DASHBOARD_SNAPSHOT_COLUMNS = {
  "table-audit-log": {
    INSERT: ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"],
    SELECT: ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"],
  },
  "table-batch": { SELECT: ["id", "licenseeId", "manufacturerId"] },
  "table-inventory-status-rollup": { SELECT: ["active", "activated", "allocated", "blocked", "dormant", "licenseeId", "manufacturerId", "printed", "redeemed", "scanned", "totalCodes"] },
  "table-licensee": { SELECT: ["id", "isActive", "orgId", "suspendedAt"] },
  "table-manufacturer-licensee-link": { SELECT: ["isPrimary", "licenseeId", "manufacturerId", "updatedAt"] },
  "table-organization": { SELECT: ["id", "isActive"] },
  "table-qrcode": { SELECT: ["batchId", "licenseeId", "status"] },
  "table-user": { SELECT: ["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "orgId", "role", "status"] },
};
const BATCH_OPERATIONAL_SCOPE_COLUMNS = {
  "table-audit-log": {
    INSERT: ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"],
    SELECT: ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"],
  },
  "table-batch": { SELECT: ["id", "licenseeId", "manufacturerId", "parentBatchId", "rootBatchId"] },
  "table-licensee": { SELECT: ["id", "isActive", "orgId", "suspendedAt"] },
  "table-manufacturer-licensee-link": { SELECT: ["isPrimary", "licenseeId", "manufacturerId", "updatedAt"] },
  "table-organization": { SELECT: ["id", "isActive"] },
  "table-user": { SELECT: ["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "orgId", "role", "status"] },
};
const BATCH_OPERATIONAL_SCOPE_AND_ROWS_COLUMNS = {
  ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
  "table-batch": { SELECT: ["createdAt", "endCode", "id", "lifecycleState", "licenseeId", "manufacturerId", "metadata", "name", "parentBatchId", "printPackDownloadedAt", "printPackDownloadedByUserId", "printedAt", "releasedAt", "releasedByUserId", "rootBatchId", "sampleScanPolicy", "startCode", "suspendedAt", "suspendedReason", "totalCodes", "updatedAt"] },
  "table-licensee": { SELECT: ["id", "isActive", "name", "orgId", "prefix", "suspendedAt"] },
  "table-qrcode": { SELECT: ["batchId"] },
  "table-user": { SELECT: ["deletedAt", "disabledAt", "email", "id", "isActive", "licenseeId", "name", "orgId", "role", "status"] },
};
const BATCH_OPERATIONAL_READ_COLUMNS_BY_WORKFLOW = new Map([
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches", BATCH_OPERATIONAL_SCOPE_AND_ROWS_COLUMNS],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map", BATCH_OPERATIONAL_SCOPE_AND_ROWS_COLUMNS],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-total", {
    ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
  }],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups", {
    ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
    "table-inventory-status-rollup": { SELECT: ["active", "activated", "allocated", "batchId", "blocked", "dormant", "licenseeId", "manufacturerId", "printed", "redeemed", "scanned"] },
  }],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges", {
    ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
    "table-qrcode": { SELECT: ["batchId", "code", "displayCode", "status"] },
  }],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps", {
    ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
    "table-qrcode": { SELECT: ["batchId", "status"] },
  }],
  ["workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries", {
    ...BATCH_OPERATIONAL_SCOPE_COLUMNS,
    "table-print-item": { SELECT: ["agentAckedAt", "confirmationEvidence", "deadLetterReason", "deviceJobRef", "dispatchedAt", "failureReason", "id", "printConfirmedAt", "printSessionId", "qrCodeId", "state"] },
    "table-print-job": { SELECT: ["batchId", "id", "status"] },
    "table-print-session": { SELECT: ["batchId", "id", "printJobId", "status"] },
    "table-qrcode": { SELECT: ["batchId", "code", "displayCode", "id", "licenseeId", "printJobId", "status"] },
  }],
]);
const BATCH_OPERATIONAL_FUNCTION_SIGNATURES_BY_WORKFLOW = new Map([
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps", ["app_rls.batch_status_fallback(text,text,text,text,text,text[])"]],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map", ["app_rls.batch_operational_scope(text,text,text,text)", "app_rls.batch_operational_rows(text,text,text,text,text,integer,integer)"]],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches", ["app_rls.batch_operational_scope(text,text,text,text)", "app_rls.batch_operational_rows(text,text,text,text,text,integer,integer)"]],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups", ["app_rls.batch_inventory_rollups(text,text,text,text,text,text[])"]],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-total", ["app_rls.batch_operational_total(text,text,text,text,text)"]],
  ["workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges", ["app_rls.batch_unassigned_ranges(text,text,text,text,text,text[])"]],
  ["workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries", ["app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text[])"]],
]);

const commandActorsFor = (workflow, table, routeEvidence) => {
  const text = `${workflow.id} ${workflow.canonicalSourceFiles.join(" ")}`.toLowerCase();
  const guards = new Set(routeEvidence?.guards || []);
  if (workflow.id === AUDIT_LOGS_WORKFLOW_ID) return ["manufacturer", "licensee-admin", "platform-admin"];
  if (workflow.id === FRAUD_REPORTS_WORKFLOW_ID) return ["platform-admin"];
  if (workflow.id === TRACE_TIMELINE_WORKFLOW_ID) return ["authenticated-user", "manufacturer", "licensee-admin", "platform-admin"];
  if (workflow.id === RISK_ANALYTICS_WORKFLOW_ID) return ["licensee-admin", "platform-admin"];
  if (DASHBOARD_SNAPSHOT_WORKFLOW_ID_SET.has(workflow.id)) return ["licensee-admin", "manufacturer", "platform-admin"];
  if (BATCH_OPERATIONAL_READ_WORKFLOW_ID_SET.has(workflow.id)) return ["licensee-admin", "manufacturer", "platform-admin"];
  if (workflow.manufacturerBootstrapBoundaryId) return ["manufacturer"];
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

const AUDIT_CSV_EXPORT_WORKFLOW_ID = "workflow-http-backend-src-controllers-audit-controller-ts-export-logs-csv";
const AUDIT_LOGS_WORKFLOW_ID = "workflow-http-backend-src-controllers-audit-controller-ts-get-logs";
const FRAUD_REPORTS_WORKFLOW_ID = "workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports";
const MANUFACTURER_BOOTSTRAP_BOUNDARY_ID = "manufacturer-bootstrap-post-password-actor";
const PLATFORM_READ_SCOPE_BOUNDARY_ID = "platform-read-scope-v1";
const POLICY_ALERT_ACTOR_CEILING_ID = "policy-alert-actor-ceiling-v1";
const PUBLIC_READ_CONTRACT_ID = "public-read-contract-v1";

const runtimeIdentityForCommand = (workflow) => workflow.authorizationBoundaryType === "operator-break-glass" ? "identity-production-break-glass"
  : workflow.authorizationBoundaryType === "pre-auth-security-function" || workflow.authorizationBoundaryType === "public-proof-boundary" ? "identity-pre-auth-app"
    : workflow.executionSurface === "worker" ? "identity-worker"
      : workflow.executionSurface === "scheduled" ? "identity-scheduled-job"
        : workflow.authorizationBoundaryType === "migration-owner" ? "identity-migration"
          : ["cli", "startup"].includes(workflow.executionSurface) ? "identity-operator"
            : "identity-authenticated-app";

const assuranceForCommand = (workflow, actors, command, table, routeEvidence) => {
  if (workflow.id === RISK_ANALYTICS_WORKFLOW_ID) return "password-verified";
  if (DASHBOARD_SNAPSHOT_WORKFLOW_ID_SET.has(workflow.id)) return "password-verified";
  if (BATCH_OPERATIONAL_READ_WORKFLOW_ID_SET.has(workflow.id)) return "password-verified";
  if (workflow.platformReadRequiredAssurance) return workflow.platformReadRequiredAssurance;
  const guards = new Set(routeEvidence?.guards || []);
  if (workflow.id === AUDIT_CSV_EXPORT_WORKFLOW_ID) return "password-verified";
  if (workflow.id === AUDIT_LOGS_WORKFLOW_ID) return "mfa-verified";
  if (workflow.id === FRAUD_REPORTS_WORKFLOW_ID) return "mfa-verified";
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
  const auditCsvExport = workflow.id === AUDIT_CSV_EXPORT_WORKFLOW_ID;
  const auditLogsRead = workflow.id === AUDIT_LOGS_WORKFLOW_ID;
  const fraudReportsRead = workflow.id === FRAUD_REPORTS_WORKFLOW_ID;
  const manufacturerBootstrap = workflow.manufacturerBootstrapBoundaryId === MANUFACTURER_BOOTSTRAP_BOUNDARY_ID;
  const platformReadScope = workflow.platformReadScopeBoundaryId === PLATFORM_READ_SCOPE_BOUNDARY_ID;
  const policyAlertActorCeiling = workflow.policyAlertActorCeilingBoundaryId === POLICY_ALERT_ACTOR_CEILING_ID;
  const publicReadContract = workflow.publicReadContractBoundaryId === PUBLIC_READ_CONTRACT_ID;
  const dashboardSnapshot = DASHBOARD_SNAPSHOT_WORKFLOW_ID_SET.has(workflow.id);
  const batchOperationalRead = BATCH_OPERATIONAL_READ_WORKFLOW_ID_SET.has(workflow.id);
  const securityFunction = table.primaryCategory === "security-sensitive" && (command !== "SELECT" || table.sensitiveColumns.length > 0) && !auditCsvExport && !auditLogsRead && !fraudReportsRead && workflow.id !== RISK_ANALYTICS_WORKFLOW_ID;
  const preAuthFunction = actors.includes("pre-auth-runtime");
  const workerBoundary = actors.some((actor) => ["worker", "scheduled-job"].includes(actor));
  const operatorApproval = actors.some((actor) => ["operator-admin", "break-glass"].includes(actor));
  const functionEvidence = workflow.supportingEvidence.filter((evidence) => evidence.method?.startsWith("$function:"));
  const rawEvidence = functionEvidence.length > 0 &&
    workflow.supportingEvidence.every((evidence) => evidence.method?.startsWith("$function:"));
  let allowedColumns = command === "DELETE" ? [] : command === "SELECT"
    ? scalarColumns.filter((column) => !(table.primaryCategory === "security-sensitive" && table.sensitiveColumns.includes(column)))
    : scalarColumns.filter((column) => !protectedColumns.includes(column));
  if (auditCsvExport && table.prismaModel === "User" && command === "SELECT") allowedColumns = ["id", "name"];
  if (auditCsvExport && table.prismaModel === "AuditLog" && command === "SELECT") allowedColumns = ["id", "createdAt", "action", "entityType", "entityId", "userId", "licenseeId"];
  if (auditLogsRead && table.prismaModel === "User" && command === "SELECT") allowedColumns = ["id", "name"];
  if (auditLogsRead && table.prismaModel === "AuditLog" && command === "SELECT") allowedColumns = ["id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details", "createdAt"];
  if (auditLogsRead && table.prismaModel === "AuditLog" && command === "INSERT") allowedColumns = ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"];
  if (fraudReportsRead && table.prismaModel === "AuditLog" && command === "SELECT") allowedColumns = ["id", "createdAt", "userId", "licenseeId", "details", "ipAddress"];
  if (manufacturerBootstrap && table.prismaModel === "ManufacturerLicenseeLink" && command === "SELECT") allowedColumns = ["manufacturerId", "licenseeId", "isPrimary", "createdAt", "updatedAt"];
  if (platformReadScope && command === "SELECT") allowedColumns = workflow.platformReadAllowedColumnsByTable?.[table.id] || [];
  if (policyAlertActorCeiling) allowedColumns = workflow.policyAlertAllowedColumnsByTableAndCommand?.[table.id]?.[command] || [];
  if (publicReadContract && workflow.publicReadProjectionProfile) allowedColumns = workflow.publicReadAllowedColumnsByTableAndCommand?.[table.id]?.[command] || [];
  if (workflow.id === RISK_ANALYTICS_WORKFLOW_ID) allowedColumns = workflow.riskAnalyticsAllowedColumnsByTableAndCommand?.[table.id]?.[command] || [];
  if (dashboardSnapshot) allowedColumns = DASHBOARD_SNAPSHOT_COLUMNS[table.id]?.[command] || [];
  if (batchOperationalRead) allowedColumns = BATCH_OPERATIONAL_READ_COLUMNS_BY_WORKFLOW.get(workflow.id)?.[table.id]?.[command] || [];
  const hardDeleteSemantics = command === "DELETE" ? deleteSemanticsFor(table, workflow) : "not-applicable";
  const approvalClass = actors.includes("break-glass") ? "dual-approved-break-glass"
    : actors.includes("operator-admin") ? "operator-approved"
      : actors.includes("checker") && /release|approve/.test(workflow.id) ? "maker-checker-separation"
        : hardDeleteSemantics === "retention delete" ? "retention-authorization"
          : "none";
  const requiresApproval = approvalClass !== "none";
  const dedicatedPlatformProjection = platformReadScope && ["dedicated-aggregate-projection", "dedicated-directory-projection"].includes(workflow.platformReadExecutionBoundary);
  const requiresNamedFunction = preAuthFunction || securityFunction || rawEvidence || dedicatedPlatformProjection || dashboardSnapshot || batchOperationalRead;
  const boundaryMode = platformReadScope && workflow.platformReadScopeClass === "prohibited-platform-read"
    ? "prohibited"
    : workerBoundary ? "restricted-worker" : operatorApproval ? "operator-approval" : requiresNamedFunction ? "named-function" : "ordinary-rls";
  const minimumAssuranceByActorClass = Object.fromEntries(actors.map((actor) => [
    actor,
    workflow.runtimeRequiredAssuranceByActorClass?.[actor] || workflow.dashboardSnapshotRequiredAssuranceByActorClass?.[actor] || workflow.platformReadRequiredAssuranceByActorClass?.[actor] || (
      actor === "platform-admin" && ["none", "password-verified", "mfa-bootstrap"].includes(assurance) ? "mfa-verified" : assurance
    ),
  ]));
  return {
    id: `command-${slug(table.prismaModel)}-${command.toLowerCase()}-${crypto.createHash("sha256").update(workflow.id).digest("hex").slice(0, 12)}`,
    tableId: table.id,
    command,
    actorClasses: actors,
    runtimeIdentities: [identityId],
    minimumAssurance: assurance,
    minimumAssuranceByActorClass,
    scopeRule: publicReadContract
      ? workflow.tenantScopeRule
      : policyAlertActorCeiling
      ? workflow.tenantScopeRule
      : platformReadScope
      ? workflow.tenantScopeRule
      : auditLogsRead
      ? "Tenant administrators require their canonical licensee; manufacturers require their own actor plus an approved linked licensee; platform administrators require fresh MFA, one explicit licensee and purpose. Every filter only narrows that boundary."
      : fraudReportsRead
      ? "Validated platform administrators require fresh MFA, one explicit canonical licensee scope, a recorded purpose and request attribution. Query filters only narrow that licensee scope."
      : auditCsvExport
      ? "Tenant actors require matching canonical licensee or manufacturer actor context; platform administrators require fresh MFA, one explicit licensee scope and a recorded purpose. Filters only narrow scope."
      : manufacturerBootstrap
      ? "Verified User.id must equal app.user_id and app.manufacturer_id before the read; ManufacturerLicenseeLink.manufacturerId must equal that actor. requestedLicenseeId may only narrow the freshly verified membership set, blank scope never means all, and active Licensee/Organization checks are mandatory."
      : workflow.id === TRACE_TIMELINE_WORKFLOW_ID
      ? "Authenticated tenant actors require their canonical licensee; manufacturers additionally require their own actor ID and one linked licensee; platform administrators require fresh MFA, one explicit licensee and purpose. Filters only narrow scope."
      : workflow.id === RISK_ANALYTICS_WORKFLOW_ID
      ? "An ACTIVE database-hydrated LICENSEE_ADMIN or ORG_ADMIN uses its nonblank canonical licensee and organization. A database-hydrated platform administrator requires fresh MFA and one active database-validated licensee and organization selector. Fixed tenant-risk-analytics purpose, request attribution, bounded candidates/dimensions and identical tenant predicates are mandatory; blank or foreign scope is denied."
      : dashboardSnapshot
      ? "The exact dashboard function revalidates the ACTIVE database actor, fixed dashboard-snapshot-read purpose and actor-specific assurance. Tenant administrators use their canonical licensee and organization; manufacturers use only their current active linked-licensee set or one linked selector; platform administrators use fresh MFA and either the reviewed global aggregate or one active selected licensee."
      : batchOperationalRead
      ? "The exact batch operational-read functions revalidate the ACTIVE database actor, fixed batch-operational-read purpose and actor-specific assurance. Tenant administrators use their canonical active licensee and organization; manufacturers use only current active linked batches assigned to their actor and may narrow to one linked licensee; platform administrators require fresh MFA and one explicit active licensee selector."
      : scopeRuleFor(table, actors),
    allowedColumns,
    protectedColumns,
    allowedLifecycleStates: lifecycle.allowed,
    forbiddenLifecycleStates: lifecycle.forbidden,
    lifecycleColumns: lifecycle.columns,
    withCheckRule: command === "SELECT" || command === "DELETE"
      ? "not-applicable"
      : auditCsvExport || auditLogsRead || fraudReportsRead
        ? "New row preserves trusted actor, tenant, request and purpose context. Ownership, actor, approval, audit-attribution, identity, token/hash, and lifecycle fields come only from trusted server context or the named boundary."
        : `New row preserves ${scopeRuleFor(table, actors)} Ownership, actor, approval, audit-attribution, identity, token/hash, and lifecycle fields come only from trusted server context or the named boundary.`,
    requiresNamedFunction,
    namedFunctionClass: requiresNamedFunction ? (dashboardSnapshot ? "exact-dashboard-snapshot-function" : batchOperationalRead ? "exact-batch-operational-read-function" : dedicatedPlatformProjection ? `exact-${workflow.platformReadExecutionBoundary}` : preAuthFunction ? "narrow-pre-auth-security-definer" : rawEvidence ? "exact-reviewed-query-function" : "authenticated-security-repository-function") : "none",
    ...(workflow.id === RISK_ANALYTICS_WORKFLOW_ID
      ? { namedFunctionSignatures: [RISK_ANALYTICS_FUNCTION_SIGNATURE] }
      : batchOperationalRead
        ? { namedFunctionSignatures: BATCH_OPERATIONAL_FUNCTION_SIGNATURES_BY_WORKFLOW.get(workflow.id) }
        : {}),
    requiresRestrictedWorkerBoundary: workerBoundary,
    requiresAuditEvent: publicReadContract || manufacturerBootstrap || policyAlertActorCeiling || workflow.approvedReadAttribution === true || command !== "SELECT" || actors.some((actor) => ["platform-admin", "operator", "operator-admin", "break-glass"].includes(actor)),
    requiresApproval,
    approvalClass,
    authorizationBoundary: boundaryMode,
    hardDeleteSemantics,
    dependentDataBehavior: command === "DELETE" ? (table.authorizationParentTable ? "Only the schema-defined parent cascade and reviewed retention lifecycle may affect dependent rows." : "Dependent rows must be enumerated and certified before execution; implicit cross-tenant cascades are denied.") : "not-applicable",
    retentionLegalConsequences: command === "DELETE" ? "Legal hold, retention policy, tenant scope, and immutable audit evidence must be checked before deletion." : "not-applicable",
    supportingWorkflowIds: [workflow.id],
    supportingEvidence: [...workflow.canonicalSourceFiles, ...(routeEvidence ? [`${routeEvidence.source} guards=${routeEvidence.guards.join(",") || "none"}`] : [])],
    allowScenarios: publicReadContract
      ? workflow.expectedAllowedScenarios
      : policyAlertActorCeiling
      ? workflow.expectedAllowedScenarios
      : platformReadScope
      ? workflow.expectedAllowedScenarios
      : manufacturerBootstrap
      ? ["A password-verified manufacturer reads only rows whose manufacturerId equals the database-verified actor; one client value may narrow but never establish the eligible licensee set."]
      : [`${actors.join(" or ")} using ${identityId} at ${assurance} performs ${command} within the recorded scope, column set, lifecycle, and boundary.`],
    denyScenarios: publicReadContract
      ? workflow.expectedDeniedScenarios
      : policyAlertActorCeiling
      ? workflow.expectedDeniedScenarios
      : platformReadScope
      ? workflow.expectedDeniedScenarios
      : manufacturerBootstrap
      ? ["Caller role or tenant claims, blank scope, foreign/revoked/disabled membership, ambiguous primary membership, missing request attribution, secret projection or platform-admin fallback is denied."]
      : ["Anonymous, empty-context, foreign-tenant, wrong-actor, lower-assurance, forbidden-state, protected-column, role-elevation, ownership-transfer, or unapproved execution is denied."],
    ...(manufacturerBootstrap ? { manufacturerBootstrapBoundaryId: MANUFACTURER_BOOTSTRAP_BOUNDARY_ID } : {}),
    ...(platformReadScope ? { platformReadScopeBoundaryId: PLATFORM_READ_SCOPE_BOUNDARY_ID, platformReadScopeClass: workflow.platformReadScopeClass } : {}),
    ...(policyAlertActorCeiling ? { policyAlertActorCeilingBoundaryId: POLICY_ALERT_ACTOR_CEILING_ID, policyAlertClass: workflow.policyAlertClass } : {}),
    ...(publicReadContract ? { publicReadContractBoundaryId: PUBLIC_READ_CONTRACT_ID, publicAccessClass: workflow.publicAccessClass, publicFunctionId: workflow.publicReadFunctionId } : {}),
    confidence: routeEvidence || workerBoundary || preAuthFunction || operatorApproval || manufacturerBootstrap || platformReadScope || policyAlertActorCeiling || publicReadContract || workflow.contextBoundaryStatus === "implemented" ? "high" : "medium",
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
        const actors = workflow.runtimeImplementedActorClasses || workflow.policyAlertActorClasses || workflow.platformReadActorClasses || workflow.publicReadActorClasses || commandActorsFor(workflow, table, routeEvidence);
        const identityId = runtimeIdentityForCommand(workflow);
        const assurance = workflow.policyAlertRequiredAssurance || workflow.publicReadRequiredAssurance || assuranceForCommand(workflow, actors, command, table, routeEvidence);
        const rule = buildCommandRule({ table, workflow, command, actors, identityId, assurance, routeEvidence });
        rules.push(rule);
        workflow.commandRuleIds.push(rule.id);
        workflow.commandActorClasses.push(...actors);
        workflow.requiredAssurance.push(...Object.values(rule.minimumAssuranceByActorClass));
        workflow.runtimeIdentities.push(identityId);
      }
    }
    workflow.commandRuleIds.sort();
    workflow.commandActorClasses = [...new Set(workflow.commandActorClasses)].sort();
    workflow.actorClasses = workflow.commandActorClasses;
    workflow.requiredAssurance = [...new Set(workflow.requiredAssurance)].sort();
    workflow.runtimeIdentities = [...new Set(workflow.runtimeIdentities)].sort();
    workflow.semanticStatus = workflow.commandRuleIds.length || workflow.tablesTouched.every((id) => !tablesById.get(id)?.forceRlsTarget) ? "mapped" : "unresolved";
    if (workflow.contextBoundaryStatus !== "implemented" && !workflow.systemBoundaryId && !workflow.manufacturerBootstrapBoundaryId && !workflow.platformReadScopeBoundaryId && !workflow.policyAlertActorCeilingBoundaryId && !workflow.publicReadContractBoundaryId) {
      workflow.expectedAllowedScenarios = ["Every database command matches one referenced command rule, including its actor, identity, assurance, scope, columns, lifecycle, and special boundary."];
      workflow.expectedDeniedScenarios = ["Any command without a matching rule, or with foreign scope, missing assurance, protected-column assignment, forbidden lifecycle state, or role elevation is denied."];
    }
    if (workflow.platformAdminRequiredAssurance) {
      workflow.requiredAssurance = [...new Set([...workflow.requiredAssurance, workflow.platformAdminRequiredAssurance])].sort();
    }
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== "decision-policy-command-semantics");
  }
  const scheduledCredentialTable = tablesById.get("table-scheduled-job-credential");
  if (scheduledCredentialTable) {
    const scheduledContracts = validateNamedSqlFunctionContracts().filter((contract) => contract.security.deploymentPhase === "session-b-b03-scheduled");
    const commandColumns = (command) => [...new Set(scheduledContracts.flatMap((contract) =>
      contract.security.ownerPrivileges?.filter(([table, candidate]) => table === "ScheduledJobCredential" && candidate === command)
        .flatMap(([, , columns]) => columns) || []
    ))].sort();
    for (const definition of [
      { suffix: "scheduled", actor: "scheduled-job", identity: "identity-scheduled-job", commands: ["SELECT", "UPDATE"] },
      { suffix: "operator", actor: "operator", identity: "identity-operator", commands: ["SELECT", "INSERT", "UPDATE"] },
    ]) for (const command of definition.commands) {
      const syntheticWorkflow = {
        id: `scheduled-job-credential-${definition.suffix}`,
        canonicalSourceFiles: ["backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql"],
        supportingEvidence: ["Exact named-function contract and hash-only ScheduledJobCredential migration."],
        executionSurface: definition.suffix === "scheduled" ? "scheduled" : "internal",
        authorizationBoundaryType: definition.suffix === "scheduled" ? "restricted-worker" : "operator-break-glass",
        contextBoundaryStatus: "implemented",
      };
      const rule = buildCommandRule({ table: scheduledCredentialTable, workflow: syntheticWorkflow, command,
        actors: [definition.actor], identityId: definition.identity,
        assurance: definition.suffix === "scheduled" ? "system-verified" : "operator-approved", routeEvidence: null });
      rule.allowedColumns = commandColumns(command).filter((column) => command !== "SELECT" || !scheduledCredentialTable.sensitiveColumns.includes(column));
      rule.requiresNamedFunction = true;
      rule.namedFunctionClass = definition.suffix === "scheduled" ? "exact-scheduled-capability-function" : "exact-operator-capability-function";
      rule.authorizationBoundary = definition.suffix === "scheduled" ? "restricted-worker" : "named-function";
      rule.supportingWorkflowIds = definition.suffix === "scheduled"
        ? ["workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler"]
        : [];
      if (definition.suffix === "scheduled") rule.workerBoundaryId = "worker-boundary-scheduled-compliance-packs";
      rules.push(rule);
    }
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
  const ruleIdsFor = (workflowId) => rules.filter((rule) => rule.supportingWorkflowIds.includes(workflowId)).map((rule) => rule.id).sort();
  const sqlCertificationProfiles = [
    {
      id: "sql-profile-risk-analytics-licensee-admin", workflowId: RISK_ANALYTICS_WORKFLOW_ID, route: "GET /api/analytics/risk-scores",
      routes: ["GET /api/analytics/risk-scores"],
      functionSignature: RISK_ANALYTICS_FUNCTION_SIGNATURE,
      actorClass: "licensee-admin", roleValues: ["LICENSEE_ADMIN", "ORG_ADMIN"], minimumAssurance: "password-verified", purposeCodes: ["tenant-risk-analytics"],
      scopeType: "canonical-licensee-organization", status: "named-function-candidate", commandRuleIds: ruleIdsFor(RISK_ANALYTICS_WORKFLOW_ID),
    },
    {
      id: "sql-profile-risk-analytics-platform-admin", workflowId: RISK_ANALYTICS_WORKFLOW_ID, route: "GET /api/analytics/risk-scores",
      routes: ["GET /api/analytics/risk-scores"],
      functionSignature: RISK_ANALYTICS_FUNCTION_SIGNATURE,
      actorClass: "platform-admin", roleValues: ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"], minimumAssurance: "mfa-verified", purposeCodes: ["tenant-risk-analytics"],
      scopeType: "database-validated-selected-licensee-organization", status: "named-function-candidate", commandRuleIds: ruleIdsFor(RISK_ANALYTICS_WORKFLOW_ID),
    },
    {
      id: "sql-profile-audit-log-licensee-admin", workflowId: AUDIT_LOGS_WORKFLOW_ID, route: "GET /api/audit/logs",
      actorClass: "licensee-admin", roleValues: ["LICENSEE_ADMIN", "ORG_ADMIN"], minimumAssurance: "mfa-verified", purposeCodes: ["audit-log-read"],
      scopeType: "canonical-licensee-organization", status: "direct-policy-candidate", commandRuleIds: ruleIdsFor(AUDIT_LOGS_WORKFLOW_ID),
    },
    {
      id: "sql-profile-audit-log-manufacturer", workflowId: AUDIT_LOGS_WORKFLOW_ID, route: "GET /api/audit/logs",
      actorClass: "manufacturer", roleValues: ["MANUFACTURER", "MANUFACTURER_ADMIN", "MANUFACTURER_USER"], minimumAssurance: "mfa-verified", purposeCodes: ["audit-log-read"],
      scopeType: "canonical-manufacturer-linked-licensee", status: "direct-policy-candidate", commandRuleIds: ruleIdsFor(AUDIT_LOGS_WORKFLOW_ID),
    },
    {
      id: "sql-profile-audit-log-platform-admin", workflowId: AUDIT_LOGS_WORKFLOW_ID, route: "GET /api/audit/logs",
      actorClass: "platform-admin", roleValues: ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"], minimumAssurance: "mfa-verified", purposeCodes: ["platform-audit-log-read"],
      scopeType: "database-validated-selected-licensee", status: "direct-policy-candidate",
      commandRuleIds: ruleIdsFor(AUDIT_LOGS_WORKFLOW_ID).filter((ruleId) => rules.find((rule) => rule.id === ruleId)?.tableId === "table-audit-log"),
    },
    {
      id: "sql-profile-trace-licensee-admin", workflowId: TRACE_TIMELINE_WORKFLOW_ID, route: "GET /api/trace/timeline",
      actorClass: "licensee-admin", roleValues: ["LICENSEE_ADMIN", "ORG_ADMIN"], minimumAssurance: "password-verified", purposeCodes: ["trace-timeline-read"],
      scopeType: "canonical-licensee-organization", status: "direct-policy-candidate", commandRuleIds: ruleIdsFor(TRACE_TIMELINE_WORKFLOW_ID),
    },
    {
      id: "sql-profile-trace-manufacturer", workflowId: TRACE_TIMELINE_WORKFLOW_ID, route: "GET /api/trace/timeline",
      actorClass: "manufacturer", roleValues: ["MANUFACTURER", "MANUFACTURER_ADMIN", "MANUFACTURER_USER"], minimumAssurance: "password-verified", purposeCodes: ["trace-timeline-read"],
      scopeType: "canonical-manufacturer-linked-licensee", status: "direct-policy-candidate", commandRuleIds: ruleIdsFor(TRACE_TIMELINE_WORKFLOW_ID),
    },
    ...DASHBOARD_SNAPSHOT_WORKFLOW_IDS.flatMap((workflowId, index) => [
      {
        id: `sql-profile-dashboard-snapshot-${index === 0 ? "scope" : "data"}-licensee-admin`,
        workflowId,
        route: "GET /api/dashboard/stats",
        routes: ["GET /api/dashboard/stats", "GET /api/events/dashboard"],
        functionSignature: index === 0 ? "app_rls.dashboard_snapshot_scope(text,text,text)" : "app_rls.dashboard_snapshot_data(text,text,text,text)",
        actorClass: "licensee-admin",
        roleValues: ["LICENSEE_ADMIN", "ORG_ADMIN"],
        minimumAssurance: "password-verified",
        purposeCodes: ["dashboard-snapshot-read"],
        scopeType: "canonical-licensee-organization",
        status: "named-function-candidate",
        commandRuleIds: ruleIdsFor(workflowId),
      },
      {
        id: `sql-profile-dashboard-snapshot-${index === 0 ? "scope" : "data"}-manufacturer`,
        workflowId,
        route: "GET /api/dashboard/stats",
        routes: ["GET /api/dashboard/stats", "GET /api/events/dashboard"],
        functionSignature: index === 0 ? "app_rls.dashboard_snapshot_scope(text,text,text)" : "app_rls.dashboard_snapshot_data(text,text,text,text)",
        actorClass: "manufacturer",
        roleValues: ["MANUFACTURER", "MANUFACTURER_ADMIN", "MANUFACTURER_USER"],
        minimumAssurance: "mfa-verified",
        purposeCodes: ["dashboard-snapshot-read"],
        scopeType: "canonical-manufacturer-active-licensee-set",
        status: "named-function-candidate",
        commandRuleIds: ruleIdsFor(workflowId),
      },
      {
        id: `sql-profile-dashboard-snapshot-${index === 0 ? "scope" : "data"}-platform-admin`,
        workflowId,
        route: "GET /api/dashboard/stats",
        routes: ["GET /api/dashboard/stats", "GET /api/events/dashboard"],
        functionSignature: index === 0 ? "app_rls.dashboard_snapshot_scope(text,text,text)" : "app_rls.dashboard_snapshot_data(text,text,text,text)",
        actorClass: "platform-admin",
        roleValues: ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"],
        minimumAssurance: "mfa-verified",
        purposeCodes: ["dashboard-snapshot-read"],
        scopeType: "database-validated-global-or-selected-licensee-aggregate",
        status: "named-function-candidate",
        commandRuleIds: ruleIdsFor(workflowId),
      },
    ]),
    ...BATCH_OPERATIONAL_READ_WORKFLOW_IDS.flatMap((workflowId) => [
      ["licensee-admin", ["LICENSEE_ADMIN", "ORG_ADMIN"], "password-verified", "canonical-licensee-organization"],
      ["manufacturer", ["MANUFACTURER", "MANUFACTURER_ADMIN", "MANUFACTURER_USER"], "mfa-verified", "canonical-manufacturer-active-licensee-set"],
      ["platform-admin", ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"], "mfa-verified", "database-validated-selected-licensee-organization"],
    ].map(([actorClass, roleValues, minimumAssurance, scopeType]) => ({
      id: `sql-profile-batch-operational-${workflowId.split("-").slice(-5).join("-")}-${actorClass}`,
      workflowId,
      route: "GET /api/qr/batches",
      routes: ["GET /api/qr/batches", "GET /api/qr/batches/:id/allocation-map"],
      functionSignatures: BATCH_OPERATIONAL_FUNCTION_SIGNATURES_BY_WORKFLOW.get(workflowId),
      actorClass,
      roleValues,
      minimumAssurance,
      purposeCodes: ["batch-operational-read"],
      scopeType,
      status: "named-function-candidate",
      commandRuleIds: ruleIdsFor(workflowId),
    }))),
    {
      id: "sql-profile-blocked-platform-and-incompatible-projections",
      workflowIds: [AUDIT_CSV_EXPORT_WORKFLOW_ID, FRAUD_REPORTS_WORKFLOW_ID, TRACE_TIMELINE_WORKFLOW_ID],
      actorClasses: ["platform-admin", "operator", "authenticated-user", "licensee-admin"], status: "direct-policy-blocked",
      blockers: ["platform-licensee-selector-validation-boundary-pending", "shared-runtime-role-incompatible-column-projection", "operator-procedure-required", "authenticated-user-role-ceiling-unresolved-for-direct-sql"],
    },
  ];
  const manifest = { schemaVersion: 1, generatedFrom: ["backend/prisma/schema.prisma", "documents/security/rls-program/tables.json", "documents/security/rls-program/workflows.json", "documents/security/rls-program/manufacturer-bootstrap-boundary.json", "documents/security/rls-program/platform-read-scope-boundary.json", "documents/security/rls-program/policy-alert-actor-ceiling.json", "documents/security/rls-program/public-read-contract.json", "backend/src/routes/index.ts"], actorClasses: [...actorClasses], assuranceLevels: [...assuranceLevels], commandVocabulary: [...policyCommands], sqlCertificationProfiles, rules: rules.sort((a, b) => a.id.localeCompare(b.id)) };
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

const PREAUTH_WORKFLOW_BOUNDARIES = Object.freeze({
  "workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-find-pre-candidate-password-user": ["password-login lookup", "exact-security-definer-function", "preauth-fn-lookup-password-user", "none"],
  "workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-record-password-login-failure": ["failed-login recording", "exact-security-definer-function", "preauth-fn-record-password-failure", "none"],
  "workflow-internal-backend-src-services-auth-password-reset-service-ts-request-password-reset": ["password-reset request", "exact-security-definer-function", "preauth-fn-request-password-reset", "none"],
  "workflow-internal-backend-src-services-auth-password-reset-service-ts-reset-password-with-token": ["password-reset completion", "exact-security-definer-function", "preauth-fn-consume-password-reset", "none"],
  "workflow-internal-backend-src-services-auth-invite-service-ts-get-invite-preview": ["invitation/setup-link lookup", "exact-security-definer-function", "preauth-fn-lookup-invitation", "none"],
  "workflow-internal-backend-src-services-auth-invite-service-ts-accept-invite": ["invitation/setup-link consumption", "exact-security-definer-function", "preauth-fn-consume-invitation", "none"],
  "workflow-internal-backend-src-services-auth-email-verification-service-ts-confirm-email-verification": ["email-verification consumption", "exact-security-definer-function", "preauth-fn-consume-email-verification", "none"],
});

const arg = (name, type, nullable = false) => ({ name, type, nullable });
const column = (name, type, nullable = false) => ({ name, type, nullable });
const access = (tableId, command, columns) => ({ tableId, command, columns });
const functionContract = (definition) => ({
  sqlSchema: "app_auth",
  fixedSearchPath: "pg_catalog,public",
  securityDefiner: true,
  dynamicSqlAllowed: false,
  genericQueryInputsAllowed: false,
  fullyQualifiedApplicationObjects: true,
  callerOwnedFunctionsAllowed: false,
  callerSetContextTrusted: false,
  ownerIdentity: "identity-auth-function-owner",
  executableRuntimeIdentities: ["identity-pre-auth-app"],
  publicExecutionDenied: true,
  restrictedReadExecutionDenied: true,
  appExecutionStatus: "denied after the runtime-role split; any current prototype app-role grant must be removed before activation",
  transactionRequirements: "One database transaction; any mutation, token consumption, session revocation, and returned result commit or roll back together.",
  implementationStatus: "production-reviewed SQL generated from the named-function contract registry",
  ...definition,
});

const buildPreAuthFunctionManifest = () => {
  const functions = [
    functionContract({
      id: "preauth-fn-lookup-password-user", sqlFunctionName: "lookup_password_user", arguments: [arg("requested_email", "text")],
      returnColumns: [column("id", "text"), column("email", "text"), column("passwordHash", "text", true), column("name", "text"), column("role", "text"), column("licenseeId", "text", true), column("orgId", "text", true), column("status", "text"), column("isActive", "boolean"), column("disabledAt", "timestamp without time zone", true), column("deletedAt", "timestamp without time zone", true), column("failedLoginAttempts", "integer"), column("lockedUntil", "timestamp without time zone", true), column("lastLoginAt", "timestamp without time zone", true), column("emailVerifiedAt", "timestamp without time zone", true)],
      purpose: "Find exactly one password-login candidate without actor context and return only password-verification/account-state/context bootstrap fields.", supportingWorkflowIds: ["workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-find-pre-candidate-password-user"], tablesRead: ["table-user"], tablesWritten: [],
      exactAllowedColumns: [access("table-user", "SELECT", ["id", "email", "passwordHash", "name", "role", "licenseeId", "orgId", "status", "isActive", "disabledAt", "deletedAt", "failedLoginAttempts", "lockedUntil", "lastLoginAt", "emailVerifiedAt"])],
      inputNormalization: "Trim and lowercase exactly once; require 3..320 characters and a single local@domain.tld shape; reject non-normalized or malformed input.", duplicateStateBehavior: "Materialize at most two case-insensitive matches and return zero rows unless exactly one exists.", tokenBindingRequirements: "Not a token flow; requested email is the sole normalized lookup key and caller-set app.* variables are ignored.", expiryChecks: "not-applicable", expiryRequired: false, oneTimeConsumptionBehavior: "not-applicable", oneTimeToken: false, rowLockingRequirements: "None; read-only lookup.", replayProtection: "Read-only; endpoint rate limiting and generic credential errors prevent enumeration.", volatility: "STABLE", parallelSafety: "SAFE", auditEventRequirement: "Authentication service records a generic login outcome without password hash or existence disclosure.", rateLimitExpectation: "Shared login pre-auth limiter plus IP and actor limiter.", secretColumnExposures: [{ tableId: "table-user", column: "passwordHash", justification: "Required only for local password verification inside the trusted backend; never returned to the HTTP caller or logged." }], externalResponseMode: "generic-invalid-credentials", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["One normalized active or inactive account candidate is returned for local password and account-state evaluation."], denyScenarios: ["Malformed email, duplicate case-insensitive state, missing account, direct User enumeration, session-variable redirection, unrelated role, PUBLIC, or restricted-read execution returns no candidate or permission denial."], p2TestRequirements: ["Exact signature/catalog security", "normalization and malformed email denial", "zero/one/duplicate matches", "session-variable manipulation cannot redirect lookup", "passwordHash is never exposed outside backend verification"],
    }),
    functionContract({
      id: "preauth-fn-record-password-failure", sqlFunctionName: "record_password_failure", arguments: [arg("requested_email", "text"), arg("attempted_at", "timestamp without time zone"), arg("max_attempts", "integer"), arg("lockout_minutes", "integer")], returnColumns: [column("failedLoginAttempts", "integer"), column("lockedUntil", "timestamp without time zone", true)],
      purpose: "Atomically increment one normalized account's failed-login counter and establish bounded lockout state.", supportingWorkflowIds: ["workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-record-password-login-failure"], tablesRead: ["table-user"], tablesWritten: ["table-user"], exactAllowedColumns: [access("table-user", "SELECT", ["id", "email", "failedLoginAttempts", "lockedUntil"]), access("table-user", "UPDATE", ["failedLoginAttempts", "lockedUntil", "updatedAt"])],
      inputNormalization: "Email must already be trimmed/lowercase and valid; attempted_at is required; max_attempts is 1..100; lockout_minutes is 1..1440.", duplicateStateBehavior: "Update zero rows unless exactly one case-insensitive email match exists.", tokenBindingRequirements: "Not a token flow; the normalized email and attempted_at bind the exact failure event.", expiryChecks: "not-applicable", expiryRequired: false, oneTimeConsumptionBehavior: "not-applicable", oneTimeToken: false, rowLockingRequirements: "Single UPDATE acquires the row lock and increments from the stored value; concurrent failures cannot lose increments.", replayProtection: "Each invocation is an auditable failed attempt; bounded inputs prevent arbitrary lockout duration and the function never clears an existing lock.", volatility: "VOLATILE", parallelSafety: "UNSAFE", auditEventRequirement: "Generic AUTH_LOGIN_FAIL/LOCKED event; no account-existence or credential detail.", rateLimitExpectation: "Shared login pre-auth limiter plus IP and actor limiter.", secretColumnExposures: [], externalResponseMode: "same-error-as-unknown-account", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["A valid failed attempt updates exactly one normalized account and returns only counter/lockout state."], denyScenarios: ["Malformed/bounds-invalid input, duplicate state, unknown account, cross-account update, arbitrary columns, or caller-selected lockout outside bounds updates nothing."], p2TestRequirements: ["parallel increment and threshold crossing", "duplicate/unknown no-op", "bounded inputs", "existing lock preservation", "exact returned columns"],
    }),
    functionContract({
      id: "preauth-fn-request-password-reset", sqlFunctionName: "request_password_reset", arguments: [arg("requested_email", "text"), arg("reset_token_hash", "text"), arg("expires_at", "timestamp without time zone"), arg("requested_at", "timestamp without time zone"), arg("created_ip_hash", "text", true), arg("user_agent_hash", "text", true)], returnColumns: [column("accepted", "boolean"), column("deliveryRequired", "boolean"), column("userId", "text", true), column("email", "text", true), column("licenseeId", "text", true), column("orgId", "text", true), column("expiresAt", "timestamp without time zone", true)],
      purpose: "Issue a reset-token row for exactly one eligible account while preserving a constant-success external response.", supportingWorkflowIds: ["workflow-internal-backend-src-services-auth-password-reset-service-ts-request-password-reset"], tablesRead: ["table-user"], tablesWritten: ["table-password-reset"], exactAllowedColumns: [access("table-user", "SELECT", ["id", "email", "isActive", "deletedAt", "licenseeId", "orgId"]), access("table-password-reset", "INSERT", ["orgId", "userId", "tokenHash", "expiresAt", "createdIpHash", "userAgentHash"])],
      inputNormalization: "Trim/lowercase and validate email; require a fixed-format server-generated token hash; requested_at is required; expires_at must be after requested_at and within configured reset TTL ceiling.", duplicateStateBehavior: "Ambiguous case-insensitive account state issues no token but returns the same accepted external outcome.", tokenBindingRequirements: "The server generates the opaque raw token, passes only its hash, and the inserted row binds it to exactly one User.id and orgId.", expiryChecks: "expires_at must be future, finite, and within the reviewed reset TTL ceiling.", expiryRequired: true, oneTimeConsumptionBehavior: "Issuance only; the token row is marked unused and may be consumed once by preauth-fn-consume-password-reset.", oneTimeToken: true, rowLockingRequirements: "No account mutation; unique tokenHash plus exact-one account match. Collision fails closed.", replayProtection: "Unique token hash, rate limiting, bounded TTL, and constant external response.", volatility: "VOLATILE", parallelSafety: "UNSAFE", auditEventRequirement: "Generic reset-request event and response; nullable internal delivery fields must never be serialized to the requester.", rateLimitExpectation: "Password-reset route, IP, normalized-email, and issuance-frequency limits.", secretColumnExposures: [], externalResponseMode: "constant-success", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["Eligible exact account gets one bound reset row; backend may use internal delivery fields to send the link while HTTP returns only accepted=true."], denyScenarios: ["Malformed email/hash, duplicate account, inactive/deleted account, invalid expiry, token collision, or rate-limit violation issues no token and never reveals existence."], p2TestRequirements: ["constant external response equivalence", "duplicate/inactive/deleted no issuance", "unique hash and bounded expiry", "returned internal fields cannot cross the route response"],
    }),
    functionContract({
      id: "preauth-fn-consume-password-reset", sqlFunctionName: "consume_password_reset_token", arguments: [arg("token_hash_candidates", "text[]"), arg("new_password_hash", "text"), arg("consumed_at", "timestamp without time zone")], returnColumns: [column("id", "text"), column("email", "text"), column("name", "text"), column("role", "text"), column("licenseeId", "text", true), column("orgId", "text", true)],
      purpose: "Atomically consume one valid reset token, activate/update its bound account password, and revoke existing sessions.", supportingWorkflowIds: ["workflow-internal-backend-src-services-auth-password-reset-service-ts-reset-password-with-token"], tablesRead: ["table-password-reset", "table-user", "table-refresh-token"], tablesWritten: ["table-password-reset", "table-user", "table-refresh-token"], exactAllowedColumns: [access("table-password-reset", "SELECT", ["id", "userId", "tokenHash", "usedAt", "expiresAt"]), access("table-password-reset", "UPDATE", ["usedAt"]), access("table-user", "SELECT", ["id", "email", "name", "role", "licenseeId", "orgId"]), access("table-user", "UPDATE", ["passwordHash", "status", "emailVerifiedAt", "failedLoginAttempts", "lockedUntil", "updatedAt"]), access("table-refresh-token", "SELECT", ["userId", "revokedAt"]), access("table-refresh-token", "UPDATE", ["revokedAt", "revokedReason", "lastUsedAt"])],
      inputNormalization: "Require 1..3 non-empty fixed-format server-derived hash candidates, one approved password hash format, and non-null consumed_at; reject raw tokens and duplicate candidate values.", duplicateStateBehavior: "Lock at most two matching reset rows and fail closed unless exactly one token row and one bound user exist.", tokenBindingRequirements: "Candidate hashes derive only from the supplied opaque token; matched PasswordReset.userId is the sole account authority.", expiryChecks: "Matched token expiresAt must be greater than consumed_at.", expiryRequired: true, oneTimeConsumptionBehavior: "Require usedAt IS NULL under row lock; set usedAt=consumed_at in the same transaction as password update and session revocation.", oneTimeToken: true, rowLockingRequirements: "SELECT matching PasswordReset FOR UPDATE, verify exactly one, and lock/update the bound User before mutation.", replayProtection: "Atomic usedAt transition and row lock; concurrent/replayed calls return no success.", volatility: "VOLATILE", parallelSafety: "UNSAFE", auditEventRequirement: "AUTH_PASSWORD_RESET_COMPLETED after commit; no token/hash/password in audit.", rateLimitExpectation: "Reset-completion IP/actor limiter plus bounded token attempts.", secretColumnExposures: [{ tableId: "table-user", column: "passwordHash", justification: "Accepted only as a server-generated write value; never selected or returned." }, { tableId: "table-password-reset", column: "tokenHash", justification: "Compared internally to server-derived candidates; never returned." }], externalResponseMode: "generic-invalid-or-expired-token", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["One unexpired unused token atomically changes only its bound account and revokes that account's live refresh tokens."], denyScenarios: ["Unknown, ambiguous, expired, used, replayed, cross-account, raw-token, malformed-hash, or concurrent consumption changes nothing."], p2TestRequirements: ["FOR UPDATE/concurrent single winner", "expiry and usedAt denial", "atomic rollback across three tables", "all live sessions revoked", "cross-account and duplicate hash denial"],
    }),
    functionContract({
      id: "preauth-fn-lookup-invitation", sqlFunctionName: "lookup_invitation_token", arguments: [arg("token_hash_candidates", "text[]"), arg("checked_at", "timestamp without time zone")], returnColumns: [column("email", "text"), column("role", "text"), column("expiresAt", "timestamp without time zone"), column("licenseeName", "text", true), column("requiresConnector", "boolean")],
      purpose: "Return the minimal preview for one valid invitation token without exposing its hash or unrelated tenant data.", supportingWorkflowIds: ["workflow-internal-backend-src-services-auth-invite-service-ts-get-invite-preview"], tablesRead: ["table-invite", "table-licensee"], tablesWritten: [], exactAllowedColumns: [access("table-invite", "SELECT", ["tokenHash", "email", "role", "expiresAt", "usedAt", "licenseeId"]), access("table-licensee", "SELECT", ["id", "name"])],
      inputNormalization: "Require 1..3 unique fixed-format server-derived token hashes and non-null checked_at; raw token fragments are forbidden.", duplicateStateBehavior: "Return zero rows unless exactly one Invite matches all candidate hashes; duplicate/ambiguous state fails closed.", tokenBindingRequirements: "The preview is bound only to the exact invite hash, stored role, stored email, stored licensee, and optional matching Licensee.id.", expiryChecks: "Require usedAt IS NULL and expiresAt > checked_at.", expiryRequired: true, oneTimeConsumptionBehavior: "Read-only preview; rejects consumed tokens but does not consume a valid token.", oneTimeToken: true, rowLockingRequirements: "None for preview; consumption rechecks under lock.", replayProtection: "No state change; expiry, usedAt, bounded candidates, rate limiting, and minimal projection limit replay value.", volatility: "STABLE", parallelSafety: "SAFE", auditEventRequirement: "No token/hash logging; abnormal repeated preview attempts are security telemetry only.", rateLimitExpectation: "Invite-preview route plus IP and actor limiter.", secretColumnExposures: [{ tableId: "table-invite", column: "tokenHash", justification: "Compared internally only; never returned." }], externalResponseMode: "generic-invalid-or-expired-invite", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["One unused unexpired token returns only its intended email, role, expiry, licensee display name, and connector requirement."], denyScenarios: ["Unknown, malformed, ambiguous, expired, used, token-fragment, or cross-invite input returns no preview."], p2TestRequirements: ["minimal projection", "used/expired/duplicate denial", "candidate bounds", "no hash or unrelated Licensee columns returned"],
    }),
    functionContract({
      id: "preauth-fn-consume-invitation", sqlFunctionName: "consume_invitation_token", arguments: [arg("token_hash_candidates", "text[]"), arg("new_password_hash", "text"), arg("requested_name", "text", true), arg("consumed_at", "timestamp without time zone"), arg("request_id", "text"), arg("ip_hash", "text", true), arg("user_agent", "text", true)], returnColumns: [column("inviteId", "text"), column("id", "text"), column("email", "text"), column("name", "text"), column("role", "text"), column("licenseeId", "text", true), column("orgId", "text", true), column("status", "text")],
      purpose: "Atomically activate the existing account bound to one invitation without changing its role or tenant ownership.", supportingWorkflowIds: ["workflow-internal-backend-src-services-auth-invite-service-ts-accept-invite"], tablesRead: ["table-invite", "table-user"], tablesWritten: ["table-invite", "table-user"], exactAllowedColumns: [access("table-invite", "SELECT", ["id", "orgId", "licenseeId", "email", "role", "manufacturerId", "tokenHash", "expiresAt", "usedAt"]), access("table-invite", "UPDATE", ["usedAt", "acceptedByUserId"]), access("table-user", "SELECT", ["id", "email", "role", "orgId", "licenseeId", "status", "isActive", "deletedAt"]), access("table-user", "UPDATE", ["passwordHash", "status", "emailVerifiedAt", "name", "failedLoginAttempts", "lockedUntil", "updatedAt"])],
      inputNormalization: "Require bounded unique server-derived hash candidates, approved password hash, name trimmed to the product limit, and non-null consumed_at.", duplicateStateBehavior: "Lock at most two matches and fail unless exactly one Invite and exactly one existing User with normalized Invite.email exist.", tokenBindingRequirements: "Invite email, role, orgId and licenseeId must equal the existing User binding; function never creates a user or writes role/orgId/licenseeId/manufacturerId.", expiryChecks: "Require Invite.expiresAt > consumed_at.", expiryRequired: true, oneTimeConsumptionBehavior: "Require usedAt IS NULL under lock and atomically set usedAt/acceptedByUserId with account activation.", oneTimeToken: true, rowLockingRequirements: "Lock the Invite and bound User; exactly one transaction performs validation, password/state update, and consumption.", replayProtection: "Atomic usedAt transition, row locks, and exact account/tenant/role binding.", volatility: "VOLATILE", parallelSafety: "UNSAFE", auditEventRequirement: "AUTH_INVITE_ACCEPTED after commit with invite/user IDs; no token/hash/password.", rateLimitExpectation: "Invite-accept route plus IP and actor limiter.", secretColumnExposures: [{ tableId: "table-user", column: "passwordHash", justification: "Accepted only as a server-generated write value; never selected or returned." }, { tableId: "table-invite", column: "tokenHash", justification: "Compared internally only; never returned." }], externalResponseMode: "generic-invalid-or-expired-invite", returnsAccountExistenceToExternalCaller: false, roleCeiling: "Never writes User.role or tenant keys. A licensee/manufacturer invite cannot create or promote SUPER_ADMIN/PLATFORM_SUPER_ADMIN; any platform invite must already bind an operator-created matching platform user.",
      allowScenarios: ["One matching unused invite activates only its pre-created, same-email, same-role, same-tenant account."], denyScenarios: ["Role/tenant mismatch, missing user, attempted platform elevation, expired/used/ambiguous token, disabled/deleted account, or replay changes nothing."], p2TestRequirements: ["single concurrent winner", "role/org/licensee immutability", "licensee invite platform ceiling", "missing/disabled/deleted user denial", "atomic invite/user rollback"],
    }),
    functionContract({
      id: "preauth-fn-consume-email-verification", sqlFunctionName: "consume_email_verification_token", arguments: [arg("token_hash_candidates", "text[]"), arg("consumed_at", "timestamp without time zone")], returnColumns: [column("verified", "boolean"), column("purpose", "text"), column("userId", "text"), column("email", "text")],
      purpose: "Atomically consume one account-bound email-verification token, apply its exact verification/email-change state, and revoke sessions after an email change.", supportingWorkflowIds: ["workflow-internal-backend-src-services-auth-email-verification-service-ts-confirm-email-verification"], tablesRead: ["table-email-verification-token", "table-user", "table-refresh-token"], tablesWritten: ["table-email-verification-token", "table-user", "table-refresh-token"], exactAllowedColumns: [access("table-email-verification-token", "SELECT", ["id", "userId", "email", "pendingEmail", "purpose", "tokenHash", "expiresAt", "usedAt"]), access("table-email-verification-token", "UPDATE", ["usedAt"]), access("table-user", "SELECT", ["id", "email", "pendingEmail", "orgId", "licenseeId", "status", "isActive", "deletedAt"]), access("table-user", "UPDATE", ["email", "pendingEmail", "pendingEmailRequestedAt", "emailVerifiedAt", "status", "updatedAt"]), access("table-refresh-token", "SELECT", ["userId", "revokedAt"]), access("table-refresh-token", "UPDATE", ["revokedAt", "revokedReason", "lastUsedAt"])],
      inputNormalization: "Require 1..3 unique fixed-format server-derived token hashes and non-null consumed_at; token fragments and arbitrary user IDs are forbidden.", duplicateStateBehavior: "Lock at most two token matches and fail unless exactly one token and its exact User.id exist; pending-email collision also fails closed.", tokenBindingRequirements: "EmailVerificationToken.userId is the sole account authority; EMAIL_CHANGE additionally requires token.pendingEmail to equal User.pendingEmail and remain globally unique.", expiryChecks: "Require expiresAt > consumed_at.", expiryRequired: true, oneTimeConsumptionBehavior: "Require usedAt IS NULL under lock; set usedAt in the same transaction as emailVerifiedAt/email transition and any session revocation.", oneTimeToken: true, rowLockingRequirements: "Lock token and bound User; uniqueness check and mutations execute atomically.", replayProtection: "Atomic usedAt transition and row lock; already-verified accounts are idempotent only when the same unused account-bound token is valid, then token is consumed once.", volatility: "VOLATILE", parallelSafety: "UNSAFE", auditEventRequirement: "AUTH_EMAIL_VERIFIED or AUTH_EMAIL_CHANGE_CONFIRMED after commit; no token/hash.", rateLimitExpectation: "Email-verification route plus IP and actor limiter.", secretColumnExposures: [{ tableId: "table-email-verification-token", column: "tokenHash", justification: "Compared internally only; never returned." }], externalResponseMode: "generic-invalid-or-expired-verification", returnsAccountExistenceToExternalCaller: false,
      allowScenarios: ["One unused unexpired token verifies only its bound account; EMAIL_CHANGE also applies the bound pending email and revokes that account's sessions."], denyScenarios: ["Unknown, ambiguous, expired, used, cross-account, pending-email mismatch/collision, disabled/deleted account, fragment lookup, or replay changes nothing."], p2TestRequirements: ["account binding", "single concurrent winner", "already-verified safe behavior", "email collision denial", "EMAIL_CHANGE session revocation", "atomic rollback"],
    }),
  ].sort((a, b) => a.id.localeCompare(b.id));
  for (const fn of functions) {
    const contract = namedFunctionContractFor(`app_auth.${fn.sqlFunctionName}`);
    assert(contract, `${fn.id} lacks its authoritative named-function contract`);
    fn.definitionSource = contract.definitionLocation;
    fn.rollbackSource = contract.security.rollbackDefinition;
    fn.disposableProbes = [...contract.disposableProbes];
    fn.tablesRead = [...new Set(contract.tableCommands.filter(([, command]) => command === "SELECT").map(([table]) => `table-${slug(table)}`))].sort();
    fn.tablesWritten = [...new Set(contract.tableCommands.filter(([, command]) => command !== "SELECT").map(([table]) => `table-${slug(table)}`))].sort();
  }
  return { schemaVersion: 1, generatedFrom: ["documents/security/rls-program/workflows.json", "documents/security/rls-program/command-semantics.json", "documents/security/rls-program/public-read-contract.json", "backend/src/services/auth"], publicReadContractReference: "public-read-contract-v1 preserves these seven exact app_auth functions and defines separate app_public functions; no generic pre-auth function or direct-table fallback is approved.", functionCount: functions.length, securityInvariants: ["No dynamic SQL or generic query input", "SET search_path=pg_catalog and fully qualified application objects", "NOLOGIN auth owner; EXECUTE only for pre-auth runtime", "PUBLIC, restricted-read and authenticated-app execution denied", "No direct table grants to pre-auth runtime", "Caller-set app.* variables are not authority"], functions };
};

export const buildPreAuthBoundary = (workflowManifest, commandManifest, currentTableManifest = null) => {
  const selected = workflowManifest.workflows.filter((workflow) => PREAUTH_WORKFLOW_BOUNDARIES[workflow.id]);
  assert(selected.every((workflow) => PREAUTH_WORKFLOW_BOUNDARIES[workflow.id]), "pre-auth workflow lacks an explicit boundary classification");
  for (const workflow of selected) {
    const [group, boundaryMode, functionId, assurance] = PREAUTH_WORKFLOW_BOUNDARIES[workflow.id];
    workflow.preAuthBoundary = { workflowGroup: group, boundaryMode, functionId, status: "resolved" };
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== "decision-pre-auth-boundary");
    workflow.contextRequirementsSource = "human-reviewed";
    workflow.requiredAssurance = [assurance];
    if (boundaryMode === "ordinary-authenticated-context") {
      workflow.authorizationBoundaryType = "authenticated-context";
      workflow.authenticationStage = "actor-resolved-bootstrap";
      workflow.actorClasses = ["authenticated-user"];
      workflow.commandActorClasses = ["authenticated-user"];
      workflow.runtimeIdentities = ["identity-authenticated-app"];
      workflow.contextRequirements = ["Install canonical actor context from the verified password/bootstrap-token identity before any table command."];
    } else {
      workflow.contextRequirements = [`EXECUTE only ${functionId}; no direct table access or caller-set app.* authority.`];
      workflow.preAuthFunctionId = functionId;
    }
    for (const rule of commandManifest.rules.filter((rule) => rule.supportingWorkflowIds.includes(workflow.id))) {
      rule.preAuthBoundary = workflow.preAuthBoundary;
      rule.minimumAssurance = assurance;
      if (boundaryMode === "ordinary-authenticated-context") {
        rule.actorClasses = ["authenticated-user"];
        rule.runtimeIdentities = ["identity-authenticated-app"];
        rule.requiresNamedFunction = false;
        rule.namedFunctionClass = "none";
        rule.authorizationBoundary = "ordinary-rls";
        rule.allowScenarios = [`Resolved actor using identity-authenticated-app at ${assurance} performs the command only after canonical transaction context is installed.`];
        rule.denyScenarios = ["Pre-auth runtime, anonymous caller, missing/mismatched actor context, lower assurance, or direct contextless table access is denied."];
      } else rule.preAuthFunctionId = functionId;
    }
  }
  const manifest = buildPreAuthFunctionManifest();
  const functionIds = new Set(manifest.functions.map((fn) => fn.id));
  for (const workflow of selected.filter((item) => item.preAuthBoundary.boundaryMode === "exact-security-definer-function")) assert(functionIds.has(workflow.preAuthBoundary.functionId), `${workflow.id} references missing pre-auth function`);
  writeJson(preAuthFunctionsPath, manifest);

  const tableManifest = currentTableManifest || readJson(tableManifestPath);
  const functionTables = new Set(manifest.functions.flatMap((fn) => [...fn.tablesRead, ...fn.tablesWritten]));
  const movedTables = new Set(selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context").flatMap((workflow) => workflow.tablesTouched));
  for (const table of tableManifest.tables) {
    if (functionTables.has(table.id)) table.preAuthAccessMode = "exact-named-security-definer-function-only";
    else if (movedTables.has(table.id)) table.preAuthAccessMode = "denied; actor or system context required";
  }
  if (!currentTableManifest) {
    writeJson(tableManifestPath, tableManifest);
    writeTableOwnershipReview(tableManifest, buildPolicyDependencyGraph(tableManifest));
  }

  const identityManifest = readJson(identityManifestPath);
  const preAuth = identityManifest.identities.find((identity) => identity.id === "identity-pre-auth-app");
  preAuth.approvedFunctionIds = manifest.functions.map((fn) => fn.id);
  preAuth.directTablePrivileges = [];
  preAuth.publicSchemaCreate = false;
  preAuth.restrictedReadHelperAccess = false;
  preAuth.resolvedDecisions = [...new Set([...preAuth.resolvedDecisions, "decision-pre-auth-boundary"])].sort();
  preAuth.unresolvedDecisions = preAuth.unresolvedDecisions.filter((id) => id !== "decision-pre-auth-boundary");
  const owner = identityManifest.identities.find((identity) => identity.id === "identity-auth-function-owner");
  owner.approvedFunctionIds = manifest.functions.map((fn) => fn.id);
  owner.resolvedDecisions = [...new Set([...owner.resolvedDecisions, "decision-pre-auth-boundary"])].sort();
  owner.unresolvedDecisions = owner.unresolvedDecisions.filter((id) => id !== "decision-pre-auth-boundary");
  writeJson(identityManifestPath, identityManifest);
  return manifest;
};

export const writePreAuthBoundaryReview = (manifest, workflows) => {
  const selected = workflows.filter((workflow) => workflow.preAuthBoundary);
  const moved = selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context");
  const lines = ["# MSCQR pre-authentication boundary review", "", "This review records the seven production SQL boundaries generated from the authoritative named-function contracts, including exact ownership, grants, FORCE-RLS policies, rollback, and PostgreSQL 18 probes.", "", `Selected workflows: ${selected.length}; exact functions: ${manifest.functions.length}; moved behind actor context: ${moved.length}; operator-only: 0; retired: 0.`, "", "## Workflow reconciliation", "", "| Workflow | Group | Boundary | Function/assurance |", "|---|---|---|---|"];
  for (const workflow of selected.sort((a, b) => a.id.localeCompare(b.id))) lines.push(`| ${workflow.id} | ${workflow.preAuthBoundary.workflowGroup} | ${workflow.preAuthBoundary.boundaryMode} | ${workflow.preAuthBoundary.functionId || workflow.requiredAssurance.join(", ")} |`);
  lines.push("", "## Exact function families", "", "| Function | Purpose | Reads | Writes | One-time |", "|---|---|---|---|---:|");
  for (const fn of manifest.functions) lines.push(`| ${fn.id} (` + "`" + `${fn.sqlSchema}.${fn.sqlFunctionName}` + "`" + `) | ${fn.purpose} | ${fn.tablesRead.join(", ") || "none"} | ${fn.tablesWritten.join(", ") || "none"} | ${fn.oneTimeToken ? "yes" : "no"} |`);
  lines.push("", "Exact arguments, return columns, table/column exposure, normalization, duplicate-state handling, expiry, locking, replay, transaction and P2 requirements live in `pre-auth-functions.json`.", "", "## Execution grants and certification", "", "The LOGIN pre-auth runtime receives only CONNECT, app_auth USAGE and EXECUTE on the seven exact signatures. PUBLIC, restricted-read and authenticated-app execution are denied; the NOLOGIN auth owner owns only app_auth and approved functions and receives exact required table-column privileges. The checked-in production definitions, rollback, generated policies and PostgreSQL 18 probe are maintained by the named-function contract registry.", "", "All token functions reject ambiguous matches. Reset, invitation and email-consumption functions lock the token row and atomically consume it with account/session mutations. Reset request uses a constant-success external response. Invitation consumption never writes role or tenant ownership and cannot elevate a licensee invitation to a platform role.", "");
  fs.writeFileSync(preAuthBoundaryReviewPath, `${lines.join("\n")}\n`);
};

export const buildPreAuthProgramme = () => {
  const workflowManifest = readJson(workflowManifestPath);
  const commandManifest = readJson(commandSemanticsPath);
  const manifest = buildPreAuthBoundary(workflowManifest, commandManifest);
  writePreAuthBoundaryReview(manifest, workflowManifest.workflows);
  writeJson(workflowManifestPath, workflowManifest);
  writeJson(commandSemanticsPath, commandManifest);
  const decisions = readJson(decisionManifestPath);
  const decision = decisions.decisions.find((item) => item.id === "decision-pre-auth-boundary");
  const selected = workflowManifest.workflows.filter((workflow) => workflow.preAuthBoundary);
  decision.status = "resolved";
  decision.resolvedAt = "2026-07-16";
  decision.affectedWorkflows = selected.map((workflow) => workflow.id);
  decision.affectedTables = [...new Set(selected.flatMap((workflow) => workflow.tablesTouched))].sort();
  decision.resolution = { authority: "documents/security/rls-program/pre-auth-functions.json", selectedWorkflows: selected.length, exactFunctions: manifest.functions.length, movedBehindContext: selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context").length, operatorOnly: 0, retired: 0, guarantees: manifest.securityInvariants };
  writeJson(decisionManifestPath, decisions);
  return manifest;
};

const WORKER_BOUNDARY_DEFINITIONS = Object.freeze({
  "workflow-worker-backend-src-services-audit-log-outbox-service-ts-flush-audit-log-outbox": {
    id: "worker-boundary-audit-outbox-delivery",
    workerClass: "actor-derived-job",
    runtimeIdentity: "identity-worker",
    entrypoint: "backend/src/worker.ts -> startAuditLogOutboxWorker -> flushAuditLogOutbox",
    queueOrScheduleSource: "AuditLogOutbox polling started by the registered backend worker script",
    producerIdentity: ["identity-authenticated-app", "identity-worker", "identity-scheduled-job"],
    durableJobTableOrPayloadSource: "table-audit-log-outbox; the row ID, immutable canonical payload digest, scope fields, job type, request ID, expiry and idempotency key are authority; payload JSON alone is not",
    tenantScopeFields: ["organization_id", "licensee_id"],
    actorFields: ["initiating_user_id", "initiating_actor_role_snapshot", "executing_system_identity"],
    scopeVerificationMethod: "Load the durable row by job ID, verify its canonical payload digest, re-resolve the initiating actor and tenant relationship, and reject any payload/row mismatch before installing context.",
    authorizationRevalidationRules: ["Initiating actor still exists", "Tenant relationship still exists", "Required audit action remains allowlisted", "Caller-controlled platform-admin flags are ignored"],
    tablesRead: ["table-audit-log-outbox"],
    tablesWritten: ["table-audit-log-outbox", "table-audit-log"],
    tableCommands: [{ tableId: "table-audit-log-outbox", commands: ["SELECT", "UPDATE"] }, { tableId: "table-audit-log", commands: ["INSERT"], authority: "worker-fn-consume-audit-outbox" }],
    idempotencyStrategy: { keySource: "durable idempotency_key derived from the original audit request/correlation and canonical payload digest", uniquenessBoundary: "job_type + tenant scope + idempotency_key", conflictBehavior: "reject same key with a different digest", replayResult: "return the existing flushedAuditLogId without inserting another audit event", conflictingPayloadDenied: true },
    replayProtection: "One durable row, immutable digest, maximum age, row lock and QUEUED/FAILED-to-SENT compare-and-set; SENT is terminal.",
    retryPolicy: { maxAttempts: 10, backoffSeconds: "bounded exponential 10..300", duplicateSideEffectsAllowed: false, retryableStates: ["QUEUED", "FAILED"] },
    deadLetterBehavior: "After maxAttempts, retain the row as terminal FAILED/dead-letter evidence, stop automatic delivery, and require an audited operator requeue with a new execution claim.",
    concurrencyControl: { type: "row-lock-plus-compare-and-set", databaseEnforced: true, rule: "Lock one row and transition only the expected status; the distributed lease is an optimization, not authority." },
    leaseOrLockSemantics: "Global poller lease plus per-row FOR UPDATE/CAS; lease expiry cannot permit duplicate AuditLog insertion.",
    maximumJobAgeSeconds: 86400,
    cancellationSemantics: "Shutdown stops claiming new rows; an in-transaction row completes or rolls back. Terminal SENT rows cannot be cancelled.",
    acceptedJobTypes: ["AUDIT_LOG_RECOVERY"],
    namedFunctionRequirement: { required: true, functionId: "worker-fn-consume-audit-outbox", sqlSchema: "app_rls", sqlFunctionName: "consume_audit_log_outbox", arguments: [{ name: "job_id", type: "text" }, { name: "payload_digest", type: "text" }, { name: "attempted_at", type: "timestamp without time zone" }], genericQueryInputsAllowed: false, reason: "Audit insertion and durable one-time completion must be atomic and column-narrow." },
  },
  "workflow-worker-backend-src-services-siem-outbox-service-ts-flush-security-event-outbox": {
    id: "worker-boundary-siem-outbox-delivery",
    workerClass: "platform-scoped-system-job",
    runtimeIdentity: "identity-worker",
    entrypoint: "backend/src/worker.ts -> startSecurityEventOutboxWorker -> flushSecurityEventOutbox",
    queueOrScheduleSource: "SecurityEventOutbox polling started by the registered backend worker script",
    producerIdentity: ["identity-authenticated-app", "identity-worker", "identity-scheduled-job"],
    durableJobTableOrPayloadSource: "table-security-event-outbox; durable row ID, allowlisted event type, immutable payload digest, scope version, request ID, expiry and idempotency key are authority",
    tenantScopeFields: ["organization_id when the event is tenant-scoped", "licensee_id when the event is tenant-scoped"],
    actorFields: ["initiating_user_id when present", "executing_system_identity"],
    scopeVerificationMethod: "Load the durable outbox row, validate its allowlisted event type and canonical digest, and resolve any tenant/actor references from authoritative tables; JSON claims never grant authority.",
    authorizationRevalidationRules: ["Event type is allowlisted", "Any referenced tenant still exists", "Any actor attribution matches the durable event", "No human role is installed or impersonated"],
    tablesRead: ["table-security-event-outbox"],
    tablesWritten: ["table-security-event-outbox"],
    tableCommands: [{ tableId: "table-security-event-outbox", commands: ["SELECT", "UPDATE"] }],
    idempotencyStrategy: { keySource: "SecurityEventOutbox.id used as the stable external event ID plus immutable payload digest", uniquenessBoundary: "SIEM sink + outbox row ID", conflictBehavior: "reject the same row ID with a different digest", replayResult: "return/retain the existing SENT result; never send a second logical event", conflictingPayloadDenied: true },
    replayProtection: "Stable webhook event ID, immutable digest, expiry, attempt counter and QUEUED/FAILED-to-SENT compare-and-set.",
    retryPolicy: { maxAttempts: 10, backoffSeconds: "bounded exponential 5..300", duplicateSideEffectsAllowed: false, retryableStates: ["QUEUED", "FAILED"] },
    deadLetterBehavior: "After maxAttempts, retain terminal FAILED evidence and require an audited operator requeue; never mutate the original event ID or payload.",
    concurrencyControl: { type: "lease-plus-row-claim", databaseEnforced: true, rule: "Use a database compare-and-set claim per row in addition to the distributed poller lease." },
    leaseOrLockSemantics: "Global SIEM poller lease plus database row claim; queue delivery or Redis lease alone is insufficient.",
    maximumJobAgeSeconds: 86400,
    cancellationSemantics: "Shutdown stops new claims; an in-flight external request records a retryable outcome unless SENT was durably committed.",
    acceptedJobTypes: ["AUDIT_LOG", "CSP_VIOLATION"],
    namedFunctionRequirement: { required: false, functionId: null, genericQueryInputsAllowed: false, reason: "Exact table SELECT/UPDATE plus a database CAS claim is sufficient; network delivery cannot be made atomic by a database function." },
  },
  "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler": {
    id: "worker-boundary-scheduled-compliance-packs",
    workerClass: "scheduled-maintenance-job",
    runtimeIdentity: "identity-scheduled-job",
    entrypoint: "backend/src/worker.ts -> startCompliancePackScheduler",
    queueOrScheduleSource: "UTC hour/minute schedule configured for the registered backend worker process",
    producerIdentity: ["identity-scheduled-job"],
    durableJobTableOrPayloadSource: "table-compliance-pack-job plus a durable schedule-run key; each tenant partition is claimed before report generation",
    tenantScopeFields: ["licensee_id", "organization_id resolved from licensee_id", "schedule_scope_version"],
    actorFields: ["executing_system_identity; no human actor or platform-admin impersonation"],
    scopeVerificationMethod: "An exact schedule-claim function enumerates only active allowlisted tenant partitions, creates/claims one durable CompliancePackJob, and the scheduled transaction revalidates licensee-to-organization scope.",
    authorizationRevalidationRules: ["Licensee remains active", "Licensee-to-organization binding matches", "Schedule ID matches the verified durable credential and claimed job", "No platform-user lookup or human impersonation is permitted"],
    tablesRead: ["table-scheduled-job-credential", "table-licensee", "table-organization", "table-compliance-pack-job", "table-action-idempotency-key", "table-incident", "table-incident-handoff", "table-audit-log", "table-evidence-retention-policy"],
    tablesWritten: ["table-compliance-pack-job", "table-action-idempotency-key", "table-audit-log-outbox"],
    tableCommands: [{ tableId: "table-scheduled-job-credential", commands: ["SELECT", "UPDATE"], authority: "worker-fn-claim-compliance-pack-slice" }, { tableId: "table-licensee", commands: ["SELECT"], authority: "worker-fn-claim-compliance-pack-slice" }, { tableId: "table-organization", commands: ["SELECT"], authority: "worker-fn-claim-compliance-pack-slice" }, { tableId: "table-compliance-pack-job", commands: ["SELECT", "INSERT", "UPDATE"] }, { tableId: "table-action-idempotency-key", commands: ["SELECT", "INSERT", "UPDATE"] }, { tableId: "table-incident", commands: ["SELECT"] }, { tableId: "table-incident-handoff", commands: ["SELECT"] }, { tableId: "table-audit-log", commands: ["SELECT"] }, { tableId: "table-evidence-retention-policy", commands: ["SELECT"] }, { tableId: "table-audit-log-outbox", commands: ["INSERT"] }],
    idempotencyStrategy: { keySource: "compliance-pack + licensee_id + UTC schedule stamp + report period", uniquenessBoundary: "job_type + licensee_id + schedule stamp", conflictBehavior: "reject a different tenant/period/digest for the same key", replayResult: "return the existing job/result; RELEASED/COMPLETED work is not regenerated", conflictingPayloadDenied: true },
    replayProtection: "Unique schedule-partition key, durable job state, maximum age and RUNNING-to-COMPLETED/FAILED compare-and-set.",
    retryPolicy: { maxAttempts: 3, backoffSeconds: "bounded exponential 60..900 within maximum job age", duplicateSideEffectsAllowed: false, retryableStates: ["FAILED"] },
    deadLetterBehavior: "After maxAttempts or maximum age, retain FAILED job/evidence and require an operator-approved new job ID; never overwrite a completed pack.",
    concurrencyControl: { type: "unique-schedule-key-plus-compare-and-set", databaseEnforced: true, rule: "Unique tenant/schedule partition and durable RUNNING claim; process-level lastRunStamp is not authority." },
    leaseOrLockSemantics: "One bounded schedule claim (maximum 100 tenant partitions) followed by one tenant transaction at a time; safe cancellation leaves unclaimed partitions for retry.",
    maximumJobAgeSeconds: 7200,
    cancellationSemantics: "Stop after the current tenant transaction, leave unclaimed partitions retryable, and never publish a partial artifact as COMPLETED.",
    acceptedJobTypes: ["SCHEDULED_COMPLIANCE_PACK"],
    namedFunctionRequirement: { required: true, functionId: "worker-fn-claim-compliance-pack-slice", sqlSchema: "app_rls", sqlFunctionName: "claim_compliance_pack_slice", arguments: [{ name: "capability", type: "text" }, { name: "schedule_id", type: "text" }, { name: "due_at", type: "timestamp without time zone" }, { name: "batch_size", type: "integer" }], genericQueryInputsAllowed: false, reason: "A hash-only scheduled capability authorizes one bounded platform-wide tenant claim; every returned report remains tenant-scoped." },
  },
});

const WORKER_CONTEXT_KEYS = ["app.system_identity", "app.job_id", "app.job_type", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.initiating_user_id", "app.request_id", "app.auth_assurance"];
const buildWorkerBoundaryManifest = (workflowManifest, commandManifest, currentTableManifest = null) => {
  const tableManifest = currentTableManifest || readJson(tableManifestPath);
  const selected = workflowManifest.workflows.filter((workflow) => ["worker", "scheduled"].includes(workflow.executionSurface) && workflow.authorizationBoundaryType === "restricted-worker");
  assert.deepEqual(selected.map((workflow) => workflow.id).sort(), Object.keys(WORKER_BOUNDARY_DEFINITIONS).sort(), "worker workflow selector drifted; classify the registered execution path, not queue-named producers");
  const boundaries = [];
  for (const workflow of selected) {
    const definition = WORKER_BOUNDARY_DEFINITIONS[workflow.id];
    const rules = commandManifest.rules.filter((rule) => rule.supportingWorkflowIds.includes(workflow.id));
    for (const tableCommand of definition.tableCommands) {
      const existing = workflow.commandsPerTable.find((item) => item.tableId === tableCommand.tableId);
      if (existing) existing.commands = [...new Set([...existing.commands, ...tableCommand.commands])].sort();
      else workflow.commandsPerTable.push({ tableId: tableCommand.tableId, commands: [...tableCommand.commands].sort() });
      for (const command of tableCommand.commands) {
        if (rules.some((rule) => rule.tableId === tableCommand.tableId && rule.command === command)) continue;
        const source = commandManifest.rules.find((rule) =>
          rule.tableId === tableCommand.tableId &&
          rule.command === command &&
          rule.authorizationBoundary !== "prohibited" &&
          !rule.supportingWorkflowIds.some((id) => [AUDIT_CSV_EXPORT_WORKFLOW_ID, AUDIT_LOGS_WORKFLOW_ID, FRAUD_REPORTS_WORKFLOW_ID].includes(id))
        );
        assert(source, `${definition.id} cannot derive ${tableCommand.tableId}:${command} command semantics`);
        const rule = structuredClone(source);
        rule.id = `command-${slug(tableCommand.tableId.replace(/^table-/, ""))}-${command.toLowerCase()}-${definition.id}`;
        rule.supportingWorkflowIds = [workflow.id];
        rule.supportingEvidence = [definition.entrypoint, `Transitive worker contract in ${workerBoundariesPath.slice(repoRoot.length + 1)}`];
        rule.status = "architecture-resolved";
        commandManifest.rules.push(rule);
        rules.push(rule);
      }
    }
    workflow.commandsPerTable.sort((a, b) => a.tableId.localeCompare(b.tableId));
    workflow.tablesTouched = workflow.commandsPerTable.map((item) => item.tableId);
    for (const rule of rules) {
      rule.workerBoundaryId = definition.id;
      rule.actorClasses = [definition.runtimeIdentity === "identity-scheduled-job" ? "scheduled-job" : "worker"];
      rule.runtimeIdentities = [definition.runtimeIdentity];
      rule.minimumAssurance = "system-verified";
      rule.requiresRestrictedWorkerBoundary = true;
      rule.authorizationBoundary = "restricted-worker";
      rule.scopeRule = definition.scopeVerificationMethod;
      rule.allowScenarios = [`${definition.id} uses ${definition.runtimeIdentity} at system-verified with a fresh verified durable job, exact context and command.`];
      rule.denyScenarios = ["Unverified payload scope, unknown/stale job, conflicting replay, wrong identity, human impersonation, platform-admin context or out-of-bound command is denied."];
      const requirement = definition.tableCommands.find((item) => item.tableId === rule.tableId && item.commands.includes(rule.command));
      if (requirement?.authority?.startsWith("worker-fn-")) {
        rule.requiresNamedFunction = true;
        rule.namedFunctionClass = requirement.authority;
      }
      if (definition.id === "worker-boundary-scheduled-compliance-packs" && rule.tableId === "table-user") rule.workerAccessDisposition = "remove-before-activation; no human impersonation";
      if (definition.id === "worker-boundary-scheduled-compliance-packs" && rule.tableId === "table-licensee") {
        rule.requiresNamedFunction = true;
        rule.namedFunctionClass = "worker-fn-claim-compliance-pack-slice";
        rule.workerAccessDisposition = "replace-direct-enumeration-with-exact-function";
      }
    }
    workflow.workerBoundaryId = definition.id;
    workflow.workerClass = definition.workerClass;
    workflow.runtimeIdentities = [definition.runtimeIdentity];
    workflow.actorClasses = [definition.runtimeIdentity === "identity-scheduled-job" ? "scheduled-job" : "worker"];
    workflow.commandActorClasses = [...workflow.actorClasses];
    workflow.requiredAssurance = ["system-verified"];
    workflow.commandRuleIds = rules.map((rule) => rule.id).sort();
    workflow.scopeVerificationMethod = definition.scopeVerificationMethod;
    workflow.requiredTransactionContext = WORKER_CONTEXT_KEYS;
    workflow.idempotencyStrategy = definition.idempotencyStrategy;
    workflow.expectedAllowedScenarios = [`${definition.id} executes only an allowlisted job with verified durable scope, system identity and exact commands.`];
    workflow.expectedDeniedScenarios = ["Unverified JSON scope, unknown job type, stale/replayed job, conflicting idempotency payload, platform-admin context, human impersonation or wrong runtime identity is denied."];
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== "decision-worker-identity-model");
    boundaries.push({
      ...definition,
      workflowIds: [workflow.id],
      requiredTransactionContext: { keys: WORKER_CONTEXT_KEYS, transactionLocal: true, sameTransactionAsProtectedQueries: true, derivedFromVerifiedServerEvidence: true, clearsAtTransactionEnd: true, fixedAssurance: "system-verified", humanRoleContextAllowed: false, platformAdminContextAllowed: false },
      exactCommandRuleIds: rules.map((rule) => rule.id).sort(),
      namedFunctionRequirement: { ...definition.namedFunctionRequirement, ownerIdentity: definition.namedFunctionRequirement.required ? (definition.runtimeIdentity === "identity-scheduled-job" ? "identity-auth-function-owner" : "identity-table-owner") : null, securityMode: definition.runtimeIdentity === "identity-scheduled-job" ? "DEFINER" : "INVOKER", fixedSearchPath: definition.runtimeIdentity === "identity-scheduled-job" ? "pg_catalog,public" : "pg_catalog", publicExecutionDenied: true, executableRuntimeIdentity: definition.runtimeIdentity },
      auditEventRequirement: { required: true, fields: ["system_identity", "job_id", "job_type", "initiating_user_id_when_present", "tenant_scope", "request_id", "outcome", "retry_attempt"], executorAttribution: definition.runtimeIdentity, humanActorIsInitiatorOnly: true, immutable: true },
      correlationIdRequirement: "A validated UUID request/correlation ID is mandatory in the durable record and every audit/retry event.",
      allowedScenarios: ["An accepted job type with a fresh durable record, verified scope, matching digest/idempotency key and exact runtime identity executes once."],
      deniedScenarios: ["Unknown type, missing or payload-only scope, actor/tenant mismatch, expired job, replay conflict, malformed correlation ID, unexpected command, platform-admin flag or wrong identity is denied."],
      implementationStatus: definition.runtimeIdentity === "identity-scheduled-job"
        ? "implemented; PostgreSQL 18 disposable certification required for each generated package"
        : "contract-resolved; runtime/schema implementation required before activation",
      p2TestRequirements: ["verified durable scope and empty/payload-only denial", "idempotent replay and conflicting digest denial", "concurrent single winner", "maximum-age and unknown-type denial", "audit executor/job attribution", "retry/dead-letter/cancellation state machine"],
      assurance: "system-verified",
      platformAdminContextAllowed: false,
      humanImpersonationAllowed: false,
      unknownJobTypesRejected: true,
      conflictingReplayPayloadDenied: true,
      sideEffectsDeduplicated: true,
    });
  }
  for (const [workflowId, boundaryId] of [["workflow-internal-backend-src-services-audit-log-outbox-service-ts-queue-audit-log-outbox", "worker-boundary-audit-outbox-delivery"], ["workflow-internal-backend-src-services-siem-outbox-service-ts-queue-security-event", "worker-boundary-siem-outbox-delivery"]]) {
    const producer = workflowManifest.workflows.find((workflow) => workflow.id === workflowId);
    assert(producer, `${workflowId} producer workflow missing`);
    producer.producesWorkerBoundaryId = boundaryId;
    producer.workerClassificationEvidence = "Durable enqueue producer; executes under its originating request/system identity and is not the non-interactive consumer.";
  }
  const attention = workflowManifest.workflows.find((workflow) => workflow.id === "workflow-http-backend-src-services-attention-queue-service-ts-get-attention-queue-snapshot-uncached");
  assert(attention, "attention queue authenticated workflow missing");
  attention.workerClassificationEvidence = "Synchronous authenticated dashboard read reached from dashboardController; the word Queue is a product noun, not worker registration evidence.";
  commandManifest.rules.sort((a, b) => a.id.localeCompare(b.id));
  for (const table of tableManifest.tables) {
    const touching = workflowManifest.workflows.filter((workflow) => workflow.tablesTouched.includes(table.id));
    table.productionRuntimeReaders = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.includes("SELECT")).map((workflow) => workflow.id);
    table.productionRuntimeWriters = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.some((command) => ["INSERT", "UPDATE", "DELETE"].includes(command))).map((workflow) => workflow.id);
    table.requiredCommands = [...new Set(touching.flatMap((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands || []))].sort();
    applyRuntimeCommandMatrix(table, workflowManifest.workflows);
    table.commandRuleIds = commandManifest.rules.filter((rule) => rule.tableId === table.id).map((rule) => rule.id).sort();
  }
  if (!currentTableManifest) writeJson(tableManifestPath, tableManifest);
  return { schemaVersion: 1, generatedFrom: ["documents/security/rls-program/workflows.json", "documents/security/rls-program/command-semantics.json", "backend/src/worker.ts"], boundaryCount: boundaries.length, contextKeys: WORKER_CONTEXT_KEYS, securityInvariants: ["Durable or cryptographically authenticated job evidence is authority; JSON payload scope is not", "Worker and scheduled credentials remain distinct", "Transaction-local system context never impersonates a human or platform administrator", "Every mutation is idempotent, replay-protected, concurrency-protected and auditable", "No generic worker function or platform-wide bypass"], boundaries: boundaries.sort((a, b) => a.id.localeCompare(b.id)) };
};

export const writeWorkerIdentityReview = (manifest) => {
  const lines = ["# MSCQR worker and scheduled-job identity review", "", "This review defines authorization contracts only. It changes no worker runtime, SQL function, database role, policy, RLS state, queue, schedule or database.", "", `Selected execution workflows: ${manifest.boundaries.length} (workers: ${manifest.boundaries.filter((item) => item.runtimeIdentity === "identity-worker").length}; scheduled: ${manifest.boundaries.filter((item) => item.runtimeIdentity === "identity-scheduled-job").length}).`, "", "## Approved boundaries", "", "| Boundary | Class | Runtime | Durable authority | Tables read | Tables written | Named function |", "|---|---|---|---|---|---|---|"];
  for (const boundary of manifest.boundaries) lines.push(`| ${boundary.id} | ${boundary.workerClass} | ${boundary.runtimeIdentity} | ${boundary.durableJobTableOrPayloadSource} | ${boundary.tablesRead.join(", ")} | ${boundary.tablesWritten.join(", ")} | ${boundary.namedFunctionRequirement.required ? boundary.namedFunctionRequirement.functionId : "none"} |`);
  const contextKeys = manifest.contextKeys.map((key) => "`" + key + "`").join(", ");
  lines.push("", "## Context, idempotency and audit", "", "Every protected transaction installs only these transaction-local keys from verified durable evidence: " + contextKeys + ". Human role and platform-admin context are forbidden; `app.auth_assurance` is fixed to `system-verified`.", "", "Audit-outbox delivery preserves the initiating actor as origin evidence while recording `identity-worker` as executor. SIEM delivery uses the durable outbox ID as the stable external event ID. Scheduled compliance uses a hash-only credential, a unique licensee/schedule partition and `identity-scheduled-job`; it performs no platform-user lookup or human impersonation.", "", "All retries retain the same job ID, digest and idempotency key. Conflicting payloads are denied, terminal results are returned rather than repeated, database row/CAS or unique constraints enforce concurrency, and retry exhaustion retains immutable dead-letter evidence.", "", "## Remaining implementation work", "", "The scheduled compliance boundary is implemented by the checked-in B03 credential migration, exact SECURITY DEFINER functions, owner policies and scheduled/operator grants. Every generated package must still pass the PostgreSQL 18 disposable capability, denial, replay, concurrency, rollback and cleanup probes before use. Other worker boundaries remain contract-resolved until their own durable claims and exact runtime functions are implemented. No generic query function or broad worker grant is permitted.", "");
  fs.writeFileSync(workerIdentityReviewPath, `${lines.join("\n")}\n`);
};

const writeWorkerIdentityAuthority = (manifest) => {
  const identities = readJson(identityManifestPath);
  for (const identityId of ["identity-worker", "identity-scheduled-job"]) {
    const identity = identities.identities.find((item) => item.id === identityId);
    identity.approvedWorkerBoundaryIds = manifest.boundaries.filter((boundary) => boundary.runtimeIdentity === identityId).map((boundary) => boundary.id);
    identity.requiredTransactionContextKeys = WORKER_CONTEXT_KEYS;
    identity.directPreAuthFunctionExecution = false;
    identity.publicSchemaCreate = false;
    identity.resolvedDecisions = [...new Set([...identity.resolvedDecisions, "decision-worker-identity-model"])].sort();
    identity.unresolvedDecisions = identity.unresolvedDecisions.filter((id) => id !== "decision-worker-identity-model");
  }
  const owner = identities.identities.find((item) => item.id === "identity-table-owner");
  owner.allowedSchemas = [...new Set([...owner.allowedSchemas, "app_rls"])].sort();
  owner.approvedWorkerFunctionIds = manifest.boundaries.filter((boundary) => boundary.namedFunctionRequirement.required).map((boundary) => boundary.namedFunctionRequirement.functionId).sort();
  owner.resolvedDecisions = [...new Set([...owner.resolvedDecisions, "decision-worker-identity-model"])].sort();
  writeJson(identityManifestPath, identities);
};

export const buildWorkerProgramme = () => {
  const workflowManifest = readJson(workflowManifestPath);
  const commandManifest = readJson(commandSemanticsPath);
  const manifest = buildWorkerBoundaryManifest(workflowManifest, commandManifest);
  writeJson(workerBoundariesPath, manifest);
  writeWorkerIdentityReview(manifest);
  writeJson(workflowManifestPath, workflowManifest);
  writeJson(commandSemanticsPath, commandManifest);
  writeWorkerIdentityAuthority(manifest);
  const decisions = readJson(decisionManifestPath);
  const decision = decisions.decisions.find((item) => item.id === "decision-worker-identity-model");
  decision.status = "resolved";
  decision.resolvedAt = "2026-07-16";
  decision.affectedWorkflows = manifest.boundaries.flatMap((boundary) => boundary.workflowIds);
  decision.affectedTables = [...new Set(manifest.boundaries.flatMap((boundary) => [...boundary.tablesRead, ...boundary.tablesWritten]))].sort();
  decision.resolution = { authority: "documents/security/rls-program/worker-boundaries.json", boundaries: manifest.boundaries.length, workerWorkflows: manifest.boundaries.filter((item) => item.runtimeIdentity === "identity-worker").length, scheduledWorkflows: manifest.boundaries.filter((item) => item.runtimeIdentity === "identity-scheduled-job").length, namedFunctions: manifest.boundaries.filter((item) => item.namedFunctionRequirement.required).length, guarantees: manifest.securityInvariants };
  writeJson(decisionManifestPath, decisions);
  return manifest;
};

const OWNER_ATTRIBUTES = Object.freeze({ login: false, superuser: false, createDatabase: false, createRole: false, replication: false, bypassRls: false, inherit: false });
const ENVIRONMENT_ROLES = Object.freeze({
  development: { tableOwner: "mscqr_dev_owner", authOwner: "mscqr_dev_auth_owner", migration: "mscqr_dev_migration" },
  staging: { tableOwner: "mscqr_staging_owner", authOwner: "mscqr_staging_auth_owner", migration: "mscqr_staging_migration" },
  production: { tableOwner: "mscqr_prod_owner", authOwner: "mscqr_prod_auth_owner", migration: "mscqr_prod_migration" },
});

const ownershipRule = (id, objectClass, expectedOwner, creationIdentity, transferMechanism, verification, rollbackBehavior, extra = {}) => ({
  id, objectClass, expectedOwner, creationIdentity, transferMechanism, temporaryMembershipRequirements: "Only the brokered administrative ownership phase may grant identity-migration one target-owner membership at a time with SET TRUE, INHERIT FALSE and ADMIN FALSE. It is revoked in the same transaction before success.", postTransferVerification: verification, rollbackBehavior, forbiddenOwnershipStates: ["owned by any runtime LOGIN identity", "owned by identity-migration at deployment success", "owned by an environment administrator LOGIN"], ...extra,
});

export const buildObjectOwnershipManifest = (tableManifest, identityManifest, preAuthManifest, workerManifest) => {
  const safeRollback = "Clean-room only: stop every green consumer, prove no required data was accepted, drop the fresh green database, then drop only package-marked roles. The blue database remains untouched; object-level restoration is unsupported.";
  const perObjectTransfer = "After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden.";
  const tableOwner = "identity-table-owner";
  const authOwner = "identity-auth-function-owner";
  const rules = [
    ownershipRule("ownership-tables", "tables", tableOwner, "identity-migration", perObjectTransfer, "Every Prisma table has relowner=environment table owner; all 77 FORCE targets and both migration-only tables are included.", safeRollback),
    ownershipRule("ownership-table-owned-sequences", "table-owned-sequences", tableOwner, "identity-migration", perObjectTransfer, "Every identity/serial sequence linked through pg_depend has the same owner as its owning table.", safeRollback),
    ownershipRule("ownership-standalone-sequences", "standalone-sequences", tableOwner, "identity-migration", perObjectTransfer, "Every non-extension application sequence has the table owner; no orphan migration-owned sequence remains.", safeRollback),
    ownershipRule("ownership-indexes", "indexes", "owning-table-owner", "identity-migration", "Index ownership follows its owning table and is normalized by the table transfer.", "Every application index resolves to a table whose relowner is the table owner.", safeRollback),
    ownershipRule("ownership-constraints", "constraints", "owning-table-owner", "identity-migration", "Constraint authority follows the owning table; no independent runtime ownership exists.", "Every constraint belongs to a table certified to the table owner; referenced tables are also certified.", safeRollback),
    ownershipRule("ownership-policies", "policies", "owning-table-owner", "identity-migration", "Policies have no independent owner; only the owning table owner may create, alter, or drop them through the reviewed deployment path.", "Every policy's table relowner is the table owner and no policy command is installed by startup/runtime.", safeRollback),
    ownershipRule("ownership-schemas", "schemas", "schema-specific", "identity-migration", "Explicit ALTER SCHEMA OWNER through the broker path: public and app_rls to table owner; app_auth to auth owner; extension-owned schemas remain extension-managed.", "pg_namespace proves exact schema owners and PUBLIC/runtime CREATE is absent on protected schemas.", safeRollback),
    ownershipRule("ownership-functions", "functions", "schema-and-function-specific", "identity-migration", perObjectTransfer, "app_auth exact pre-auth signatures have auth owner; approved app_rls worker helpers have table owner and SECURITY INVOKER; no migration/runtime-owned application function remains.", safeRollback),
    ownershipRule("ownership-procedures", "procedures", tableOwner, "identity-migration", perObjectTransfer, "Every application procedure is owned by the table owner; app_auth procedures are forbidden unless separately added to the exact auth manifest.", safeRollback),
    ownershipRule("ownership-enum-types", "enum-types", tableOwner, "identity-migration", perObjectTransfer, "Every non-extension application enum type has typowner=table owner.", safeRollback),
    ownershipRule("ownership-composite-types", "composite-types", tableOwner, "identity-migration", perObjectTransfer, "Every standalone non-extension composite type has typowner=table owner; table row types follow their table.", safeRollback),
    ownershipRule("ownership-views", "views", tableOwner, "identity-migration", perObjectTransfer, "Every application view has relowner=table owner and uses an explicitly reviewed security option.", safeRollback),
    ownershipRule("ownership-materialized-views", "materialized-views", tableOwner, "identity-migration", perObjectTransfer, "Every application materialized view has relowner=table owner and an exact refresh authority.", safeRollback),
    ownershipRule("ownership-triggers", "triggers", "owning-table-owner", "identity-migration", "Trigger authority follows the table; its called function is separately certified under the function rule.", "Every non-internal trigger is attached to a table-owner table and calls an approved-owner function.", safeRollback),
    ownershipRule("ownership-publications", "publications", "external-managed-service-owner", "controlled-platform-administration-only", "Application migrations may not create publications. If introduced, a separately approved non-runtime administrative owner is required.", "No MSCQR application publication is present; future presence fails verification until allowlisted.", safeRollback, { presence: "not-detected" }),
    ownershipRule("ownership-subscriptions", "subscriptions", "external-managed-service-owner", "controlled-platform-administration-only", "Application migrations may not create subscriptions. If introduced, a separately approved non-runtime administrative owner is required.", "No MSCQR application subscription is present; future presence fails verification until allowlisted.", safeRollback, { presence: "not-detected" }),
    ownershipRule("ownership-extensions", "extensions", "managed-service-extension-owner", "controlled-platform-administration-only", "Extension installation and update are outside Prisma migrations; extension-owned objects/schemas are identified by extension dependencies and excluded from application transfer.", "Every extension and extension-owned object is on an explicit platform allowlist and is not owned by a runtime role.", safeRollback, { presence: "catalog-discovery-required-per-environment" }),
  ];
  const manifest = {
    schemaVersion: 1,
    decisionId: "decision-object-ownership-chain",
    status: "architecture-resolved",
    postgresVersion: "18",
    environments: ENVIRONMENT_ROLES,
    logicalOwnerIdentities: [
      { identityId: tableOwner, environmentRoleNames: Object.fromEntries(Object.entries(ENVIRONMENT_ROLES).map(([environment, roles]) => [environment, roles.tableOwner])), attributes: OWNER_ATTRIBUTES, owns: ["all 78 Prisma tables", "application sequences", "public and app_rls schemas", "table-bound objects", "approved app_rls SECURITY INVOKER helpers"], forbiddenMemberships: "No runtime role and no standing migration membership." },
      { identityId: authOwner, environmentRoleNames: Object.fromEntries(Object.entries(ENVIRONMENT_ROLES).map(([environment, roles]) => [environment, roles.authOwner])), attributes: OWNER_ATTRIBUTES, owns: ["app_auth schema", "approved app_auth and app_rls SECURITY DEFINER boundaries"], forbiddenOwnership: ["application tables", "application sequences", "app_rls schema", "non-approved functions"], forbiddenMemberships: "No runtime role and no standing migration membership." },
      { identityId: "identity-migration", environmentRoleNames: Object.fromEntries(Object.entries(ENVIRONMENT_ROLES).map(([environment, roles]) => [environment, roles.migration])), attributes: { login: true, superuser: false, bypassRls: false, inherit: false }, ownsAtSuccess: [], credentialPurpose: "deployment-only", createAuthority: "Reviewed DDL during the migration window only", ownerMembershipAtSuccess: [] },
    ],
    postgres18CapabilityPrerequisites: [
      "CREATEROLE alone is not blanket authority to transfer ownership or grant arbitrary membership.",
      "The transfer executor must be the current owner or otherwise have the required object authority and must be able to SET ROLE to the new owner; role membership SET, INHERIT and ADMIN options are independent.",
      "Any temporary membership uses ADMIN FALSE, INHERIT FALSE, SET TRUE and is revoked before success; INHERIT FALSE prevents automatic privileges but SET TRUE remains powerful until revocation.",
      "ALTER DEFAULT PRIVILEGES applies to objects subsequently created by the named/current creator, not inherited role defaults, so every possible creation identity is normalized explicitly.",
    ],
    recommendedTransferModel: { id: "clean-room-broker-per-object-transfer", recommended: true, migrationOwnerMembership: "transactional-admin-phase-only", transferExecutor: "audited broker-controlled green-database administrator", grantorAuthority: "The green administrator must hold exact SET/ADMIN authority for the package-created migration and NOLOGIN owner roles; CREATEROLE alone is insufficient.", temporaryMembership: { member: "identity-migration", roles: [tableOwner, authOwner], admin: false, inherit: false, set: true, grantedOneAtATime: true, revokedBeforeSuccess: true, runtimeCredentialUsed: false, auditRequired: true }, reason: "Prisma owns zero-based objects as the restricted migration identity; the separate administrative phase transfers them deterministically without giving a running migration or runtime session owner authority." },
    fallbackTransferModel: { id: "none", recommended: false, activation: "unsupported", requirements: ["Destroy and recreate the green candidate if the exact transfer model cannot execute"], successWithActiveMembershipAllowed: false },
    objectClasses: rules,
    schemaOwnershipRules: [
      { schema: "public", expectedOwner: tableOwner, publicCreate: false, runtimeCreate: false, notes: "USAGE is grant-generated; upgraded databases are checked because PUBLIC CREATE may predate secure defaults." },
      { schema: "app_rls", expectedOwner: tableOwner, publicCreate: false, runtimeCreate: false, notes: "Contains only approved transaction helpers and SECURITY INVOKER worker helpers." },
      { schema: "app_auth", expectedOwner: authOwner, publicCreate: false, runtimeCreate: false, notes: "Only exact pre-auth functions; identity-pre-auth-app receives USAGE and exact EXECUTE." },
      { schema: "prisma-created", expectedOwner: tableOwner, publicCreate: false, runtimeCreate: false, notes: "Any additional Prisma application schema must be declared before migration." },
      { schema: "extension-owned", expectedOwner: "managed-service-extension-owner", publicCreate: false, runtimeCreate: false, notes: "Discovered by extension dependency and allowlisted; never reassigned by application migration." },
    ],
    approvedFunctionOwnerBoundaries: {
      preAuth: preAuthManifest.functions.map((fn) => ({ functionId: fn.id, schema: fn.sqlSchema, name: fn.sqlFunctionName, argumentTypes: fn.arguments.map((argument) => argument.type), owner: authOwner, securityMode: "DEFINER" })),
      worker: workerManifest.boundaries.filter((boundary) => boundary.namedFunctionRequirement.required).map((boundary) => ({ functionId: boundary.namedFunctionRequirement.functionId, schema: boundary.namedFunctionRequirement.sqlSchema, name: boundary.namedFunctionRequirement.sqlFunctionName, argumentTypes: boundary.namedFunctionRequirement.arguments.map((argument) => argument.type), owner: boundary.runtimeIdentity === "identity-scheduled-job" ? authOwner : tableOwner, securityMode: boundary.runtimeIdentity === "identity-scheduled-job" ? "DEFINER" : "INVOKER" })),
    },
    sequenceOwnershipRules: { tableOwned: "Owner must equal the owning table owner; dependency must identify exactly one owning column/table.", standalone: "Non-extension application sequences use identity-table-owner and exact command grants; migration ownership is residue.", extensionOwned: "Remain with the allowlisted extension owner and are excluded only through catalog dependency evidence." },
    enumAndTypeOwnershipRules: { applicationEnums: tableOwner, applicationCompositeTypes: tableOwner, tableRowTypes: "follow owning table", extensionTypes: "managed-service-extension-owner by catalog dependency" },
    policyOwnershipSemantics: "PostgreSQL policies have no independent owner field. Their authority is the owning table's relowner; all policy lifecycle operations therefore remain with identity-table-owner through the deployment path.",
    defaultPrivilegeRules: { creationIdentities: ["identity-migration", tableOwner, authOwner], publicGrants: [], runtimeGrants: [], revokePublicByDefault: ["EXECUTE on functions/procedures", "USAGE on types", "all privileges on tables, sequences and schemas"], commandGrantSource: "documents/security/rls-program/command-semantics.json", notes: "Defaults affect future objects only and are normalized for each possible creator. Exact runtime grants are applied after ownership transfer; no app, read, worker, scheduled or pre-auth access is inherited from defaults." },
    migrationLifecycle: [
      { step: 1, id: "authenticate", requirement: "identity-migration authenticates with the deployment-only environment credential." },
      { step: 2, id: "preflight", requirement: "Verify the exact green database/environment and administrator, require a template0-clean application catalog, zero managed roles, zero unexpected grants/policies/memberships/default ACLs and no traffic." },
      { step: 3, id: "temporary-authority", requirement: "Only after zero-based Prisma migration, the brokered administrator grants the migration owner one SET-only target-owner edge inside the ownership transaction." },
      { step: 4, id: "migrate", requirement: "Migration creates/alters only reviewed objects and records the created/changed object set." },
      { step: 5, id: "transfer", requirement: "Broker transfers each object to its class owner using the deterministic object manifest." },
      { step: 6, id: "normalize-privileges", requirement: "Normalize schema privileges, exact grants, routine EXECUTE, and creator-specific default privileges." },
      { step: 7, id: "revoke-temporary-authority", requirement: "Revoke every temporary membership/authority in the success and failure paths." },
      { step: 8, id: "catalog-verification", requirement: "Run the complete catalog contract and compare the created/changed set with expected owners and grants." },
      { step: 9, id: "completion-gate", requirement: "Fail deployment if ownership, membership, grant, security-mode, or verification residue exists." },
    ],
    catalogVerification: [
      { id: "verify-table-owners", catalogs: ["pg_class", "pg_namespace", "pg_roles"], proves: "All 75 FORCE RLS tables and both migration-only tables have the environment table owner; relrowsecurity/relforcerowsecurity are checked separately without changing state." },
      { id: "verify-sequence-owners", catalogs: ["pg_class", "pg_depend"], proves: "Table-owned and standalone application sequences have the correct owner and dependency." },
      { id: "verify-schema-owners-and-create", catalogs: ["pg_namespace", "aclexplode"], proves: "public/app_rls belong to table owner, app_auth to auth owner, and PUBLIC/runtime roles lack CREATE." },
      { id: "verify-function-owners-and-modes", catalogs: ["pg_proc", "pg_namespace", "aclexplode"], proves: "Exact pre-auth functions have auth owner and SECURITY DEFINER; approved app_rls helpers have table owner and SECURITY INVOKER; PUBLIC/unexpected EXECUTE is absent." },
      { id: "verify-type-owners", catalogs: ["pg_type", "pg_depend"], proves: "Non-extension enum/composite types have table owner and extension-owned types match the allowlist." },
      { id: "verify-no-owner-residue", catalogs: ["pg_class", "pg_namespace", "pg_proc", "pg_type", "pg_roles"], proves: "Migration, runtime and environment admin LOGIN roles own no protected object." },
      { id: "verify-membership-closure", catalogs: ["pg_auth_members", "pg_roles"], proves: "Runtime roles cannot reach owners; migration has no remaining owner membership; temporary rows are absent." },
      { id: "verify-default-and-object-privileges", catalogs: ["pg_default_acl", "information_schema", "aclexplode"], proves: "PUBLIC and runtime roles have no broad defaults or unexpected application-object privileges." },
      { id: "verify-optional-object-classes", catalogs: ["pg_publication", "pg_subscription", "pg_extension", "pg_depend"], proves: "Optional platform-owned objects are absent or exactly allowlisted and never runtime/migration owned." },
    ],
    forbiddenOwnershipStates: ["LOGIN owner for a protected object", "migration-owned object at success", "runtime-owned application object", "runtime membership in table or auth owner", "migration owner membership after transfer", "PUBLIC CREATE on a protected schema", "broad runtime grants from default privileges", "SECURITY DEFINER app_rls worker helper"],
    migrationCompletionGate: { catalogVerificationRequired: true, transferFailureReportsSuccess: false, revocationFailureReportsSuccess: false, ownershipResidueAllowed: 0, migrationMembershipResidueAllowed: 0, runtimeOwnedObjectsAllowed: 0, transactionRule: "Every package phase is transactional. Any phase failure stops green activation; cleanup destroys the unused green database and then removes only exact package-marked roles.", failClosed: true },
    migrationOnlyTables: tableManifest.tables.filter((table) => table.primaryCategory === "migration-only").map((table) => ({ tableId: table.id, owner: tableOwner, forceRlsTarget: false, runtimeGrants: [], decision: "No production runtime access; physical ownership is still normalized to the table owner." })),
    evidence: ["scripts/rls/generate-clean-room-rls-sql.mjs", "scripts/rls/certify-clean-room-database.mjs", "scripts/rls/certify-full-database.mjs", "scripts/tests/full-database-rls-enforcement.test.mjs", "backend/prisma/migrations"],
  };
  return manifest;
};

const applyObjectOwnershipAuthority = (manifest, tables, identities, decisions) => {
  const runtimeIds = identities.identities.filter((identity) => identity.loginExpectation !== "NOLOGIN").map((identity) => identity.id);
  for (const identity of identities.identities) {
    identity.mayOwnProtectedObjects = ["identity-table-owner", "identity-auth-function-owner"].includes(identity.id);
    identity.ownerRoleMemberships = [];
    identity.objectOwnershipDecision = "decision-object-ownership-chain";
    if (runtimeIds.includes(identity.id)) identity.protectedObjectOwnershipAllowed = false;
  }
  const tableOwner = identities.identities.find((identity) => identity.id === "identity-table-owner");
  Object.assign(tableOwner, { roleAttributes: OWNER_ATTRIBUTES, ownedObjectClasses: ["tables", "sequences", "public/app_rls schemas", "indexes/constraints/policies/triggers through tables", "application types/views/materialized views", "approved app_rls SECURITY INVOKER functions"], mayOwnProtectedObjects: true });
  const authOwner = identities.identities.find((identity) => identity.id === "identity-auth-function-owner");
  Object.assign(authOwner, { roleAttributes: OWNER_ATTRIBUTES, ownedObjectClasses: ["app_auth schema", "exact approved pre-auth functions"], mayOwnProtectedObjects: true });
  const migration = identities.identities.find((identity) => identity.id === "identity-migration");
  Object.assign(migration, { maySetRole: false, enduringObjectOwnershipAllowed: false, temporaryOwnerMembershipRecommended: false, migrationCompletionRequiresCatalogVerification: true, ownerMembershipResidueAllowed: false });
  for (const identity of [tableOwner, authOwner, migration]) {
    identity.resolvedDecisions = [...new Set([...identity.resolvedDecisions, "decision-object-ownership-chain"])].sort();
    identity.unresolvedDecisions = identity.unresolvedDecisions.filter((id) => id !== "decision-object-ownership-chain");
  }
  for (const table of tables.tables) {
    table.physicalOwnerRole = "identity-table-owner";
    table.objectOwnershipRuleId = "ownership-tables";
    table.migrationOwnershipAllowedAtCompletion = false;
    table.ownershipTransferStatus = "architecture-resolved";
    table.unresolvedDecisionIds = table.unresolvedDecisionIds.filter((id) => id !== "decision-object-ownership-chain");
    table.unresolvedDecisions = table.unresolvedDecisions.filter((id) => id !== "decision-object-ownership-chain");
  }
  const decision = decisions.decisions.find((item) => item.id === "decision-object-ownership-chain");
  decision.status = "resolved";
  decision.resolvedAt = "2026-07-16";
  decision.affectedTables = tables.tables.map((table) => table.id);
  decision.resolution = { authority: "documents/security/rls-program/object-ownership-chain.json", protectedObjectClasses: manifest.objectClasses.length, tableOwner: "identity-table-owner", authOwner: "identity-auth-function-owner", migrationOwnershipResidueAllowed: 0, runtimeOwnershipAllowed: 0, recommendedTransferModel: manifest.recommendedTransferModel.id, catalogVerificationRequired: true };
};

const writeObjectOwnershipReview = (manifest) => {
  const lines = ["# MSCQR Object Ownership Review", "", "This is the human review of `object-ownership-chain.json`. It changes no database owner, role, grant, policy, RLS state, SQL artifact, or runtime behavior.", "", "## Role and object ownership matrix", "", "| Object class | Enduring owner | Creation identity | Transfer | Verification |", "|---|---|---|---|---|"];
  for (const rule of manifest.objectClasses) lines.push(`| ${rule.objectClass} | ${rule.expectedOwner} | ${rule.creationIdentity} | ${rule.transferMechanism} | ${rule.postTransferVerification} |`);
  lines.push("", "## Migration lifecycle", "");
  for (const step of manifest.migrationLifecycle) lines.push(`${step.step}. **${step.id}:** ${step.requirement}`);
  lines.push("", "## Temporary authority model", "", "The approved clean-room path separates zero-based Prisma DDL from ownership transfer. The restricted migration credential never receives owner membership while migrations run. In the later brokered administrative transaction, the administrator temporarily gives `identity-migration` one target-owner membership with `ADMIN FALSE`, `INHERIT FALSE`, `SET TRUE`, assumes the migration owner of the new objects, transfers the exact allowlisted objects, and revokes the membership before commit. There is no fallback transfer path and success requires zero membership and ownership residue.", "", "## Schema, sequence, type, function and policy ownership", "", "`public` and `app_rls` belong to the table owner; `app_auth` belongs to the auth owner. PUBLIC and runtime CREATE are denied. Prisma-created application schemas must be declared and table-owner owned. Extension schemas remain with the allowlisted managed extension owner. Table-owned and standalone application sequences, enums, composite types, views and materialized views use the table owner. Indexes, constraints, policies and triggers follow the owning table; called functions are verified independently.", "", `The seven approved pre-auth functions are auth-owner SECURITY DEFINER functions. The ${manifest.approvedFunctionOwnerBoundaries.worker.length} approved worker helpers are table-owner SECURITY INVOKER functions. Policies have no independent PostgreSQL owner: their authority follows the table owner.`, "", "## Default privileges", "", "Every possible creator—migration, table owner and auth owner—has explicit future-object defaults. PUBLIC receives no application-object privilege; runtime roles receive no default table, sequence, schema, type or routine access. Exact runtime grants come only from command semantics after transfer.", "", "## Failure, rollback and catalog verification", "", "Installation is permitted only in a fresh green database on isolated green infrastructure. Preflight refuses any application object, managed role, unexpected grant, policy, membership or default ACL. A failed candidate is not repaired in place: stop and disconnect green consumers, prove no required data was accepted, drop the green database, drop only exact package-marked roles, and keep or restore traffic to the untouched blue database.", "", "Catalog certification covers all 77 tables (75 FORCE targets plus two migration-only tables), sequences/dependencies, schemas/CREATE ACLs, exact function owners/security modes/EXECUTE ACLs, types, owner membership closure, default ACLs and optional publications/subscriptions/extensions. Migration, runtime and environment-admin LOGIN ownership must all be zero.", "", "## Environment differences", "", "The contract is identical in development, staging and production; only the `mscqr_dev_*`, `mscqr_staging_*` and `mscqr_prod_*` role names differ. Green must use a separate PostgreSQL cluster or instance because roles are cluster-wide and all managed names must be absent before apply. The current blue database and its roles are never mutation targets.", "", "## Certification status", "", "The clean-room generator, exact catalog verifier, failure-injection harness and role-marker cleanup package implement this ownership model. Application-path workflow certification and green staging activation remain separate gates.", "");
  fs.writeFileSync(objectOwnershipReviewPath, `${lines.join("\n")}\n`);
};

export const buildObjectOwnershipProgramme = () => {
  const tables = readJson(tableManifestPath);
  const identities = readJson(identityManifestPath);
  const decisions = readJson(decisionManifestPath);
  const manifest = buildObjectOwnershipManifest(tables, identities, readJson(preAuthFunctionsPath), readJson(workerBoundariesPath));
  applyObjectOwnershipAuthority(manifest, tables, identities, decisions);
  writeJson(objectOwnershipChainPath, manifest);
  writeObjectOwnershipReview(manifest);
  writeJson(tableManifestPath, tables);
  writeJson(identityManifestPath, identities);
  writeJson(decisionManifestPath, decisions);
  return manifest;
};

const OPERATOR_ACTION_CLASSES = Object.freeze(["read-diagnostics", "catalog-verification", "deployment-preflight", "migration-broker", "credential-rotation", "account-recovery", "mfa-repair", "session-revocation", "tenant-security-recovery", "incident-containment", "data-retention-redaction", "job-recovery", "RLS-readiness-check", "RLS-activation-control", "RLS-rollback-control", "break-glass-only", "prohibited"]);
const OPERATOR_SECRET_COLUMNS = Object.freeze(["passwordHash", "tokenHash", "secret", "privateKey", "credentialPublicKey", "backupCodeHash", "platform-admin flags", "tenant ownership columns", "audit actor identity"]);
const operatorWorkflowBoundaryId = (workflowId) => workflowId.includes("break-glass-mfa-reset") ? "operator-boundary-breakglass-mfa-repair"
  : workflowId.includes("repair-admin-accounts") ? "operator-boundary-prohibited-platform-role-repair"
  : workflowId.includes("resend-password-setup-link") ? "operator-boundary-account-setup-link-reissue"
  : workflowId.includes("mscqr-print-test") ? "operator-boundary-print-diagnostic"
  : workflowId.includes("seed-staging-rls-validation-data") ? "operator-boundary-staging-rls-fixture"
  : workflowId.includes("run-system-integration") ? "operator-boundary-prohibited-audit-browser"
  : "operator-boundary-prohibited-seed-and-test-data";

const operatorBoundary = (id, actionClass, environmentAvailability, actorClass, exactCommandOrNamedProcedure, overrides = {}) => ({
  id,
  actionClass,
  environmentAvailability,
  actorClass,
  runtimeIdentity: actorClass === "break-glass" ? "identity-production-break-glass" : "identity-operator",
  exactCommandOrNamedProcedure,
  acceptedArguments: [],
  returnedFields: ["operation_id", "status", "affected_count", "audit_event_id"],
  targetSchemas: exactCommandOrNamedProcedure.kind === "named-procedure" ? ["app_ops"] : [],
  targetTables: [],
  targetFunctions: exactCommandOrNamedProcedure.kind === "named-procedure" ? [exactCommandOrNamedProcedure.identifier] : [],
  requiredAssurance: actorClass === "break-glass" ? "dual-approved-break-glass" : "operator-approved",
  approvalRequirement: { required: !["read-diagnostics", "catalog-verification", "prohibited"].includes(actionClass), distinctApprovers: actorClass === "break-glass" ? 2 : 1 },
  approvalClass: actorClass === "break-glass" ? "dual-approved-break-glass" : actionClass === "prohibited" ? "not-applicable-denied" : "operator-change-approval",
  ticketRequirement: environmentAvailability.includes("production"),
  purposeRequirement: true,
  maximumDurationMinutes: actorClass === "break-glass" ? 30 : 60,
  maximumRowScope: "one exact target or one bounded metadata page of at most 100 rows",
  tenantScopeRequirement: "Exact tenant/account/object identifier must be bound to approved server evidence; global scope is denied unless this boundary explicitly describes catalog-only metadata.",
  allowedColumns: [],
  prohibitedColumns: [...OPERATOR_SECRET_COLUMNS],
  transactionBehavior: "One transaction for validation, mutation, immutable audit and result; failure rolls back business mutation while preserving broker failure evidence.",
  auditEventRequirement: { required: true, immutable: true, fields: ["operator_actor", "runtime_identity", "ticket_id", "approval_id", "purpose", "target", "before_digest", "after_digest", "result", "started_at", "completed_at"] },
  beforeAfterEvidence: true,
  expiryBehavior: "The command authorization expires at maximumDurationMinutes or earlier completion; stale approvals and credentials are rejected.",
  revocationBehavior: "Broker authorization is revoked on completion, failure, approval withdrawal or expiry and absence is verified.",
  retrySemantics: "Retry uses the same operation/idempotency key; a conflicting target or payload is denied and a completed result is returned without repeating side effects.",
  allowScenarios: ["The exact allowlisted command runs with verified actor, assurance, environment, approval, ticket/purpose, target scope and unexpired authorization."],
  denyScenarios: ["Arbitrary SQL, missing or stale evidence, shared identity, foreign target, excessive rows, protected-column output, role/tenant elevation or owner reachability is denied."],
  implementationStatus: actionClass === "prohibited" ? "prohibited" : "contract-only-not-implemented",
  certificationTests: ["Exact allow case", "Wrong environment and target denial", "Expired/missing approval denial", "Secret-output redaction", "Ownership/SET ROLE/BYPASSRLS denial", "Audit and retry proof"],
  workflowIds: [],
  exactCommandRuleIds: [],
  arbitrarySqlAllowed: false,
  objectOwnershipAllowed: false,
  ownerRoleMembershipAllowed: false,
  setRoleAllowed: false,
  bypassRlsAllowed: false,
  superuserAllowed: false,
  applicationImpersonationAllowed: false,
  unrestrictedCrossTenantScope: false,
  schemaCreateAllowed: false,
  migrationAuthorityAllowed: actionClass === "migration-broker",
  roleElevationAllowed: false,
  tenantReassignmentAllowed: false,
  auditDeletionAllowed: false,
  secretOutputAllowed: false,
  sharedCredentialAllowed: false,
  automaticRevocation: true,
  ...overrides,
});

export const buildOperatorBoundaryManifest = (workflowManifest, commandManifest) => {
  const proc = (identifier, signature) => ({ kind: "named-procedure", identifier, signature, arbitraryArgumentsAllowed: false });
  const command = (identifier, syntax) => ({ kind: "operator-command", identifier, syntax, arbitraryArgumentsAllowed: false });
  const denied = (identifier) => ({ kind: "prohibited", identifier, syntax: "No executable command", arbitraryArgumentsAllowed: false });
  const boundaries = [
    operatorBoundary("operator-boundary-catalog-verification", "catalog-verification", ["development", "staging", "production"], "operator-admin", proc("app_ops.catalog_verification", "app_ops.catalog_verification(environment text, release_sha text, manifest_digest text)"), { acceptedArguments: ["environment", "release_sha", "manifest_digest"], returnedFields: ["object_class", "object_identity", "expected_owner", "actual_owner", "rls_enabled", "force_rls", "grant_status", "membership_status"], maximumRowScope: "catalog metadata for the exact programme manifest only", tenantScopeRequirement: "not-applicable: catalog metadata only", approvalRequirement: { required: false, distinctApprovers: 0 }, beforeAfterEvidence: false }),
    operatorBoundary("operator-boundary-health-readiness", "read-diagnostics", ["development", "staging", "production"], "operator-admin", proc("app_ops.health_readiness", "app_ops.health_readiness(component text)"), { acceptedArguments: ["component allowlist"], returnedFields: ["component", "status", "checked_at", "redacted_reason_code"], maximumRowScope: "one allowlisted component", tenantScopeRequirement: "not-applicable: redacted aggregate health", approvalRequirement: { required: false, distinctApprovers: 0 }, beforeAfterEvidence: false }),
    operatorBoundary("operator-boundary-failed-job-summary", "read-diagnostics", ["development", "staging", "production"], "operator-admin", proc("app_ops.failed_job_summary", "app_ops.failed_job_summary(job_type text, tenant_id uuid, page_size integer)"), { acceptedArguments: ["allowlisted job_type", "exact tenant_id", "page_size 1..100"], returnedFields: ["job_id", "job_type", "tenant_id", "state", "attempt_count", "last_error_code", "updated_at"], maximumRowScope: "100 rows within one tenant and job type", tenantScopeRequirement: "exact tenant required", approvalRequirement: { required: false, distinctApprovers: 0 }, beforeAfterEvidence: false }),
    operatorBoundary("operator-boundary-tenant-incident-summary", "read-diagnostics", ["development", "staging", "production"], "operator-admin", proc("app_ops.tenant_incident_summary", "app_ops.tenant_incident_summary(tenant_id uuid, incident_id uuid, page_size integer)"), { acceptedArguments: ["exact tenant_id", "exact incident_id", "page_size 1..100"], returnedFields: ["incident_id", "tenant_id", "status", "severity", "event_type", "created_at", "redacted_summary"], maximumRowScope: "one incident and at most 100 redacted events", tenantScopeRequirement: "exact tenant and incident binding required", approvalRequirement: { required: false, distinctApprovers: 0 }, beforeAfterEvidence: false }),
    operatorBoundary("operator-boundary-print-diagnostic", "read-diagnostics", ["development", "staging"], "operator-admin", proc("app_ops.print_diagnostic", "app_ops.print_diagnostic(batch_id uuid)"), { acceptedArguments: ["exact batch_id"], returnedFields: ["batch_id", "print_job_id", "print_state", "item_counts", "redacted_failure_codes"], targetTables: ["table-batch", "table-print-item", "table-qrcode"], maximumRowScope: "one batch aggregate; no QR payload rows", tenantScopeRequirement: "batch tenant derived and verified", approvalRequirement: { required: false, distinctApprovers: 0 }, beforeAfterEvidence: false }),
    operatorBoundary("operator-boundary-deployment-preflight", "deployment-preflight", ["development", "staging", "production"], "operator-admin", command("mscqr-operator deployment-preflight", "mscqr-operator deployment-preflight --environment <exact> --release-sha <sha> --migration-set-digest <sha256> --baseline-digest <sha256> --approval-id <id>"), { acceptedArguments: ["environment", "release_sha", "migration_set_digest", "baseline_digest", "approval_id"], returnedFields: ["preflight_id", "environment", "release_sha", "checks", "ready", "expires_at"], maximumRowScope: "catalog and release metadata only", tenantScopeRequirement: "not-applicable: deployment metadata only" }),
    operatorBoundary("operator-boundary-migration-broker", "migration-broker", ["development", "staging", "production"], "operator-admin", command("mscqr-operator migration-broker", "mscqr-operator migration-broker --environment <exact> --migration-id <id> --checksum <sha256> --release-sha <sha> --preflight-id <id> --approval-id <id> --ticket-id <id> --purpose <text>"), { acceptedArguments: ["environment", "migration_id", "checksum", "release_sha", "preflight_id", "approval_id", "ticket_id", "purpose"], returnedFields: ["operation_id", "migration_id", "transfer_status", "revocation_status", "catalog_verification_status", "transcript_digest"], maximumRowScope: "exact reviewed migration object set", tenantScopeRequirement: "not-applicable: object manifest scope", transactionBehavior: "Follow object-ownership-chain.json: preflight, reviewed DDL, per-object transfer, grant normalization, unconditional revocation and catalog gate; any residue fails closed.", migrationAuthorityAllowed: false }),
    operatorBoundary("operator-boundary-credential-rotation", "credential-rotation", ["development", "staging", "production"], "operator-admin", command("mscqr-operator rotate-runtime-credential", "mscqr-operator rotate-runtime-credential --environment <exact> --identity <allowlisted> --rotation-id <id> --approval-id <id> --ticket-id <id> --purpose <text>"), { acceptedArguments: ["environment", "allowlisted runtime identity", "rotation_id", "approval_id", "ticket_id", "purpose"], returnedFields: ["rotation_id", "identity", "consumer_count", "verification_status", "old_credential_revoked"], maximumRowScope: "one runtime identity credential and its registered consumers", tenantScopeRequirement: "not-applicable: credential metadata; secret values never returned" }),
    operatorBoundary("operator-boundary-account-setup-link-reissue", "account-recovery", ["development", "staging", "production"], "operator-admin", proc("app_ops.reissue_account_setup_link", "app_ops.reissue_account_setup_link(target_user_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_user_id", "operator_id", "approved reason", "approval_id"], returnedFields: ["operation_id", "delivery_queued", "audit_event_id"], targetTables: ["table-user", "table-invite", "table-password-reset"], allowedColumns: ["one-time token issuance metadata", "expiry", "consumed state", "delivery state"], maximumRowScope: "one existing account", tenantScopeRequirement: "target tenant is immutable and operator scope must cover it" }),
    operatorBoundary("operator-boundary-locked-account-recovery", "account-recovery", ["development", "staging", "production"], "operator-admin", proc("app_ops.recover_locked_account", "app_ops.recover_locked_account(target_user_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_user_id", "operator_id", "approved reason", "approval_id"], targetTables: ["table-user", "table-refresh-token"], allowedColumns: ["failedLoginAttempts", "lockedUntil", "session revocation state"], maximumRowScope: "one exact account", tenantScopeRequirement: "target tenant is immutable and operator scope must cover it" }),
    operatorBoundary("operator-boundary-operator-mfa-repair", "mfa-repair", ["development", "staging"], "operator-admin", proc("app_ops.reset_account_mfa", "app_ops.reset_account_mfa(target_user_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_user_id", "operator_id", "approved reason", "approval_id"], targetTables: ["table-user", "table-admin-mfa-credential", "table-admin-web-authn-credential", "table-user-mfa-factor", "table-user-backup-code", "table-refresh-token"], allowedColumns: ["MFA disabled/reset state", "credential revocation state", "session revocation state"], maximumRowScope: "one exact account", tenantScopeRequirement: "target tenant and role are immutable; maker/checker must differ" }),
    operatorBoundary("operator-boundary-breakglass-mfa-repair", "mfa-repair", ["production"], "break-glass", proc("app_ops.reset_account_mfa", "app_ops.reset_account_mfa(target_user_id uuid, executor_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_user_id", "ephemeral executor_id", "incident reason", "dual approval_id"], targetTables: ["table-user", "table-admin-mfa-credential", "table-admin-web-authn-credential", "table-user-mfa-factor", "table-user-backup-code", "table-refresh-token"], allowedColumns: ["MFA disabled/reset state", "credential revocation state", "session revocation state"], maximumRowScope: "one exact account", tenantScopeRequirement: "account binding fixed before credential issuance; role and tenant immutable", maximumDurationMinutes: 30 }),
    operatorBoundary("operator-boundary-session-revocation", "session-revocation", ["development", "staging", "production"], "operator-admin", proc("app_ops.revoke_account_sessions", "app_ops.revoke_account_sessions(target_user_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_user_id", "operator_id", "approved reason", "approval_id"], targetTables: ["table-refresh-token"], allowedColumns: ["revokedAt", "revocationReason"], maximumRowScope: "all sessions for one exact account", tenantScopeRequirement: "target account tenant must be verified" }),
    operatorBoundary("operator-boundary-tenant-security-recovery", "tenant-security-recovery", ["development", "staging", "production"], "operator-admin", proc("app_ops.recover_tenant_security_state", "app_ops.recover_tenant_security_state(tenant_id uuid, recovery_case_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["tenant_id", "recovery_case_id", "operator_id", "approved reason", "approval_id"], targetTables: ["table-organization", "table-licensee", "table-manufacturer-licensee-link"], allowedColumns: ["approved suspension/recovery state only"], maximumRowScope: "one tenant root and explicitly enumerated access links", tenantScopeRequirement: "one exact tenant root; ownership columns immutable" }),
    operatorBoundary("operator-boundary-contain-user", "incident-containment", ["development", "staging", "production"], "operator-admin", proc("app_ops.contain_user", "app_ops.contain_user(user_id uuid, incident_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["user_id", "incident_id", "operator_id", "reason", "approval_id"], targetTables: ["table-user", "table-refresh-token"], allowedColumns: ["disabled/security status", "session revocation state"], maximumRowScope: "one exact user and that user's sessions", tenantScopeRequirement: "incident tenant must match user tenant" }),
    operatorBoundary("operator-boundary-contain-tenant", "incident-containment", ["development", "staging", "production"], "operator-admin", proc("app_ops.contain_tenant_access", "app_ops.contain_tenant_access(tenant_id uuid, incident_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["tenant_id", "incident_id", "operator_id", "reason", "approval_id"], targetTables: ["table-organization", "table-licensee", "table-manufacturer-licensee-link"], allowedColumns: ["approved suspension state"], maximumRowScope: "one tenant and its enumerated access links", tenantScopeRequirement: "one exact tenant; ownership columns immutable" }),
    operatorBoundary("operator-boundary-contain-qr-batch", "incident-containment", ["development", "staging", "production"], "operator-admin", proc("app_ops.contain_qr_or_batch", "app_ops.contain_qr_or_batch(target_kind text, target_id uuid, incident_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["target_kind enum QR|BATCH", "target_id", "incident_id", "operator_id", "reason", "approval_id"], targetTables: ["table-batch", "table-qrcode"], allowedColumns: ["supported FAILED/VOIDED/blocked state only"], maximumRowScope: "one batch or one QR identity; released identity fields remain immutable", tenantScopeRequirement: "incident tenant must match target tenant" }),
    operatorBoundary("operator-boundary-contain-job-type", "incident-containment", ["development", "staging", "production"], "operator-admin", proc("app_ops.contain_job_type", "app_ops.contain_job_type(job_type text, tenant_id uuid, incident_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["allowlisted job_type", "tenant_id or approved platform scope", "incident_id", "operator_id", "reason", "approval_id"], targetTables: ["table-compliance-pack-job", "table-evidence-retention-job", "table-audit-log-outbox", "table-security-event-outbox"], allowedColumns: ["paused/failed claim state"], maximumRowScope: "one allowlisted job type and one tenant; platform scope requires explicit platform approval", tenantScopeRequirement: "exact tenant unless separately approved platform incident" }),
    operatorBoundary("operator-boundary-contain-credential", "incident-containment", ["development", "staging", "production"], "operator-admin", proc("app_ops.suspend_credential", "app_ops.suspend_credential(credential_kind text, credential_id uuid, incident_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["allowlisted credential_kind", "credential_id", "incident_id", "operator_id", "reason", "approval_id"], targetTables: ["table-printer-registration", "table-printer-agent-session", "table-customer-trust-credential", "table-admin-web-authn-credential"], allowedColumns: ["revocation/suspension state", "revokedAt"], maximumRowScope: "one exact credential or connector", tenantScopeRequirement: "credential tenant/actor must match incident scope" }),
    operatorBoundary("operator-boundary-retention-redaction", "data-retention-redaction", ["development", "staging", "production"], "operator-admin", proc("app_ops.redact_retained_evidence", "app_ops.redact_retained_evidence(evidence_id uuid, retention_case_id uuid, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["evidence_id", "retention_case_id", "operator_id", "reason", "approval_id"], targetTables: ["table-incident-evidence", "table-audit-log"], allowedColumns: ["approved redaction projection only"], maximumRowScope: "one evidence object; immutable audit record is appended, never deleted", tenantScopeRequirement: "retention case tenant and legal-hold state must match" }),
    operatorBoundary("operator-boundary-job-recovery", "job-recovery", ["development", "staging", "production"], "operator-admin", proc("app_ops.recover_failed_job", "app_ops.recover_failed_job(job_id uuid, expected_state text, operator_id uuid, reason text, approval_id uuid)"), { acceptedArguments: ["job_id", "exact expected_state", "operator_id", "reason", "approval_id"], targetTables: ["table-compliance-pack-job", "table-evidence-retention-job", "table-audit-log-outbox", "table-security-event-outbox"], allowedColumns: ["retry/claim state", "attempt metadata"], maximumRowScope: "one failed durable job", tenantScopeRequirement: "job durable tenant scope is reverified" }),
    operatorBoundary("operator-boundary-staging-rls-fixture", "RLS-readiness-check", ["staging"], "operator-admin", proc("app_ops.prepare_rls_validation_fixture", "app_ops.prepare_rls_validation_fixture(fixture_id uuid, tenant_key text, approval_id uuid)"), { acceptedArguments: ["fixture_id", "reserved tenant_key", "approval_id"], targetTables: ["table-organization", "table-licensee", "table-manufacturer-licensee-link", "table-user", "table-qrrange", "table-batch", "table-qrcode"], allowedColumns: ["fixed synthetic fixture columns from the reviewed fixture manifest"], maximumRowScope: "one reserved synthetic tenant fixture with bounded QR count", tenantScopeRequirement: "reserved staging-only fixture tenant; production denied" }),
    operatorBoundary("operator-boundary-rls-readiness", "RLS-readiness-check", ["development", "staging", "production"], "operator-admin", command("mscqr-operator rls-readiness", "mscqr-operator rls-readiness --environment <exact> --release-sha <sha> --policy-digest <sha256> --grant-digest <sha256> --role-digest <sha256> --baseline-digest <sha256>"), { acceptedArguments: ["environment", "release_sha", "policy_digest", "grant_digest", "role_digest", "baseline_digest"], returnedFields: ["readiness_id", "checks", "catalog_baseline_digest", "ready", "expires_at"], maximumRowScope: "catalog metadata and bounded canary assertions only", tenantScopeRequirement: "canary uses approved synthetic tenant; no business payload output" }),
    operatorBoundary("operator-boundary-rls-activation", "RLS-activation-control", ["staging", "production"], "operator-admin", command("mscqr-operator rls-activate", "mscqr-operator rls-activate --environment <exact> --release-sha <sha> --migration-set-digest <sha256> --catalog-baseline-digest <sha256> --readiness-id <id> --approval-id <id> --ticket-id <id> --window-id <id> --checker-id <id> --rollback-digest <sha256>"), { acceptedArguments: ["environment", "release_sha", "migration_set_digest", "catalog_baseline_digest", "readiness_id", "approval_id", "ticket_id", "window_id", "independent checker_id", "rollback_digest", "staging_evidence_digest for production"], returnedFields: ["activation_id", "green_database_id", "blue_rollback_target_id", "phase", "table_set_digest", "canary_status", "post_catalog_digest", "rollback_ready"], maximumRowScope: "one checksum-bound green build and traffic switch; blue database mutation is prohibited", tenantScopeRequirement: "approved synthetic canary tenants only; operator receives no policy bypass", deploymentModel: "clean-room-blue-green", blueDatabaseMutationAllowed: false, rollbackBoundaryId: "operator-boundary-rls-rollback", productionRequirements: { stagingEvidenceRequired: true, exactReleaseBindingRequired: true, exactMigrationSetRequired: true, currentCatalogBaselineRequired: true, approvalRecordRequired: true, rollbackArtifactRequired: true, maintenanceWindowRequired: true, independentCheckerRequired: true, postActivationVerificationRequired: true } }),
    operatorBoundary("operator-boundary-rls-rollback", "RLS-rollback-control", ["staging", "production"], "operator-admin", command("mscqr-operator rls-rollback", "mscqr-operator rls-rollback --environment <exact> --activation-id <id> --release-sha <sha> --rollback-digest <sha256> --approval-id <id> --ticket-id <id> --purpose <text>"), { acceptedArguments: ["environment", "activation_id", "release_sha", "rollback_digest", "approval_id", "ticket_id", "purpose"], returnedFields: ["rollback_id", "blue_switch_status", "green_database_absent", "managed_role_residue_count", "blue_fingerprint_unchanged", "post_rollback_digest"], maximumRowScope: "one recorded green database and its exact package-marked roles only", tenantScopeRequirement: "no required data accepted; blue is the immutable rollback target", deploymentModel: "clean-room-blue-green", blueDatabaseMutationAllowed: false, pairedActivationBoundaryId: "operator-boundary-rls-activation" }),
    operatorBoundary("operator-boundary-breakglass-issuance", "break-glass-only", ["production"], "break-glass", command("mscqr-security-broker issue-breakglass", "mscqr-security-broker issue-breakglass --incident-id <id> --ticket-id <id> --purpose <text> --approver-one <id> --approver-two <id> --boundary-ids <allowlist> --ttl-minutes <1..30>"), { acceptedArguments: ["incident_id", "ticket_id", "purpose", "two distinct approver identities", "exact boundary allowlist", "ttl 1..30 minutes"], returnedFields: ["ephemeral_identity", "credential_handle", "expires_at", "allowlist_digest", "audit_transcript_id"], maximumRowScope: "only targets permitted by the issued boundary allowlist", tenantScopeRequirement: "each issued command retains exact target/tenant binding", maximumDurationMinutes: 30, lifecycle: ["incident declared", "ticket created", "two distinct approvers approve", "broker creates individually attributable ephemeral credential", "exact boundary allowlist attached", "expiry fixed at no more than 30 minutes", "every command records actor/ticket/purpose/result", "automatic revocation at expiry", "early revocation remains available", "post-use catalog and data audit", "credential and memberships verified absent"] }),
    operatorBoundary("operator-boundary-prohibited-platform-role-repair", "prohibited", ["development", "staging", "production"], "break-glass", denied("backend/scripts/repair-admin-accounts.js"), { maximumDurationMinutes: 0, maximumRowScope: "zero rows", approvalRequirement: { required: false, distinctApprovers: 0 }, ticketRequirement: false, automaticRevocation: true, denyScenarios: ["Direct creation, promotion or repair of platform administrators is not an approved operator or break-glass action; use reviewed application governance or a future exact maker/checker procedure."], transactionBehavior: "No execution is authorized." }),
    operatorBoundary("operator-boundary-prohibited-seed-and-test-data", "prohibited", ["development", "staging", "production"], "operator-admin", denied("registered Prisma/enterprise/launch-smoke seed and QR-reset workflows"), { maximumDurationMinutes: 0, maximumRowScope: "zero rows", approvalRequirement: { required: false, distinctApprovers: 0 }, ticketRequirement: false, automaticRevocation: true, denyScenarios: ["Generic seed, upsert, delete or test-data mutation is not operator administration. Local disposable development may use test credentials outside protected environment roles."], transactionBehavior: "No execution is authorized against protected environments." }),
    operatorBoundary("operator-boundary-prohibited-audit-browser", "prohibited", ["development", "staging", "production"], "operator-admin", denied("scripts/run-system-integration.mjs direct AuditLog SELECT"), { maximumDurationMinutes: 0, maximumRowScope: "zero rows", approvalRequirement: { required: false, distinctApprovers: 0 }, ticketRequirement: false, automaticRevocation: true, denyScenarios: ["Unrestricted audit-log browsing is denied; use exact redacted incident or catalog diagnostics."], transactionBehavior: "No execution is authorized." }),
  ];
  const selectedWorkflows = workflowManifest.workflows.filter((workflow) => workflow.commandActorClasses?.some((actor) => ["operator-admin", "break-glass"].includes(actor)));
  for (const workflow of selectedWorkflows) {
    const boundaryId = operatorWorkflowBoundaryId(workflow.id);
    const boundary = boundaries.find((item) => item.id === boundaryId);
    assert(boundary, `${workflow.id} lacks an operator boundary definition`);
    boundary.workflowIds.push(workflow.id);
    workflow.operatorBoundaryId = boundaryId;
    workflow.operatorBoundaryStatus = "resolved";
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== "decision-operator-administration");
    workflow.authorizationBoundaryType = boundary.actorClass === "break-glass" ? "operator-break-glass" : "unresolved";
    workflow.runtimeIdentities = [boundary.runtimeIdentity];
  }
  for (const rule of commandManifest.rules.filter((rule) => rule.actorClasses.some((actor) => ["operator-admin", "break-glass"].includes(actor)))) {
    const boundaryIds = [...new Set(rule.supportingWorkflowIds.filter((id) => selectedWorkflows.some((workflow) => workflow.id === id)).map(operatorWorkflowBoundaryId))].sort();
    assert(boundaryIds.length, `${rule.id} operator rule lacks registration-backed boundary evidence`);
    rule.operatorBoundaryIds = boundaryIds;
    rule.operatorBoundaryStatus = "resolved";
    rule.runtimeIdentities = rule.actorClasses.includes("break-glass") ? ["identity-production-break-glass"] : ["identity-operator"];
    for (const boundaryId of boundaryIds) boundaries.find((boundary) => boundary.id === boundaryId).exactCommandRuleIds.push(rule.id);
  }
  for (const boundary of boundaries) boundary.exactCommandRuleIds = [...new Set(boundary.exactCommandRuleIds)].sort();
  return { schemaVersion: 1, decisionId: "decision-operator-administration", status: "architecture-resolved", actionClasses: OPERATOR_ACTION_CLASSES, maximumBreakGlassLifetimeMinutes: 30, identities: { operator: "identity-operator", breakGlass: "identity-production-break-glass" }, arbitrarySqlAllowed: false, prohibitedActions: ["arbitrary SQL execution", "ownership changes outside the migration broker", "role membership changes outside the approved broker", "disabling FORCE RLS without the paired rollback control", "granting BYPASSRLS or superuser", "direct platform-admin flag changes", "tenant ownership changes", "credential or token hash exposure", "audit evidence deletion or attribution clearing", "unbounded cross-tenant SELECT", "permanent or shared break-glass credentials"], boundaries, supportingEvidence: ["documents/security/rls-program/object-ownership-chain.json", "documents/ops/MSCQR_STAGING_DATABASE_ROLE_CREDENTIALS_AND_CUTOVER_RUNBOOK_2026-07-10.md", "documents/ops/MSCQR_RLS_PRODUCTION_ROLLOUT_CHECKLIST_2026-06-30.md", "backend/scripts/break-glass-mfa-reset.ts", "backend/scripts/resend-password-setup-link.js", "backend/scripts/repair-admin-accounts.js"] };
};

const applyOperatorAuthority = (manifest, workflows, commandSemantics, tables, identities, decisions) => {
  const replaceIdentity = (value) => value === "identity-staging-operator-admin" ? "identity-operator" : value;
  const operator = identities.identities.find((identity) => identity.id === "identity-staging-operator-admin" || identity.id === "identity-operator");
  operator.id = "identity-operator";
  Object.assign(operator, { logicalIdentity: "operator administrator", purpose: "Standing restricted administrative login for exact broker commands and named procedures only.", tablePrivilegeMode: "no direct table privileges; exact procedure/command execution only", allowedSchemas: ["app_ops"], allowedCommands: ["CONNECT", "USAGE", "EXECUTE_EXACT_OPERATOR_BOUNDARIES"], ownershipExpectations: "Owns no object and has no owner-role membership.", mayOwnProtectedTables: false, mayOwnProtectedObjects: false, protectedObjectOwnershipAllowed: false, ownerRoleMemberships: [], mayCreateObjects: false, maySetRole: false, mayUseBypassRls: false, superuser: false, credentialSource: "dedicated-managed-operator-credential-per-environment-with-individual-attribution", standingCredential: true, rotationExpectation: "Managed rotation at least every 90 days and immediate rotation on compromise or personnel change; command approvals remain short-lived.", approvedOperatorBoundaryIds: manifest.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-operator" && boundary.actionClass !== "prohibited").map((boundary) => boundary.id), directTablePrivileges: [], unrestrictedSqlAllowed: false, applicationImpersonationAllowed: false, schemaCreateAllowed: false, migrationAuthorityAllowed: false });
  const breakGlass = identities.identities.find((identity) => identity.id === "identity-production-break-glass");
  Object.assign(breakGlass, { approvedOperatorBoundaryIds: manifest.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-production-break-glass" && boundary.actionClass !== "prohibited").map((boundary) => boundary.id), maximumLifetimeMinutes: manifest.maximumBreakGlassLifetimeMinutes, individuallyAttributable: true, sharedCredential: false, automaticRevocation: true, unrestrictedSqlAllowed: false, directTablePrivileges: [], ownerRoleMemberships: [], applicationImpersonationAllowed: false });
  for (const identity of [operator, breakGlass]) {
    identity.resolvedDecisions = [...new Set([...identity.resolvedDecisions, "decision-operator-administration"])].sort();
    identity.unresolvedDecisions = identity.unresolvedDecisions.filter((id) => id !== "decision-operator-administration");
  }
  for (const table of tables.tables) {
    table.allowedRuntimeReaders = table.allowedRuntimeReaders.map(replaceIdentity);
    table.allowedRuntimeWriters = table.allowedRuntimeWriters.map(replaceIdentity);
    table.intendedDatabaseRoles = table.intendedDatabaseRoles.map(replaceIdentity);
    for (const entry of table.allowedCommandsByIdentity) entry.identityId = replaceIdentity(entry.identityId);
  }
  for (const workflow of workflows.workflows) workflow.runtimeIdentities = workflow.runtimeIdentities.map(replaceIdentity);
  for (const rule of commandSemantics.rules) rule.runtimeIdentities = rule.runtimeIdentities.map(replaceIdentity);
  const decision = decisions.decisions.find((item) => item.id === "decision-operator-administration");
  decision.status = "resolved";
  decision.resolvedAt = "2026-07-16";
  decision.affectedWorkflows = manifest.boundaries.flatMap((boundary) => boundary.workflowIds).sort();
  decision.affectedTables = [...new Set(manifest.boundaries.flatMap((boundary) => boundary.targetTables))].sort();
  decision.resolution = { authority: "documents/security/rls-program/operator-boundaries.json", boundaries: manifest.boundaries.length, selectedWorkflows: decision.affectedWorkflows.length, selectedCommandRules: commandSemantics.rules.filter((rule) => rule.operatorBoundaryIds?.length).length, maximumBreakGlassLifetimeMinutes: manifest.maximumBreakGlassLifetimeMinutes, arbitrarySqlAllowed: false, ownershipOrBypassAllowed: false };
};

const writeOperatorAdministrationReview = (manifest) => {
  const lines = ["# MSCQR Operator Administration Review", "", "This document reviews `operator-boundaries.json`. It creates no role, procedure, policy, grant, credential, infrastructure action, or runtime behavior.", "", "## Identity model and environment ceilings", "", "`identity-operator` is an individually attributable standing but restricted LOGIN named `mscqr_dev_operator`, `mscqr_staging_operator`, or `mscqr_prod_operator`. It owns nothing, has no owner membership, SET ROLE, superuser, BYPASSRLS, CREATE, migration credential, direct table privilege, application impersonation, broad visibility, or arbitrary SQL. Development may use disposable local actions but preserves the same forbidden capabilities. Staging may run exact activation, rollback, recovery and certification boundaries after evidence checks. Production additionally requires ticket, purpose, exact release/change binding, independent approval and immutable audit; staging success is never production approval.", "", "Production break-glass is an individually attributable broker-issued identity with two distinct approvers, strong MFA, incident/ticket/purpose, an exact boundary allowlist and a maximum 30-minute lifetime. It is neither shared nor standing and cannot become an owner, migrator, SQL shell or policy bypass.", "", "## Approved action classes", "", "| Boundary | Class | Environments | Identity | Exact command/procedure | Max scope |", "|---|---|---|---|---|---|"];
  for (const boundary of manifest.boundaries) lines.push(`| ${boundary.id} | ${boundary.actionClass} | ${boundary.environmentAvailability.join(", ")} | ${boundary.runtimeIdentity} | ${boundary.exactCommandOrNamedProcedure.identifier} | ${boundary.maximumRowScope} |`);
  lines.push("", "## Diagnostic model", "", "Catalog verification exposes only programme-scoped ownership, RLS/FORCE, policy, grant, membership and signature metadata. Health is aggregate and redacted. Failed jobs are limited to one tenant/job type and 100 rows. Incident inspection is limited to one tenant/incident and redacted events. Print diagnostics return one batch aggregate, never QR payload rows. Direct audit-log browsing and secret/user enumeration remain prohibited.", "", "## Migration broker", "", "The exact migration broker command binds environment, reviewed migration ID, checksum, release SHA, preflight, approval, ticket and purpose. It follows `object-ownership-chain.json`: per-object transfer, privilege normalization, unconditional revocation and catalog verification. The operator receives neither migration credentials nor owner membership; any ownership or membership residue fails closed.", "", "## Account, MFA and incident recovery", "", "Setup-link reissue, locked-account recovery, MFA reset and session revocation each target one account, preserve role and tenant, revoke relevant sessions, return no hashes, require reason/approval and append immutable audit evidence. Production MFA repair additionally requires the 30-minute dual-approved break-glass identity. Incident procedures separately scope one user, tenant, QR/batch, job type or credential; they cannot change ownership or platform-admin status.", "", "## RLS readiness, activation and rollback", "", "Readiness binds release, policy, grant, role and baseline digests. Activation is staging/production only and binds readiness, exact release/migrations/baseline, approval, ticket, maintenance window, independent checker and checksum-paired rollback. Production also requires staging evidence. The operator verifies through normal non-bypass authority. Rollback is a separate exact command paired to the activation ID and artifact; disabling FORCE outside it is prohibited.", "", "## Break-glass lifecycle", "");
  const lifecycle = manifest.boundaries.find((boundary) => boundary.id === "operator-boundary-breakglass-issuance").lifecycle;
  lifecycle.forEach((step, index) => lines.push(`${index + 1}. ${step}.`));
  lines.push("", "## Forbidden actions", "");
  for (const action of manifest.prohibitedActions) lines.push(`- ${action}.`);
  lines.push("", "## Audit requirements", "", "Every attempted action records the human actor, execution identity, ticket, approval, purpose, target, before/after digest, result, time bounds and revocation. Mutations are idempotent and transaction-bound; a conflicting retry is denied. Break-glass adds approvers, allowlist digest, credential lifecycle and post-use catalog/data audit.", "", "## Remaining implementation work", "", "Implement the exact `app_ops` procedures and operator/broker commands in later reviewed work, generate grants from this allowlist, retire prohibited scripts from protected runtime images, add disposable PostgreSQL certification and rehearse staged activation/rollback. This contract does not authorize execution.", "");
  fs.writeFileSync(operatorAdministrationReviewPath, `${lines.join("\n")}\n`);
};

export const buildOperatorProgramme = () => {
  const workflows = readJson(workflowManifestPath);
  const commandSemantics = readJson(commandSemanticsPath);
  const tables = readJson(tableManifestPath);
  const identities = readJson(identityManifestPath);
  const decisions = readJson(decisionManifestPath);
  const manifest = buildOperatorBoundaryManifest(workflows, commandSemantics);
  applyOperatorAuthority(manifest, workflows, commandSemantics, tables, identities, decisions);
  writeJson(operatorBoundariesPath, manifest);
  writeOperatorAdministrationReview(manifest);
  writeJson(workflowManifestPath, workflows);
  writeJson(commandSemanticsPath, commandSemantics);
  writeJson(tableManifestPath, tables);
  writeJson(identityManifestPath, identities);
  writeJson(decisionManifestPath, decisions);
  return manifest;
};

const MANUFACTURER_BOOTSTRAP_WORKFLOW_IDS = [
  "workflow-internal-backend-src-rls-waves-session-b-b01-authenticated-security-repository-ts-load-authenticated-manufacturer-scope",
];

const applyManufacturerBootstrapAuthority = (workflowManifest) => {
  const boundary = readJson(manufacturerBootstrapBoundaryPath);
  assert.equal(boundary.id, MANUFACTURER_BOOTSTRAP_BOUNDARY_ID, "manufacturer bootstrap boundary ID drifted");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const workflowId of MANUFACTURER_BOOTSTRAP_WORKFLOW_IDS) {
    const workflow = workflows.get(workflowId);
    assert(workflow, `manufacturer bootstrap references missing workflow ${workflowId}`);
    workflow.manufacturerBootstrapBoundaryId = boundary.id;
    workflow.authorizationBoundaryType = "authenticated-context";
    workflow.authenticationStage = "authenticated";
    workflow.tenantScopeRule = "Verified User.id establishes manufacturer actor scope; a ManufacturerLicenseeLink row plus active Licensee and Organization establishes one licensee scope. Client input only narrows the freshly verified set and blank never means all.";
    workflow.contextRequirementsSource = "human-reviewed";
    workflow.contextRequirements = [
      "post-password actor context with database User role",
      "transaction-local request attribution and purpose",
      "verified manufacturerId before membership read",
      "fresh relationship verification before tenant context",
    ];
    workflow.expectedAllowedScenarios = boundary.allowScenarios;
    workflow.expectedDeniedScenarios = boundary.denyScenarios;
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== boundary.decisionId);
    workflow.contextBoundaryBlockers = [];
    workflow.contextBoundaryStatus = "implemented";
    workflow.currentCompatibilityStatus = "compatible";
    workflow.implementationStatus = "complete";
    workflow.implementationFamilyId = "family-split-authenticatedsecurityrep-manufacturer-session-scope-hydration-e038879b07";
    workflow.postgresqlCertificationStatus = "pending";
    workflow.implementationFiles = [
      "backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts",
      "backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql",
      "backend/src/services/manufacturerScopeService.ts",
    ];
    workflow.testFiles = ["backend/tests/manufacturerSessionScope.test.js", "backend/tests/rls-wave-b/b01/authenticationClosurePostgres18.test.js"];
    workflow.canonicalContextKeys = ["app.user_id", "app.role", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"];
    workflow.sameTransactionGuarantee = true;
    workflow.contextBoundaryFamilySplit = {
      parentFamilyId: "family-simple-tenant-scoped-reads-manufacturerscopeservice-bea2e91ac1",
      semanticKey: "manufacturer-session-scope-hydration",
      reason: "Canonical manufacturer session scope is resolved by one exact capability-bound database projection.",
      evidence: ["Authentication and session callers supply their transaction client; the repository has no global Prisma fallback or claim-carried membership authority."],
      routeRoots: ["Authentication and session callers supply their transaction client; the repository has no global Prisma fallback or claim-carried membership authority."],
      actorClasses: ["manufacturer"],
      scopeModel: "Database-verified manufacturer User.id is actor authority; eligible link rows are the bounded result, and licensee/organization context is installed only after server verification selects one link.",
      executionSurface: "internal",
      protectedTableBoundary: "ManufacturerLicenseeLink plus active Licensee and Organization actor-bound projection",
      commandSemantics: "Exact authenticated function with explicit projection, maximum 100 eligible links, deterministic ordering and same-transaction attribution; no blank tenant wildcard.",
    };
  }
  return boundary;
};

const applyPlatformReadScopeAuthority = (workflowManifest) => {
  const boundary = readJson(platformReadScopeBoundaryPath);
  assert.equal(boundary.id, PLATFORM_READ_SCOPE_BOUNDARY_ID, "platform read-scope boundary ID drifted");
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "platform read-scope workflow ordering drifted");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const classification of boundary.workflowClassifications) {
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, missingWorkflowDiagnostic({ scope: "platform read scope", workflowId: classification.workflowId, classification, workflowManifest, scan: scanProductionAccess() }));
    workflow.platformReadScopeBoundaryId = boundary.id;
    workflow.platformReadScopeClass = classification.primaryClass;
    workflow.platformReadRequiredAssurance = classification.requiredAssurance;
    workflow.platformReadRequiredAssuranceByActorClass = classification.requiredAssuranceByActorClass || null;
    workflow.platformReadActorClasses = classification.actorClasses;
    workflow.platformReadExecutionBoundary = classification.executionBoundary;
    workflow.platformReadPurposeCodes = classification.purposeCodes;
    workflow.platformReadAllowedColumnsByTable = Object.fromEntries(classification.tableProjections.map((projection) => [projection.tableId, projection.allowedColumns]));
    workflow.platformReadResponseProjection = classification.responseProjection;
    workflow.authorizationBoundaryType = classification.inventoryBoundaryType;
    workflow.authenticationStage = "authenticated";
    workflow.tenantScopeRule = classification.scopeRule;
    workflow.contextRequirementsSource = "human-reviewed";
    workflow.contextRequirements = [
      "database-verified active platform actor and database role",
      `${classification.requiredAssurance} within the approved freshness window`,
      "allowlisted purpose and immutable request attribution",
      "transaction-local canonical scope from server-validated selectors",
    ];
    workflow.expectedAllowedScenarios = boundary.allowScenarios;
    workflow.expectedDeniedScenarios = boundary.denyScenarios;
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== boundary.decisionId);
    const code = classification.primaryClass === "prohibited-platform-read"
      ? "prohibited-platform-read"
      : classification.implementationStatus === "blocked-product-state-missing"
        ? "incident-authorization-model-missing"
        : classification.executionBoundary.startsWith("dedicated-")
          ? "dedicated-platform-projection-pending"
          : "platform-read-runtime-pending";
    workflow.contextBoundaryBlockers = [{
      code,
      reason: classification.blockers.join(" "),
      remediation: classification.primaryClass === "prohibited-platform-read"
        ? "Retire the broad export or design a separately reviewed bounded projection; this boundary authorizes no export implementation."
        : "Implement the exact actor, assurance, selector, projection, bound, transaction and attribution contract in a focused runtime batch, then complete disposable PostgreSQL certification.",
    }];
    workflow.contextBoundaryPlanningEvidence = {
      reviewedAt: "2026-07-16",
      registeredRootCallChainVerified: true,
      protectedQueryTraceComplete: false,
      sameTransactionFeasible: classification.primaryClass !== "prohibited-platform-read",
      focusedTestsDeterministic: true,
    };
    if (classification.familySplit) {
      workflow.contextBoundaryFamilySplit = {
        ...classification.familySplit,
        routeRoots: classification.familySplit.evidence,
      };
    }
  }
  return boundary;
};

const applyPolicyAlertActorCeilingAuthority = (workflowManifest) => {
  const boundary = readJson(policyAlertActorCeilingPath);
  assert.equal(boundary.id, POLICY_ALERT_ACTOR_CEILING_ID, "policy alert actor-ceiling boundary ID drifted");
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "policy alert workflow ordering drifted");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const classification of boundary.workflowClassifications) {
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, `policy alert actor ceiling references missing workflow ${classification.workflowId}`);
    workflow.policyAlertActorCeilingBoundaryId = boundary.id;
    workflow.policyAlertClass = classification.primaryClass;
    workflow.policyAlertRequiredAssurance = classification.requiredAssurance;
    workflow.policyAlertActorClasses = classification.actorClasses;
    workflow.policyAlertExecutionBoundary = classification.executionBoundary;
    workflow.policyAlertPurposeCodes = classification.purposeCodes;
    workflow.policyAlertAllowedColumnsByTableAndCommand = Object.fromEntries(
      classification.tableCommandProjections.map((projection) => [projection.tableId, projection.commands])
    );
    workflow.authorizationBoundaryType = classification.inventoryBoundaryType;
    workflow.authenticationStage = classification.inventoryBoundaryType === "restricted-worker" ? "system" : "authenticated";
    workflow.tenantScopeRule = classification.scopeRule;
    workflow.contextRequirementsSource = "human-reviewed";
    workflow.contextRequirements = classification.inventoryBoundaryType === "restricted-worker"
      ? ["approved restricted system identity", "durable outbox row authority", "no human actor context"]
      : [
          "database-verified actor ceiling",
          `${classification.requiredAssurance} within the approved freshness window`,
          "allowlisted purpose and immutable request attribution",
          "transaction-local canonical scope from authoritative rows",
        ];
    workflow.expectedAllowedScenarios = boundary.allowScenarios;
    workflow.expectedDeniedScenarios = boundary.denyScenarios;
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== boundary.decisionId);
    if (!workflow.workerBoundaryId) {
      const code = classification.implementationStatus === "blocked-product-state-missing"
        ? "alert-product-state-missing"
        : classification.primaryClass === "alert-acknowledgement"
          ? "alert-concurrency-contract-pending"
          : "alert-runtime-contract-pending";
      workflow.contextBoundaryBlockers = [{
        code,
        reason: classification.blockers.join(" "),
        remediation: "Implement only the exact actor, scope, assurance, projection, lifecycle, concurrency and attribution contract in a focused runtime batch, then complete disposable PostgreSQL certification.",
      }];
    }
    workflow.contextBoundaryPlanningEvidence = {
      reviewedAt: "2026-07-16",
      registeredRootCallChainVerified: true,
      protectedQueryTraceComplete: false,
      sameTransactionFeasible: true,
      focusedTestsDeterministic: true,
      databaseConcurrencyVerified: false,
    };
  }
  return boundary;
};

const applyPublicReadContractAuthority = (workflowManifest) => {
  const boundary = readJson(publicReadContractPath);
  assert.equal(boundary.id, PUBLIC_READ_CONTRACT_ID, "public-read contract ID drifted");
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "public-read workflow ordering drifted");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const classification of boundary.workflowClassifications) {
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, `public-read contract references missing workflow ${classification.workflowId}`);
    const profile = classification.projectionProfile ? boundary.projectionProfiles[classification.projectionProfile] : [];
    workflow.publicReadContractBoundaryId = boundary.id;
    workflow.publicAccessClass = classification.primaryClass;
    workflow.publicReadFunctionId = classification.functionId;
    workflow.publicReadProjectionProfile = classification.projectionProfile;
    workflow.publicReadRateLimitClass = classification.rateLimitClass;
    workflow.publicReadActorClasses = ["anonymous", "pre-auth-runtime"];
    workflow.publicReadRequiredAssurance = "none";
    workflow.publicReadAllowedColumnsByTableAndCommand = Object.fromEntries(profile.map((entry) => [entry.tableId, entry.commands]));
    workflow.expectedAllowedScenarios = boundary.allowScenarios;
    workflow.expectedDeniedScenarios = boundary.denyScenarios;
    workflow.unresolvedDecisions = workflow.unresolvedDecisions.filter((id) => id !== boundary.decisionId);
    if (!classification.functionId.startsWith("preauth-fn-")) {
      workflow.authorizationBoundaryType = "public-proof-boundary";
      workflow.authenticationStage = "pre-authentication";
      workflow.tenantScopeRule = "One exact validated public proof or artifact authorizes at most one resource through the approved named function; caller tenant/role fields and blank scope are never authority.";
      workflow.contextRequirementsSource = "human-reviewed";
      workflow.contextRequirements = [`EXECUTE only ${classification.functionId} through identity-pre-auth-app; no direct protected-table access or caller-set app.* authority.`];
      workflow.contextBoundaryBlockers = [{
        code: classification.implementationStatus.startsWith("blocked-schema") ? "public-proof-schema-pending" : "public-boundary-runtime-pending",
        reason: `${classification.implementationStatus}; current direct Prisma and response behavior are not certified against public-read-contract-v1.`,
        remediation: "Implement the exact named function/repository call chain, proof validation, projection, rate limit, generic failure, atomic attribution and disposable PostgreSQL tests in the full-system runtime stage.",
      }];
      workflow.contextBoundaryPlanningEvidence = {
        reviewedAt: "2026-07-16",
        registeredRootCallChainVerified: true,
        protectedQueryTraceComplete: false,
        sameTransactionFeasible: true,
        focusedTestsDeterministic: true,
        databaseConcurrencyVerified: false,
      };
      if (workflow.contextBoundaryFamilySplit) {
        workflow.contextBoundaryFamilySplit.actorClasses = ["anonymous", "pre-auth-runtime"];
        workflow.contextBoundaryFamilySplit.scopeModel = "One exact validated public proof or artifact authorizes at most one resource through the approved named function; blank scope and caller tenant/role values deny.";
        workflow.contextBoundaryFamilySplit.executionSurface = workflow.executionSurface;
        workflow.contextBoundaryFamilySplit.commandSemantics = `Execute only ${classification.functionId} with the exact projection, rate limit, generic failure and atomic attribution contract.`;
      }
    }
  }
  return boundary;
};

const applyRuntimeImplementationAuthority = (workflowManifest) => {
  const workflow = workflowManifest.workflows.find((item) => item.id === RISK_ANALYTICS_WORKFLOW_ID);
  assert(workflow, `${RISK_ANALYTICS_WORKFLOW_ID} runtime workflow missing`);
  Object.assign(workflow, {
    authenticationStage: "authenticated",
    actorClasses: ["licensee-admin", "platform-admin"],
    runtimeImplementedActorClasses: ["licensee-admin", "platform-admin"],
    runtimeBlockedActorClasses: [],
    platformRuntimeStatus: "application-path-certified",
    platformRuntimeBlockers: [],
    canonicalSourceFiles: [
      "backend/src/routes/index.ts",
      "backend/src/middleware/auth.ts",
      "backend/src/controllers/tracePolicyController.ts",
      "backend/src/services/analyticsService.ts",
    ],
    tenantScopeRule: "An ACTIVE database-hydrated LICENSEE_ADMIN or ORG_ADMIN uses its nonblank User.licenseeId and User.orgId; a selector may only equal that scope. An ACTIVE database-hydrated platform administrator requires fresh MFA and one requested Licensee that is revalidated with its active Organization in the same transaction. Blank, foreign, inactive or inconsistent scope is denied.",
    contextRequirements: [
      "transaction-local canonical actor context",
      "database-hydrated ACTIVE tenant administrator and request ID",
      "nonblank database-validated organization and licensee scope",
      "fixed allowlisted tenant-risk-analytics purpose",
      "one REPEATABLE READ transaction with atomic immutable attribution",
    ],
    contextRequirementsSource: "human-reviewed",
    authorizationBoundaryType: "authenticated-context",
    expectedAllowedScenarios: [
      "A database-hydrated LICENSEE_ADMIN or ORG_ADMIN reads bounded risk analytics for its active licensee and organization.",
      "A database-hydrated platform administrator with fresh MFA reads one requested active licensee after its Licensee and Organization are revalidated in the same attributed transaction.",
      "An optional query licensee equal to canonical scope narrows nothing and is accepted.",
      "Batch, QR, scan-log, alert and policy reads share the same licensee and bounded lookback snapshot.",
      "The immutable RISK_ANALYTICS_READ attribution commits in the same transaction before serialization.",
    ],
    expectedDeniedScenarios: [
      "Password-only or stale-MFA platform, manufacturer, anonymous, inactive-session or unsupported-role actors are denied.",
      "A platform actor with blank, malformed, foreign, inactive, suspended or organization-inconsistent selector scope is denied before analytics or RISK_ANALYTICS_READ attribution.",
      "Blank, missing, foreign, inactive, suspended or organization-inconsistent scope is denied.",
      "Out-of-range date/page inputs and context purpose, actor, assurance or scope mismatch are denied before analytics reads.",
      "A protected query before context, global Prisma use, unbounded input, inconsistent tenant predicate, nested User projection or non-atomic attribution is denied.",
    ],
    currentCompatibilityStatus: "compatible",
    implementationStatus: "complete",
    contextBoundaryBlockers: [],
    requiredUnitTests: ["backend/tests/riskAnalyticsContext.test.js", "backend/tests/riskAnalyticsRouteChain.test.js"],
    unresolvedDecisions: [],
    contextBoundaryStatus: "implemented",
    implementationFamilyId: "family-simple-tenant-scoped-reads-analyticsservice-2c20deef24",
    contextBoundaryCategory: "simple tenant-scoped reads",
    approvedReadAttribution: true,
    implementationFiles: [
      "backend/src/controllers/tracePolicyController.ts",
      "backend/src/services/analyticsService.ts",
      "backend/src/lib/canonicalDbContext.ts",
      "backend/src/middleware/auth.ts",
      "backend/src/routes/index.ts",
    ],
    testFiles: [
      "backend/tests/riskAnalyticsContext.test.js",
      "backend/tests/riskAnalyticsRouteChain.test.js",
      "backend/tests/riskAnalyticsApplicationPathPostgres18.test.js",
    ],
    canonicalContextKeys: ["app.user_id", "app.role", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"],
    sameTransactionGuarantee: true,
    protectedQueryClient: "transaction-client-only",
    consistentReadScopeGuarantee: true,
    routeRootVerified: true,
    aggregateScopeStatus: "tenant-bounded",
    postgresqlCertificationStatus: "pending",
    contextBoundaryPlanningEvidence: {
      reviewedAt: "2026-07-16",
      registeredRootCallChainVerified: true,
      protectedQueryTraceComplete: true,
      sameTransactionFeasible: true,
      focusedTestsDeterministic: true,
      databaseConcurrencyVerified: true,
    },
    resolvedContextBlockerIds: [
      "blocker-family-simple-tenant-scoped-reads-analyticsservice-2c20deef24-unresolved-boundary",
      "blocker-family-simple-tenant-scoped-reads-analyticsservice-2c20deef24-unreviewed-scope",
      "blocker-family-simple-tenant-scoped-reads-analyticsservice-2c20deef24-unverified-execution-path",
      "blocker-family-simple-tenant-scoped-reads-analyticsservice-2c20deef24-unverified-root-call-chain",
    ],
    rootCallChainEvidence: [
      "backend/src/routes/index.ts registers GET /analytics/risk-scores with authenticate, requireAnyAdmin, bounded read limiters and enforceTenantIsolation before getRiskAnalyticsController.",
      "getRiskAnalyticsController is the only production caller of getRiskAnalytics; tenant and freshly MFA-verified platform paths share the same repeatable-read analytics transaction.",
      "authenticate performs exact actor-self User hydration first; tenant scope is database authoritative, while platform scope starts empty and one requested Licensee and Organization are revalidated before tenant data is accepted.",
    ],
    scopeEvidence: [
      "buildRiskAnalyticsBoundary accepts database-hydrated LICENSEE_ADMIN/ORG_ADMIN claims and fresh-MFA platform claims; platform authority is narrowed to one requested Licensee and its active Organization before analytics data is accepted.",
      "Every protected analytics predicate contains the validated tenant licensee; every scoped tenant Batch forms the bounded candidate set, preserving zero-activity rows, while in-window scans and every unresolved alert supply risk signals.",
      "Every scan row must prove matching canonical Licensee, QR and Batch parentage before it can affect a ceiling, candidate, dimension or score.",
      "Every populated PolicyAlert batch, QR, manufacturer, incident and policy-rule parent must resolve to the same active canonical tenant before candidate scoring.",
    ],
    responseProjection: [
      "Explicit tenant-safe batch and manufacturer aggregate fields; User.id/name are the only returned manufacturer fields, while role/licenseeId/orgId/isActive/status/deletedAt/disabledAt are actor/scope/predicate validation columns and are never serialized. Email, password, token, MFA, WebAuthn, recovery, metadata and platform-security fields remain unreadable.",
      "Risk rows are deterministically ordered by score and stable ID; policy thresholds and bounded result summaries only.",
    ],
    riskAnalyticsAllowedColumnsByTableAndCommand: {
      "table-audit-log": { INSERT: ["action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId"] },
      "table-batch": { SELECT: ["id", "licenseeId", "manufacturerId", "name"] },
      "table-licensee": { SELECT: ["id", "isActive", "orgId", "suspendedAt"] },
      "table-organization": { SELECT: ["id", "isActive"] },
      "table-incident": { SELECT: ["id", "licenseeId"] },
      "table-manufacturer-licensee-link": { SELECT: ["licenseeId", "manufacturerId"] },
      "table-policy-alert": { SELECT: ["acknowledgedAt", "batchId", "id", "incidentId", "licenseeId", "manufacturerId", "policyRuleId", "qrCodeId"] },
      "table-policy-rule": { SELECT: ["id", "isActive", "licenseeId", "manufacturerId", "orgId"] },
      "table-qr-scan-log": { SELECT: ["batchId", "id", "latitude", "licenseeId", "longitude", "qrCodeId", "scannedAt"] },
      "table-qrcode": { SELECT: ["batchId", "id", "licenseeId", "scanCount"] },
      "table-refresh-token": { SELECT: ["expiresAt", "id", "revokedAt", "sessionCapabilityExpiresAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityRevokedAt", "userId"] },
      "table-security-policy": { SELECT: ["geoDriftThresholdKm", "licenseeId", "multiScanThreshold", "velocitySpikeThresholdPerMin"] },
      "table-user": { SELECT: ["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "name", "orgId", "role", "status"] },
    },
  });

  for (const workflowId of DASHBOARD_SNAPSHOT_WORKFLOW_IDS) {
    const dashboardWorkflow = workflowManifest.workflows.find((item) => item.id === workflowId);
    assert(dashboardWorkflow, `${workflowId} runtime workflow missing`);
    const scopeWorkflow = workflowId.endsWith("compute-dashboard-snapshot");
    Object.assign(dashboardWorkflow, {
      authenticationStage: "authenticated",
      actorClasses: ["licensee-admin", "manufacturer", "platform-admin"],
      runtimeImplementedActorClasses: ["licensee-admin", "manufacturer", "platform-admin"],
      runtimeBlockedActorClasses: [],
      platformRuntimeStatus: "application-path-certified",
      platformRuntimeBlockers: [],
      canonicalSourceFiles: [
        "backend/src/routes/modules/realtimeRoutes.ts",
        "backend/src/middleware/auth.ts",
        "backend/src/middleware/tenantIsolation.ts",
        "backend/src/controllers/dashboardController.ts",
        "backend/src/controllers/eventsController.ts",
        "backend/src/services/dashboardSnapshotService.ts",
      ],
      tenantScopeRule: "An ACTIVE database-revalidated tenant administrator uses its canonical licensee and organization; an ACTIVE manufacturer uses its current active linked-licensee set or one linked selector; an ACTIVE platform administrator requires fresh MFA and may use the reviewed global aggregate or one active selected licensee. Every REST, SSE snapshot and SSE delta request uses fixed purpose dashboard-snapshot-read and immutable request attribution.",
      contextRequirements: [
        "transaction-local canonical actor context",
        "database-revalidated ACTIVE actor, role and scope",
        "actor-specific password or fresh-MFA assurance",
        "fixed allowlisted dashboard-snapshot-read purpose",
        "one REPEATABLE READ transaction with immutable per-request attribution",
        "exact dashboard named-function execution with no direct application table privilege",
      ],
      contextRequirementsSource: "human-reviewed",
      authorizationBoundaryType: "authenticated-context",
      expectedAllowedScenarios: [
        "An ACTIVE LICENSEE_ADMIN or ORG_ADMIN reads its active tenant dashboard through the REST or SSE root.",
        "An ACTIVE manufacturer reads aggregates across all current active links or narrows to one current linked licensee.",
        "An ACTIVE fresh-MFA platform administrator reads the reviewed global aggregate or one active selected licensee.",
        "A cache hit revalidates actor and scope in PostgreSQL and commits one immutable dashboard read attribution before delivery.",
        "Rollup totals remain authoritative when any rollup counter is nonzero; otherwise QR status rows provide the existing fallback.",
      ],
      expectedDeniedScenarios: [
        "Blank or malformed context, wrong purpose, wrong role, lower platform assurance and inactive actors are denied.",
        "Foreign, inactive, suspended or revoked tenant/manufacturer scope is denied before cached or fresh data is delivered.",
        "Direct application table access, internal helper execution and prohibited User or QRCode columns are denied.",
        "A protected query before canonical context or use of global Prisma in the dashboard family is denied.",
      ],
      currentCompatibilityStatus: "compatible",
      implementationStatus: "complete",
      contextBoundaryBlockers: [],
      requiredUnitTests: ["backend/tests/dashboardSnapshotContext.test.js"],
      requiredDisposablePostgresqlTests: ["backend/tests/dashboardSnapshotApplicationPathPostgres18.test.js"],
      unresolvedDecisions: [],
      contextBoundaryStatus: "implemented",
      implementationFamilyId: "family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887",
      contextBoundaryCategory: "simple tenant-scoped reads",
      approvedReadAttribution: true,
      implementationFiles: [
        "backend/src/controllers/dashboardController.ts",
        "backend/src/controllers/eventsController.ts",
        "backend/src/services/dashboardSnapshotService.ts",
        "backend/src/lib/canonicalDbContext.ts",
        "backend/src/middleware/auth.ts",
        "backend/src/middleware/tenantIsolation.ts",
        "backend/src/routes/modules/realtimeRoutes.ts",
      ],
      testFiles: [
        "backend/tests/dashboardSnapshotContext.test.js",
        "backend/tests/dashboardSnapshotApplicationPathPostgres18.test.js",
      ],
      canonicalContextKeys: ["app.user_id", "app.role", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"],
      sameTransactionGuarantee: true,
      protectedQueryClient: "transaction-client-only",
      consistentReadScopeGuarantee: true,
      routeRootVerified: true,
      aggregateScopeStatus: "database-revalidated-tenant-manufacturer-or-platform",
      postgresqlCertificationStatus: "pending",
      dashboardSnapshotFunction: scopeWorkflow
        ? "app_rls.dashboard_snapshot_scope(text,text,text)"
        : "app_rls.dashboard_snapshot_data(text,text,text,text)",
      dashboardSnapshotAllowedColumnsByTableAndCommand: DASHBOARD_SNAPSHOT_COLUMNS,
      dashboardSnapshotRequiredAssuranceByActorClass: {
        "licensee-admin": "password-verified",
        manufacturer: "mfa-verified",
        "platform-admin": "mfa-verified",
      },
      contextBoundaryPlanningEvidence: {
        reviewedAt: "2026-07-21",
        registeredRootCallChainVerified: true,
        protectedQueryTraceComplete: true,
        sameTransactionFeasible: true,
        focusedTestsDeterministic: true,
        databaseConcurrencyVerified: true,
      },
      resolvedContextBlockerIds: [
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-incomplete-root-transaction",
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-named-function-prerequisite",
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-unresolved-boundary",
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-unreviewed-scope",
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-unverified-execution-path",
        "blocker-family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887-unverified-root-call-chain",
      ],
      rootCallChainEvidence: [
        "realtimeRoutes registers GET /dashboard/stats and GET /events/dashboard behind authentication, tenant isolation and bounded route/IP/actor limiters.",
        "dashboardController and eventsController call dashboardSnapshotService; every protected snapshot query is inside one canonical REPEATABLE READ transaction.",
        "SSE initial snapshots and deltas share the same database-revalidated actor, scope, assurance, purpose and attribution family.",
      ],
      scopeEvidence: [
        "Tenant actor licensee and organization claims are matched to the ACTIVE User, Licensee and Organization rows in PostgreSQL.",
        "Manufacturer selectors only narrow the current active ManufacturerLicenseeLink set; the membership fingerprint is revalidated before every cache hit.",
        "Platform global and selected aggregates require a database ACTIVE actor and fresh-MFA canonical assurance; selected licensees and organizations must be active.",
      ],
      responseProjection: [
        "REST preserves success.data totalQRCodes, activeLicensees, manufacturers and totalBatches.",
        "SSE preserves the existing summary plus QR status aggregate; no protected predicate or secret column is serialized.",
      ],
    });
  }

  for (const workflowId of BATCH_OPERATIONAL_READ_WORKFLOW_IDS) {
    const batchWorkflow = workflowManifest.workflows.find((item) => item.id === workflowId);
    assert(batchWorkflow, `${workflowId} runtime workflow missing`);
    Object.assign(batchWorkflow, {
      authenticationStage: "authenticated",
      actorClasses: ["licensee-admin", "manufacturer", "platform-admin"],
      runtimeImplementedActorClasses: ["licensee-admin", "manufacturer", "platform-admin"],
      runtimeBlockedActorClasses: [],
      platformRuntimeStatus: "application-path-certified",
      platformRuntimeBlockers: [],
      canonicalSourceFiles: [
        "backend/src/routes/index.ts",
        "backend/src/middleware/auth.ts",
        "backend/src/middleware/tenantIsolation.ts",
        "backend/src/controllers/qrController.ts",
        "backend/src/services/stagingRlsBatchReadService.ts",
        "backend/src/services/stagingRlsBatchAllocationMapService.ts",
        "backend/src/services/batchAllocationService.ts",
        "backend/src/services/printReservationService.ts",
      ],
      tenantScopeRule: "An ACTIVE database-revalidated tenant administrator uses its canonical active licensee and organization; an ACTIVE fresh-MFA manufacturer reads only batches assigned to that actor across current active linked licensees or one linked selector; an ACTIVE fresh-MFA platform administrator supplies one explicit active licensee selector. Both list and allocation-map roots use fixed purpose batch-operational-read and immutable request attribution.",
      contextRequirements: [
        "transaction-local canonical actor context",
        "database-revalidated ACTIVE actor, role and scope",
        "actor-specific password or fresh-MFA assurance",
        "fixed allowlisted batch-operational-read purpose",
        "one REPEATABLE READ transaction with immutable per-request attribution",
        "exact named-function execution with no direct wide Batch, QR, User or print-table privilege",
      ],
      contextRequirementsSource: "human-reviewed",
      authorizationBoundaryType: "authenticated-context",
      expectedAllowedScenarios: [
        "An ACTIVE LICENSEE_ADMIN or ORG_ADMIN lists and paginates its tenant batches and reads an in-scope allocation map.",
        "An ACTIVE fresh-MFA manufacturer reads assigned batches across current active links or narrows to one linked licensee.",
        "An ACTIVE fresh-MFA platform administrator reads one explicitly selected active licensee.",
        "Batch ordering, totals, lineage ordering, inventory fallback, reservable print counts and response projections remain unchanged.",
        "One immutable BATCH_OPERATIONAL_READ attribution commits in the same transaction before serialization.",
      ],
      expectedDeniedScenarios: [
        "Blank or malformed context, wrong purpose, wrong role, inactive session and weak manufacturer/platform assurance are denied.",
        "Foreign, inactive, suspended or revoked tenant/manufacturer scope and a blank platform selector are denied.",
        "Direct protected table access, internal helper execution and prohibited User or print-security columns are denied.",
        "A protected query before canonical context or use of global Prisma in either route root is denied.",
      ],
      currentCompatibilityStatus: "compatible",
      implementationStatus: "complete",
      contextBoundaryBlockers: [],
      requiredUnitTests: ["backend/tests/batchOperationalReadContext.test.js"],
      requiredDisposablePostgresqlTests: ["backend/tests/batchOperationalReadApplicationPathPostgres18.test.js"],
      unresolvedDecisions: [],
      contextBoundaryStatus: "implemented",
      implementationFamilyId: "family-batch-operational-read-4a19e4013f",
      contextBoundaryCategory: "simple tenant-scoped reads",
      approvedReadAttribution: true,
      implementationFiles: [
        "backend/src/controllers/qrController.ts",
        "backend/src/services/stagingRlsBatchReadService.ts",
        "backend/src/services/stagingRlsBatchAllocationMapService.ts",
        "backend/src/services/batchAllocationService.ts",
        "backend/src/services/printReservationService.ts",
        "backend/src/lib/canonicalDbContext.ts",
      ],
      testFiles: [
        "backend/tests/batchOperationalReadContext.test.js",
        "backend/tests/batchOperationalReadApplicationPathPostgres18.test.js",
      ],
      canonicalContextKeys: ["app.user_id", "app.role", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"],
      sameTransactionGuarantee: true,
      protectedQueryClient: "transaction-client-only",
      consistentReadScopeGuarantee: true,
      routeRootVerified: true,
      aggregateScopeStatus: "database-revalidated-tenant-manufacturer-or-selected-platform-licensee",
      postgresqlCertificationStatus: "pending",
      runtimeAllowedColumnsByTableAndCommand: BATCH_OPERATIONAL_READ_COLUMNS_BY_WORKFLOW.get(workflowId),
      runtimeRequiredAssuranceByActorClass: {
        "licensee-admin": "password-verified",
        manufacturer: "mfa-verified",
        "platform-admin": "mfa-verified",
      },
      contextBoundaryPlanningEvidence: {
        reviewedAt: "2026-07-21",
        registeredRootCallChainVerified: true,
        protectedQueryTraceComplete: true,
        sameTransactionFeasible: true,
        focusedTestsDeterministic: true,
        databaseConcurrencyVerified: true,
      },
      resolvedContextBlockerIds: [],
      rootCallChainEvidence: [
        "routes/index.ts registers GET /qr/batches and GET /qr/batches/:id/allocation-map behind authentication and tenant isolation.",
        "qrController delegates both roots to one batch-operational-read family; every protected query uses the same canonical REPEATABLE READ transaction client.",
        "The repository uses exact audit-bound functions for scope, rows, totals, rollups, QR ranges and reservable print summaries; no feature flag or global Prisma fallback remains.",
      ],
      scopeEvidence: [
        "Tenant actor licensee and organization claims are matched to ACTIVE User, Licensee and Organization rows in PostgreSQL.",
        "Manufacturer scope is derived from current active ManufacturerLicenseeLink rows and the Batch.manufacturerId actor assignment; stale links fail closed.",
        "Platform access requires fresh MFA and one explicit active Licensee whose Organization is active.",
      ],
      responseProjection: [
        "Batch list pagination, updatedAt/createdAt ordering, total count, relation projection, inventory fallback and print-readiness fields are preserved.",
        "Allocation maps preserve source/selected/child lineage, createdAt/id ordering and all existing aggregate totals.",
      ],
    });
  }

  const nextWorkflow = workflowManifest.workflows.find((item) => item.id === "workflow-http-backend-src-controllers-audit-controller-ts-respond-to-fraud-report");
  assert(nextWorkflow, "respond-to-fraud-report runtime workflow missing");
  nextWorkflow.contextBoundaryBlockers = [{
    code: "incompatible-read-mutation-root",
    reason: "POST /audit/fraud-reports/:id/respond is a platform-admin mutation: it reads a report through global Prisma, appends a response audit record through another global client path, and constructs a customer-delivery side effect. It lacks one bounded licensee/purpose context, transaction-client propagation, immutable ownership guards, idempotency and concurrency enforcement.",
    remediation: "Move this workflow to a focused platform mutation batch: require one database-validated licensee/report scope and purpose, then perform report lookup, compare-and-set/idempotency, immutable response attribution and durable delivery enqueue in one canonical transaction with focused replay/concurrency tests.",
  }];
  nextWorkflow.contextBoundaryPlanningEvidence = {
    reviewedAt: "2026-07-16",
    registeredRootCallChainVerified: true,
    protectedQueryTraceComplete: false,
    sameTransactionFeasible: false,
    focusedTestsDeterministic: true,
    databaseConcurrencyVerified: false,
  };
};

export const buildWorkflowManifest = () => {
  const delegations = validateWorkflowDelegations({ repoRoot });
  const scan = scanProductionAccess();
  const existing = readJson(workflowManifestPath, { schemaVersion: 1, workflows: [] });
  const previous = new Map(existing.workflows.map((workflow) => [workflow.id, workflow]));
  const groups = new Map();
  for (const access of scan.accesses) {
    const delegation = resolveWorkflowDelegation(access, delegations);
    const canonical = delegation?.canonical || { executionSurface: access.executionSurface, sourceFile: access.sourceFile, function: access.function };
    const key = canonicalWorkflowKey(canonical);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ access, canonical, delegation });
  }
  const workflows = [...groups.entries()].map(([key, groupedAccesses]) => {
    const accesses = groupedAccesses.map((item) => item.access);
    const canonical = groupedAccesses[0].canonical;
    const delegated = groupedAccesses.some((item) => item.delegation);
    const id = workflowIdFor(canonical);
    const legacyModuleId = "workflow-internal-backend-src-services-auth-refresh-token-service-ts-module";
    const inheritedLegacyModule = id === "workflow-internal-backend-src-services-auth-refresh-token-service-ts-rotate-refresh-token"
      && !previous.has(id)
      && previous.has(legacyModuleId);
    const old = previous.get(id) || (inheritedLegacyModule ? previous.get(legacyModuleId) : {}) || {};
    const authenticatedEmailChange = id === "workflow-internal-backend-src-services-auth-email-verification-service-ts-request-email-change-verification";
    const boundary = authenticatedEmailChange
      ? "authenticated-context"
      : old.authorizationBoundaryType || boundaryFor(path.join(repoRoot, canonical.sourceFile), canonical.function, canonical.executionSurface);
    const tableCommands = [...new Set(accesses.flatMap((access) => expandCommands([access.command]).map((command) => `${access.tableId}:${command}`)))].sort().map((value) => { const index = value.lastIndexOf(":"); return { tableId: value.slice(0, index), commands: [value.slice(index + 1)] }; });
    const mergedCommands = [...new Map(tableCommands.map((item) => [item.tableId, { tableId: item.tableId, commands: tableCommands.filter((candidate) => candidate.tableId === item.tableId).flatMap((candidate) => candidate.commands).sort() }])).values()];
    const preAuth = boundary === "pre-auth-security-function";
    const background = ["worker", "scheduled"].includes(canonical.executionSurface);
    const systemSurface = ["startup", "cli"].includes(canonical.executionSurface);
    return {
      ...old,
      id,
      name: inheritedLegacyModule ? displayName(canonical.function) : old.name || displayName(canonical.function),
      entryPoint: inheritedLegacyModule ? `${canonical.executionSurface}:${canonical.function}` : old.entryPoint || `${canonical.executionSurface}:${canonical.function}`,
      executionSurface: canonical.executionSurface,
      authenticationStage: authenticatedEmailChange ? "authenticated" : old.authenticationStage || (preAuth ? "pre-authentication" : background || ["cli", "startup"].includes(canonical.executionSurface) ? "system" : "authenticated"),
      actorClasses: authenticatedEmailChange ? ["authenticated-user"] : old.actorClasses || (background ? ["system-job"] : preAuth ? ["anonymous-or-partially-authenticated"] : canonical.executionSurface === "cli" ? ["operator"] : ["authenticated-user"]),
      canonicalSourceFiles: old.contextBoundaryStatus === "implemented" && !delegated
        ? old.canonicalSourceFiles
        : [...new Set([canonical.sourceFile, ...accesses.map((access) => access.sourceFile)])].sort(),
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
  const unregisteredPotentiallyDeadAccesses = scan.unregisteredAccesses.map(({ clientKind: _clientKind, ...access }) => access);
  const result = { schemaVersion: 1, groupingRule: "One workflow per execution surface, canonical source file, and containing function; repeated table calls within that function remain one functional workflow.", generatedEvidence: { productionAccessSites: scan.accesses.length, testPathsExcluded: ["backend/tests", "scripts/tests"], registrations: scan.registrations, unregisteredPotentiallyDeadAccesses, unregisteredFiles: scan.unregisteredFiles }, workflows };
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
  const manufacturerBootstrapBoundary = applyManufacturerBootstrapAuthority(result);
  const platformReadScopeBoundary = applyPlatformReadScopeAuthority(result);
  const policyAlertActorCeiling = applyPolicyAlertActorCeilingAuthority(result);
  const publicReadContract = applyPublicReadContractAuthority(result);
  applyRuntimeImplementationAuthority(result);
  applyApplicationPathCertificationEvidence(result);
  for (const workflow of result.workflows.filter((item) => item.contextBoundaryStatus === "implemented" && item.sameTransactionGuarantee === true)) {
    workflow.protectedQueryClient = "transaction-client-only";
  }
  validateProtectedTransactionClients(result, scan);
  for (const table of tableManifest.tables) applyRuntimeCommandMatrix(table, result.workflows);
  const commandManifest = buildCommandSemantics(tableManifest, result);
  const preAuthManifest = buildPreAuthBoundary(result, commandManifest, tableManifest);
  const workerManifest = buildWorkerBoundaryManifest(result, commandManifest, tableManifest);
  writeCommandSemanticsReview(commandManifest, tableManifest, result);
  writePreAuthBoundaryReview(preAuthManifest, result.workflows);
  writeJson(workerBoundariesPath, workerManifest);
  writeWorkerIdentityReview(workerManifest);
  writeWorkerIdentityAuthority(workerManifest);
  writeJson(commandSemanticsPath, commandManifest);
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
      if (decision.id === "decision-pre-auth-boundary") {
        const selected = workflows.filter((workflow) => workflow.preAuthBoundary);
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.affectedWorkflows = selected.map((workflow) => workflow.id);
        decision.affectedTables = [...new Set(selected.flatMap((workflow) => workflow.tablesTouched))].sort();
        decision.resolution = { authority: "documents/security/rls-program/pre-auth-functions.json", selectedWorkflows: selected.length, exactFunctions: preAuthManifest.functions.length, movedBehindContext: selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context").length, operatorOnly: 0, retired: 0, guarantees: preAuthManifest.securityInvariants };
        continue;
      }
      if (decision.id === "decision-worker-identity-model") {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.affectedWorkflows = workerManifest.boundaries.flatMap((boundary) => boundary.workflowIds);
        decision.affectedTables = [...new Set(workerManifest.boundaries.flatMap((boundary) => [...boundary.tablesRead, ...boundary.tablesWritten]))].sort();
        decision.resolution = { authority: "documents/security/rls-program/worker-boundaries.json", boundaries: workerManifest.boundaries.length, workerWorkflows: workerManifest.boundaries.filter((item) => item.runtimeIdentity === "identity-worker").length, scheduledWorkflows: workerManifest.boundaries.filter((item) => item.runtimeIdentity === "identity-scheduled-job").length, namedFunctions: workerManifest.boundaries.filter((item) => item.namedFunctionRequirement.required).length, guarantees: workerManifest.securityInvariants };
        continue;
      }
      if (decision.id === manufacturerBootstrapBoundary.decisionId) {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.selectedBoundary = manufacturerBootstrapBoundary.boundaryType;
        decision.affectedWorkflows = [...manufacturerBootstrapBoundary.supportingWorkflows];
        decision.affectedTables = manufacturerBootstrapBoundary.authoritativeTables.map((entry) => entry.tableId);
        decision.resolution = {
          authority: "documents/security/rls-program/manufacturer-bootstrap-boundary.json",
          boundaryId: manufacturerBootstrapBoundary.id,
          boundaryType: manufacturerBootstrapBoundary.boundaryType,
          implementationForm: manufacturerBootstrapBoundary.implementationForm.type,
          requiredAssurance: manufacturerBootstrapBoundary.requiredAssurance,
          runtimeImplementationPending: true,
          postgresqlCertificationPending: true,
          guarantees: [
            "User.id and User.role are verified before membership reads",
            "Client licensee input only narrows a freshly verified membership set",
            "Blank scope never means all",
            "Multiple memberships use deterministic fail-closed selection",
            "No secret, platform-admin or full-tenant projection",
            "Scope switching requires MFA, request attribution, fresh transaction and audit",
          ],
        };
        continue;
      }
      if (decision.id === platformReadScopeBoundary.decisionId) {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.selectedBoundary = platformReadScopeBoundary.id;
        decision.affectedWorkflows = [...platformReadScopeBoundary.affectedWorkflows];
        decision.affectedTables = [...new Set(platformReadScopeBoundary.workflowClassifications.flatMap((classification) => classification.tableProjections.map((projection) => projection.tableId)))].sort();
        decision.resolution = {
          authority: "documents/security/rls-program/platform-read-scope-boundary.json",
          boundaryId: platformReadScopeBoundary.id,
          approvedScopeClasses: platformReadScopeBoundary.approvedScopeClasses.map((item) => item.class),
          purposeCodes: platformReadScopeBoundary.purposeCodes.map((item) => item.code),
          affectedWorkflows: platformReadScopeBoundary.affectedWorkflows.length,
          runtimeImplementationPending: true,
          postgresqlCertificationPending: true,
          guarantees: [
            "Platform-admin role alone never authorizes a read",
            "Blank scope denies unless the exact dedicated aggregate is selected",
            "Raw global row listing and broad licensee export are prohibited",
            "Every allowed read has fresh assurance, allowlisted purpose, exact projection, bounds and immutable attribution",
            "Incident response requires an active expiring incident authorization",
            "Catalog and database diagnostics remain exact operator procedures",
          ],
        };
        continue;
      }
      if (decision.id === policyAlertActorCeiling.decisionId) {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.selectedBoundary = policyAlertActorCeiling.id;
        decision.affectedWorkflows = [...policyAlertActorCeiling.affectedWorkflows];
        decision.affectedTables = [...new Set(policyAlertActorCeiling.workflowClassifications.flatMap((classification) => classification.tableCommandProjections.map((projection) => projection.tableId)))].sort();
        decision.resolution = {
          authority: "documents/security/rls-program/policy-alert-actor-ceiling.json",
          boundaryId: policyAlertActorCeiling.id,
          alertClasses: policyAlertActorCeiling.alertClasses.map((item) => item.class),
          affectedWorkflows: policyAlertActorCeiling.affectedWorkflows.length,
          runtimeImplementationPending: true,
          postgresqlCertificationPending: true,
          guarantees: [
            "No generic alert administrator or platform role wildcard",
            "Licensee and manufacturer visibility is bounded by authoritative tenant and actor rows",
            "Platform and incident access requires bounded scope, fresh assurance, purpose and attribution",
            "Only acknowledgement and one-way incident escalation have approved PolicyAlert transitions",
            "Assignment, resolution, suppression, public access, human worker impersonation and direct operator table access are prohibited",
          ],
        };
        continue;
      }
      if (decision.id === publicReadContract.decisionId) {
        decision.status = "resolved";
        decision.resolvedAt = "2026-07-16";
        decision.selectedBoundary = publicReadContract.id;
        decision.affectedWorkflows = [...publicReadContract.affectedWorkflows];
        decision.affectedTables = [...new Set(publicReadContract.workflowClassifications.flatMap((classification) => {
          const profile = classification.projectionProfile ? publicReadContract.projectionProfiles[classification.projectionProfile] : [];
          return profile.map((entry) => entry.tableId);
        }))].sort();
        decision.resolution = {
          authority: "documents/security/rls-program/public-read-contract.json",
          boundaryId: publicReadContract.id,
          publicAccessClasses: publicReadContract.publicAccessClasses,
          affectedWorkflows: publicReadContract.affectedWorkflows.length,
          workflowLevelAuthorizationFrozen: true,
          nextStage: "full-system-runtime-implementation",
          runtimeImplementationPending: true,
          postgresqlCertificationPending: true,
          guarantees: [
            "No generic public or anonymous database read",
            "Signed-token failure cannot fall back to raw QR lookup",
            "Reference, email and internal IDs are not public proof",
            "Caller tenant, role and routing fields establish no authority",
            "Public projections, rate limits, replay, expiry and generic failures are exact",
            "All public protected-table work remains named-function contract-only until full-system certification",
          ],
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
    const identityManifest = readJson(identityManifestPath);
    const ownershipManifest = buildObjectOwnershipManifest(tableManifest, identityManifest, preAuthManifest, workerManifest);
    applyObjectOwnershipAuthority(ownershipManifest, tableManifest, identityManifest, decisionManifest);
    const operatorManifest = buildOperatorBoundaryManifest(result, commandManifest);
    applyOperatorAuthority(operatorManifest, result, commandManifest, tableManifest, identityManifest, decisionManifest);
    writeJson(objectOwnershipChainPath, ownershipManifest);
    writeObjectOwnershipReview(ownershipManifest);
    writeJson(operatorBoundariesPath, operatorManifest);
    writeOperatorAdministrationReview(operatorManifest);
    writeJson(commandSemanticsPath, commandManifest);
    writeJson(workflowManifestPath, result);
    writeJson(tableManifestPath, tableManifest);
    writeJson(identityManifestPath, identityManifest);
    writeJson(decisionManifestPath, decisionManifest);
  }
  return result;
};

export const manifests = () => ({ tables: readJson(tableManifestPath), workflows: readJson(workflowManifestPath), identities: readJson(identityManifestPath), decisions: readJson(decisionManifestPath), commandSemantics: readJson(commandSemanticsPath), preAuthFunctions: readJson(preAuthFunctionsPath), workerBoundaries: readJson(workerBoundariesPath), objectOwnershipChain: readJson(objectOwnershipChainPath), operatorBoundaries: readJson(operatorBoundariesPath), systemBoundaries: readJson(systemBoundariesPath), manufacturerBootstrapBoundary: readJson(manufacturerBootstrapBoundaryPath), platformReadScopeBoundary: readJson(platformReadScopeBoundaryPath), policyAlertActorCeiling: readJson(policyAlertActorCeilingPath), publicReadContract: readJson(publicReadContractPath) });

export const validateManufacturerBootstrapBoundary = (boundary, workflowManifest, commandManifest, tableManifest, decisionManifest) => {
  assert.equal(boundary?.schemaVersion, 1, "manufacturer bootstrap schema version");
  assert.equal(boundary.id, MANUFACTURER_BOOTSTRAP_BOUNDARY_ID, "manufacturer bootstrap boundary ID");
  assert(boundary.generatedFrom?.length >= 10, "manufacturer bootstrap lacks source evidence");
  assert.equal(boundary.decisionId, "decision-context-manufacturer-bootstrap", "manufacturer bootstrap decision ID");
  assert.equal(boundary.boundaryType, "post-password-actor-bootstrap", "manufacturer bootstrap must occur after actor verification");
  assert.deepEqual(boundary.supportingWorkflows, MANUFACTURER_BOOTSTRAP_WORKFLOW_IDS, "manufacturer bootstrap workflow coverage drifted");
  assert(boundary.registeredRoots?.length >= 4, "manufacturer bootstrap lacks registered roots");

  const tables = new Map(tableManifest.tables.map((table) => [table.id, table]));
  for (const entry of boundary.authoritativeTables || []) {
    const table = tables.get(entry.tableId);
    assert(table && entry.columns?.length && entry.purpose?.trim(), `manufacturer bootstrap authoritative table ${entry.tableId} is incomplete`);
    const columns = new Set(table.schemaEvidence.fields.map((field) => field.name));
    for (const column of entry.columns) assert(columns.has(column), `manufacturer bootstrap references unknown ${entry.tableId}.${column}`);
  }
  assert.deepEqual(boundary.identityProofChain.intendedRoleCeiling, ["MANUFACTURER_ADMIN"], "manufacturer bootstrap grants deprecated, licensee or platform role visibility");
  assert.match(boundary.identityProofChain.verificationPoint, /password verifies|valid signed token/i, "manufacturer bootstrap runs before actor verification");
  assert.match(boundary.identityProofChain.authoritativeManufacturerUserId, /User\.id/, "manufacturer identity is not database verified");
  assert.match(boundary.identityProofChain.authoritativeRelationship, /manufacturerId equals the verified User\.id/, "manufacturer relationship is not actor-bound");
  assert.equal(boundary.requiredAssurance.bootstrapRead, "password-verified", "manufacturer bootstrap assurance");
  assert.equal(boundary.requiredAssurance.activeApplicationSession, "mfa-verified", "manufacturer active-session assurance");
  assert.equal(boundary.requiredAssurance.scopeSwitch, "mfa-verified", "manufacturer scope-switch assurance");

  const requestedLicensee = boundary.inputFields.find((field) => field.name === "requestedLicenseeId");
  assert(requestedLicensee && requestedLicensee.establishesAuthority === false, "caller-selected licensee becomes authoritative");
  assert.equal(boundary.trustedInputSources.role, "User.role", "manufacturer role comes from caller input or token claims");
  assert.equal(boundary.trustedInputSources.callerClaimsTrustedForAuthority, false, "manufacturer bootstrap trusts caller claims");
  assert.equal(boundary.membershipSelectionRules.blankLicenseeMeansAll, false, "blank manufacturer licensee means all");
  assert.equal(boundary.membershipSelectionRules.clientInputEstablishesAuthority, false, "client input establishes manufacturer tenant authority");
  assert.equal(boundary.membershipSelectionRules.requestedLicenseeMustMatchVerifiedMembership, true, "foreign manufacturer membership may be selected");
  assert.equal(boundary.membershipSelectionRules.foreignMembershipDenied, true, "foreign manufacturer membership is allowed");
  assert.equal(boundary.membershipSelectionRules.maximumEligibleLinks, 100, "manufacturer membership result is not bounded");
  assert.deepEqual(boundary.membershipSelectionRules.deterministicOrdering, ["isPrimary DESC", "createdAt ASC", "licenseeId ASC"], "multiple manufacturer memberships are nondeterministic");
  assert.equal(boundary.multiLicenseeBehavior.activeScopeCount, 1, "manufacturer bootstrap installs multiple active scopes");
  assert.equal(boundary.multiLicenseeBehavior.selectionProof.includes("requestedLicenseeId must exactly match"), true, "manufacturer scope selection lacks membership proof");
  assert.equal(boundary.duplicateHandling.nondeterministicSelectionAllowed, false, "duplicate manufacturer memberships do not fail closed");
  assert.match(boundary.duplicateHandling.multiplePrimaryMemberships, /Deny/i, "multiple primary memberships do not fail closed");

  for (const field of ["disabledUserAccepted", "revokedMembershipAccepted", "disabledLicenseeAccepted", "suspendedLicenseeAccepted", "disabledOrganizationAccepted", "expiredMembershipAccepted"]) assert.equal(boundary.disabledRevokedBehavior[field], false, `manufacturer bootstrap accepts ${field}`);
  const returnedNames = boundary.exactReturnedColumns.map((entry) => entry.name);
  assert.deepEqual(returnedNames, ["manufacturerUserId", "accountRole", "licenseeId", "organizationId", "relationshipStatus", "isPrimary", "displayName", "scopeVersion"], "manufacturer bootstrap projection is not exact");
  const secretPattern = /password|token|secret|backup|recovery|credential|publicKey|platformAdmin|isPlatformAdmin/i;
  assert(!boundary.exactReturnedColumns.some((entry) => secretPattern.test(`${entry.name} ${entry.source}`)), "manufacturer bootstrap returns secret or platform-admin fields");
  assert(boundary.prohibitedReturnedColumns.some((column) => /passwordHash/.test(column)) && boundary.prohibitedReturnedColumns.some((column) => /platformAdmin/i.test(column)), "manufacturer bootstrap lacks secret/platform projection prohibitions");

  assert.deepEqual(boundary.contextKeysInstalled.actorBootstrap, ["app.user_id", "app.role", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"], "manufacturer actor context uses unverified tenant fields");
  assert.deepEqual(boundary.contextKeysInstalled.selectedScopeFreshTransaction, ["app.user_id", "app.role", "app.organization_id", "app.licensee_id", "app.manufacturer_id", "app.auth_assurance", "app.request_id", "app.purpose"], "manufacturer selected-scope context is incomplete");
  assert.equal(boundary.contextKeysInstalled.blankTenantValuesAccepted, false, "manufacturer context accepts blank tenant authority");
  assert.equal(boundary.contextKeysInstalled.clientValuesInstalledDirectly, false, "manufacturer context installs query/body values directly");
  assert(boundary.contextKeysInstalled.transactionLocal && boundary.contextKeysInstalled.contextClearsAtTransactionEnd, "manufacturer context is not transaction-local");
  assert(boundary.scopeSwitchRules.requestIdRequired && boundary.scopeSwitchRules.auditRequired && boundary.scopeSwitchRules.freshMembershipReadRequired && boundary.scopeSwitchRules.freshTransactionRequired, "manufacturer scope switching lacks request attribution, audit or fresh verification");
  assert.equal(boundary.scopeSwitchRules.queryOrBodyAuthority, false, "manufacturer scope switch trusts query/body authority");
  assert(boundary.auditRequirements.required && boundary.auditRequirements.sameTransactionAsMembershipReadOrSwitch && boundary.auditRequirements.membershipListLogged === false && boundary.auditRequirements.failureResponseLeaksMembership === false, "manufacturer bootstrap audit leaks membership or is not atomic");

  assert.equal(boundary.implementationForm.type, "exact-authenticated-capability", "manufacturer bootstrap uses the wrong implementation form");
  assert.equal(boundary.implementationForm.actorIdentityVerifiedBeforeRead, true, "manufacturer bootstrap occurs before actor verification without an approved function");
  assert.equal(boundary.implementationForm.transactionClientOnly, true, "manufacturer bootstrap permits a global database client");
  assert.equal(boundary.implementationForm.globalPrismaAllowed, false, "manufacturer bootstrap permits global Prisma");
  assert.equal(boundary.implementationForm.namedFunctionRequired, true, "manufacturer bootstrap lacks its exact capability function");
  assert.equal(boundary.implementationForm.genericPreAuthFunctionAllowed, false, "manufacturer bootstrap permits a generic pre-auth function");
  assert.equal(boundary.namedFunctionContract?.signature, "app_rls.load_authenticated_manufacturer_scope(text,text,text,text,boolean)", "manufacturer bootstrap named function drifted");
  assert.equal(boundary.implementationStatus, "runtime-and-postgresql-certified", "manufacturer bootstrap certification status drifted");
  assert(boundary.postgresqlCertificationRequirements?.length >= 6, "manufacturer bootstrap lacks PostgreSQL certification requirements");

  const failures = ["noUserMatch", "duplicateNormalizedUsers", "disabledUser", "wrongRole", "noActiveRelationship", "multipleInconsistentRelationships", "requestedForeignLicensee", "revokedRelationship", "disabledTenant", "userRelationshipTenantMismatch", "unsupportedAssurance", "staleSession", "missingRequestId", "blankScope", "invitationNotFullyConsumed"];
  for (const failure of failures) assert(boundary.failureSemantics[failure]?.trim(), `manufacturer bootstrap lacks ${failure} failure semantics`);

  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const workflowId of boundary.supportingWorkflows) {
    const workflow = workflows.get(workflowId);
    assert(workflow, `manufacturer bootstrap references unknown workflow ${workflowId}`);
    assert.equal(workflow.manufacturerBootstrapBoundaryId, boundary.id, `${workflowId} lacks manufacturer bootstrap boundary ID`);
    assert.equal(workflow.authorizationBoundaryType, "authenticated-context", `${workflowId} remains pre-auth or unresolved`);
    assert(!workflow.unresolvedDecisions.includes(boundary.decisionId), `${workflowId} retains the resolved manufacturer bootstrap decision`);
    assert.equal(workflow.contextBoundaryStatus, "implemented", `${workflowId} is not context implemented`);
    for (const ruleId of workflow.commandRuleIds) {
      const rule = commandManifest.rules.find((item) => item.id === ruleId);
      assert.equal(rule?.manufacturerBootstrapBoundaryId, boundary.id, `${ruleId} lacks manufacturer bootstrap boundary ID`);
      assert.equal(rule.minimumAssurance, "password-verified", `${ruleId} has unsupported manufacturer bootstrap assurance`);
      assert.equal(rule.requiresNamedFunction, true, `${ruleId} bypasses the exact authenticated function`);
      assert.equal(rule.requiresAuditEvent, true, `${ruleId} lacks manufacturer bootstrap read attribution`);
    }
  }
  const decision = decisionManifest.decisions.find((item) => item.id === boundary.decisionId);
  assert.equal(decision?.status, "resolved", "manufacturer bootstrap decision is unresolved");
  assert.equal(decision.selectedBoundary, boundary.boundaryType, "manufacturer bootstrap decision boundary drifted");
  assert.equal(decision.resolution?.authority, "documents/security/rls-program/manufacturer-bootstrap-boundary.json", "manufacturer bootstrap decision lacks authority");
  assert.deepEqual(decision.affectedWorkflows, boundary.supportingWorkflows, "manufacturer bootstrap decision workflow coverage drifted");
  return true;
};

export const validatePlatformReadScopeBoundary = (boundary, workflowManifest, commandManifest, tableManifest, decisionManifest, operatorManifest) => {
  assert.equal(boundary?.schemaVersion, 1, "platform read-scope schema version");
  assert.equal(boundary.id, PLATFORM_READ_SCOPE_BOUNDARY_ID, "platform read-scope boundary ID");
  assert.equal(boundary.decisionId, "decision-context-platform-read-scope", "platform read-scope decision ID");
  assert.equal(boundary.actorClass, "platform-admin", "platform read-scope actor class");
  assert.equal(boundary.actorVerification.roleAloneAuthorizesAccess, false, "platform-admin role alone grants access");
  assert.equal(boundary.actorVerification.requestOrTokenRoleAuthoritativeWithoutDatabaseVerification, false, "platform-admin role alone grants access");
  assert.equal(boundary.selectorValidation.blankSelectorMeansGlobal, false, "blank platform scope becomes global");
  assert.equal(boundary.selectorValidation.callerInputEstablishesAuthority, false, "caller selector establishes platform authority");
  assert.equal(boundary.selectorValidation.conflictingSelectorsAccepted, false, "conflicting selectors are accepted");
  assert.equal(boundary.selectorValidation.unsupportedSelectorCombinationsAccepted, false, "unsupported selector combinations are accepted");
  assert.equal(boundary.purposeRules.required, true, "platform read purpose is absent");
  assert.equal(boundary.purposeRules.allowlistedCodesOnly, true, "platform read purpose is unrestricted");
  assert.equal(boundary.purposeRules.freeTextEstablishesAuthority, false, "free-text purpose establishes authority");
  const classNames = ["tenant-bounded-read", "organization-bounded-read", "licensee-bounded-read", "manufacturer-bounded-read", "actor-bounded-read", "platform-aggregate-read", "platform-diagnostic-read", "incident-response-read", "operator-procedure-only", "prohibited-platform-read"];
  assert.deepEqual(boundary.approvedScopeClasses.map((item) => item.class), classNames, "platform read scope classes are incomplete");
  for (const item of boundary.approvedScopeClasses.filter((item) => !["operator-only", "prohibited"].includes(item.disposition))) {
    assert(["mfa-verified", "step-up-verified"].includes(item.requiredAssurance), `${item.class} sensitive platform read lacks fresh MFA`);
    assert(item.defaultMaximumFreshnessMinutes > 0 && item.defaultMaximumFreshnessMinutes <= 30, `${item.class} assurance freshness is unbounded`);
  }
  assert.equal(boundary.requestAttributionRequirements.required, true, "read attribution is missing");
  assert.equal(boundary.requestAttributionRequirements.immutable, true, "read attribution is missing");
  for (const field of ["actorId", "role", "assurance", "requestId", "purposeCode", "selectedScope", "workflowId", "route", "resultCountOrBoundedSummary", "timestamp", "outcome"]) assert(boundary.requestAttributionRequirements.fields.includes(field), `read attribution is missing ${field}`);
  assert.equal(boundary.transactionRequirements.countAndListShareIdenticalScope, true, "count/list scope differs");
  assert.equal(boundary.transactionRequirements.countAndListShareOneRepeatableReadSnapshot, true, "count/list scope differs");
  assert.equal(boundary.transactionRequirements.readAttributionInSameTransaction, true, "read attribution is missing");
  assert.equal(boundary.aggregateRestrictions.rawRowsReturned, false, "aggregate exposes tenant-private rows");
  assert.equal(boundary.aggregateRestrictions.tenantPrivateRowsMaterializedInApplicationMemory, false, "aggregate exposes tenant-private rows");
  assert.equal(boundary.aggregateRestrictions.tenantIdentityDimensionsAllowed, false, "aggregate exposes tenant-private rows");
  assert(boundary.aggregateRestrictions.maximumDateWindowDays > 0 && boundary.aggregateRestrictions.maximumResultDimensions > 0, "aggregate bounds are missing");
  assert.equal(boundary.incidentReadRestrictions.incidentIdRequired, true, "incident read lacks incident binding");
  assert.equal(boundary.incidentReadRestrictions.authorizationExpiryRequired, true, "incident read lacks expiry");
  assert.equal(boundary.incidentReadRestrictions.unrelatedTenantBrowsingAllowed, false, "incident read permits unrelated tenant browsing");
  const operatorIds = new Set(operatorManifest.boundaries.map((item) => item.id));
  for (const mapping of boundary.operatorOnlyMappings) {
    assert(operatorIds.has(mapping.boundaryId), `platform read scope references unknown operator boundary ${mapping.boundaryId}`);
    assert.equal(mapping.ordinaryApplicationRead, false, "operator diagnostics are ordinary application reads");
  }
  const globalProhibited = new Set(boundary.prohibitedColumns);
  for (const column of ["passwordHash", "tokenHash", "mfaSecret", "credentialPublicKey", "privateKey", "details", "metadata"]) assert(globalProhibited.has(column), `secret or raw audit detail ${column} is not prohibited`);
  assert.equal(new Set(boundary.purposeCodes.map((item) => item.code)).size, boundary.purposeCodes.length, "platform purpose codes are duplicated");
  const tableIds = new Set(tableManifest.tables.map((item) => item.id));
  const workflows = new Map(workflowManifest.workflows.map((item) => [item.id, item]));
  const authenticatedSessionContract = namedFunctionContractFor("app_auth.require_authenticated_session");
  assert(authenticatedSessionContract, "authenticated-session verification contract is missing");
  const authenticatedSessionCommands = new Set(authenticatedSessionContract.tableCommands.map(([table, command]) => `table-${slug(table)}:${command}`));
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "platform affected workflow coverage drifted");
  assert.equal(new Set(boundary.affectedWorkflows).size, boundary.affectedWorkflows.length, "platform affected workflows are duplicated");
  const secretPattern = /password|token|secret|recovery|backup|credential|privateKey|platformAdmin|details|metadata|customerEmail|supportEmail|supportPhone/i;
  for (const classification of boundary.workflowClassifications) {
    assert(classNames.includes(classification.primaryClass), `${classification.workflowId} has an invalid platform class`);
    assert(classification.purposeCodes.length && classification.purposeCodes.every((code) => boundary.purposeCodes.some((item) => item.code === code)), `${classification.workflowId} platform read purpose is absent`);
    if (classification.requiredAssuranceByActorClass) {
      assert.deepEqual(Object.keys(classification.requiredAssuranceByActorClass).sort(), [...classification.actorClasses].sort(), `${classification.workflowId} actor assurance map drifted`);
      assert.equal(classification.requiredAssuranceByActorClass["platform-admin"], "mfa-verified", `${classification.workflowId} platform actor lacks fresh MFA`);
    }
    if (classification.runtimeImplementedActorClasses) {
      assert.deepEqual(classification.runtimeImplementedActorClasses, ["licensee-admin", "platform-admin"], `${classification.workflowId} loses implemented platform authority`);
      assert.deepEqual(classification.runtimeBlockedActorClasses, [], `${classification.workflowId} retains a stale blocked platform contract`);
      assert.deepEqual(classification.blockers, [], `${classification.workflowId} retains a stale platform selector blocker`);
      assert.deepEqual(classification.runtimeAttributionFields, ["actorId", "role", "assurance", "requestId", "purposeCode", "organizationId", "licenseeId", "workflowId", "route", "outcome", "analyzedBatchCount", "returnedBatchCount", "analyzedManufacturerCount", "timestamp"], `${classification.workflowId} attribution contract drifted`);
    }
    if (!["platform-aggregate-read", "platform-diagnostic-read", "operator-procedure-only", "prohibited-platform-read"].includes(classification.primaryClass)) assert(classification.requiredSelectors.length, `${classification.workflowId} raw global listing is approved without a specific class`);
    if (classification.primaryClass === "platform-aggregate-read") assert(boundary.aggregateRestrictions.approvedWorkflowIds.includes(classification.workflowId), `${classification.workflowId} raw global listing is approved without a specific class`);
    assert(classification.pagination && Number.isInteger(classification.pagination.maximumPageSize) && classification.pagination.maximumPageSize >= 0, `${classification.workflowId} pagination bounds are missing`);
    if (classification.primaryClass !== "prohibited-platform-read") assert(classification.maximumRows > 0 && classification.pagination.maximumPageSize > 0, `${classification.workflowId} pagination bounds are missing`);
    assert(classification.tableProjections.length && classification.tableProjections.every((projection) => tableIds.has(projection.tableId)), `${classification.workflowId} lacks exact projections`);
    for (const projection of classification.tableProjections) {
      assert(!projection.allowedColumns.some((column) => secretPattern.test(column)), `${classification.workflowId} secret or raw audit detail entered projection`);
      assert.equal(new Set(projection.allowedColumns).size, projection.allowedColumns.length, `${classification.workflowId} projection contains duplicates`);
    }
    if (classification.workflowId.endsWith("get-licensees")) {
      assert.equal(classification.pagination.mode, "keyset", "licensee directory lacks keyset pagination");
      assert(classification.pagination.maximumPageSize <= 50, "licensee directory pagination is unbounded");
      assert(!classification.tableProjections[0].allowedColumns.some((column) => /support|metadata|suspendedReason/i.test(column)), "directory projection exposes security fields");
    }
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, `platform boundary references missing workflow ${classification.workflowId}`);
    assert.equal(workflow.platformReadScopeBoundaryId, boundary.id, `${classification.workflowId} lacks platform read-scope boundary ID`);
    assert.equal(workflow.platformReadScopeClass, classification.primaryClass, `${classification.workflowId} platform class drifted`);
    assert.equal(workflow.authorizationBoundaryType, classification.inventoryBoundaryType, `${classification.workflowId} inventory boundary drifted`);
    assert.equal(workflow.platformReadRequiredAssurance, classification.requiredAssurance, `${classification.workflowId} assurance drifted`);
    assert.deepEqual(workflow.platformReadRequiredAssuranceByActorClass, classification.requiredAssuranceByActorClass || null, `${classification.workflowId} actor assurance map drifted`);
    assert(!workflow.unresolvedDecisions.includes(boundary.decisionId), `${classification.workflowId} retains resolved platform decision`);
    if (classification.runtimeImplementedActorClasses) {
      const postgresqlCertified = classification.implementationStatus === "runtime-implemented-postgresql-certified";
      assert.deepEqual(workflow.runtimeImplementedActorClasses, classification.runtimeImplementedActorClasses, `${classification.workflowId} implemented actor slice drifted`);
      assert.deepEqual(workflow.runtimeBlockedActorClasses, classification.runtimeBlockedActorClasses, `${classification.workflowId} blocked actor slice drifted`);
      assert.equal(workflow.platformRuntimeStatus, postgresqlCertified ? "application-path-certified" : "implemented-postgresql-pending", `${classification.workflowId} platform runtime status drifted`);
      assert.deepEqual(workflow.platformRuntimeBlockers, [], `${classification.workflowId} retains stale selector-validation blocker evidence`);
      assert.equal(workflow.contextBoundaryStatus, "implemented", `${classification.workflowId} tenant runtime implementation is missing`);
      assert.equal(workflow.postgresqlCertificationStatus, postgresqlCertified ? "certified" : "pending", `${classification.workflowId} PostgreSQL certification status drifted`);
      if (postgresqlCertified) {
        assert.equal(workflow.applicationPathCertificationEvidence?.status, "application-path-certified", `${classification.workflowId} lacks application-path certification evidence`);
        assert.equal(workflow.applicationPathCertificationEvidence?.postgresqlMajor, 18, `${classification.workflowId} lacks PostgreSQL 18 certification evidence`);
      }
    } else if (classification.implementationStatus === "runtime-implemented-postgresql-pending") {
      assert.equal(workflow.contextBoundaryStatus, "implemented", `${classification.workflowId} runtime implementation is missing`);
      assert.equal(workflow.postgresqlCertificationStatus, "pending", `${classification.workflowId} is falsely PostgreSQL-certified`);
    } else {
      assert.notEqual(workflow.contextBoundaryStatus, "implemented", `${classification.workflowId} is falsely context-boundary implemented`);
    }
    for (const ruleId of workflow.commandRuleIds) {
      const rule = commandManifest.rules.find((item) => item.id === ruleId);
      assert.equal(rule?.platformReadScopeBoundaryId, boundary.id, `${ruleId} lacks platform read-scope boundary ID`);
      const ruleAssurance = Object.fromEntries(rule.actorClasses.map((actor) => [actor, classification.requiredAssuranceByActorClass?.[actor] || classification.requiredAssurance]));
      assert.deepEqual(rule.minimumAssuranceByActorClass, ruleAssurance, `${ruleId} actor-specific platform assurance drifted`);
      if (classification.runtimeImplementedActorClasses) {
        assert.deepEqual(rule.actorClasses, classification.runtimeImplementedActorClasses, `${ruleId} implemented actor slice drifted`);
        assert(rule.actorClasses.includes("platform-admin"), `${ruleId} loses the certified bounded platform actor`);
      }
      assert.equal(rule.requiresAuditEvent, true, `${ruleId} read attribution is missing`);
      const isAuthenticatedSessionSupport = workflow.supportingEvidence.some((item) => item.method === "$function:app_auth.require_authenticated_session") &&
        authenticatedSessionCommands.has(`${rule.tableId}:${rule.command}`);
      if (isAuthenticatedSessionSupport) {
        assert.equal(rule.requiresNamedFunction, true, `${ruleId} authentication support is not bound to an exact function`);
        assert.equal(authenticatedSessionContract.definitionStatus, "production-reviewed", `${ruleId} authentication support is not reviewed`);
        continue;
      }
      const projection = classification.tableProjections.find((item) => item.tableId === rule.tableId);
      const implementedProjection = classification.runtimeImplementedActorClasses
        ? workflow.riskAnalyticsAllowedColumnsByTableAndCommand?.[rule.tableId]?.[rule.command]
        : projection?.allowedColumns;
      if (rule.command === "SELECT") assert.deepEqual([...rule.allowedColumns].sort(), [...(implementedProjection || [])].sort(), `${ruleId} platform projection drifted`);
      else assert((classification.runtimeImplementedActorClasses || classification.implementationStatus === "runtime-implemented-postgresql-pending") && rule.tableId === "table-audit-log" && rule.command === "INSERT", `${ruleId} adds an unsupported platform mutation`);
      if (classification.primaryClass === "prohibited-platform-read") assert.equal(rule.authorizationBoundary, "prohibited", `${ruleId} approves a prohibited platform read`);
      if (classification.executionBoundary.startsWith("dedicated-")) assert.equal(rule.requiresNamedFunction, true, `${ruleId} lacks dedicated projection boundary`);
    }
  }
  const decision = decisionManifest.decisions.find((item) => item.id === boundary.decisionId);
  assert.equal(decision?.status, "resolved", "platform read-scope decision is unresolved");
  assert.equal(decision.selectedBoundary, boundary.id, "platform read-scope decision boundary drifted");
  assert.equal(decision.resolution?.authority, "documents/security/rls-program/platform-read-scope-boundary.json", "platform read-scope decision lacks authority");
  assert.deepEqual(decision.affectedWorkflows, boundary.affectedWorkflows, "platform decision workflow coverage drifted");
  return true;
};

export const validatePolicyAlertActorCeiling = (boundary, workflowManifest, commandManifest, tableManifest, decisionManifest, operatorManifest, workerManifest) => {
  assert.equal(boundary?.schemaVersion, 1, "policy alert actor-ceiling schema version");
  assert.equal(boundary.id, POLICY_ALERT_ACTOR_CEILING_ID, "policy alert actor-ceiling boundary ID");
  assert.equal(boundary.decisionId, "decision-context-policy-alert-actor-ceiling", "policy alert actor-ceiling decision ID");
  const classNames = ["tenant-security-alert-read", "manufacturer-alert-read", "platform-alert-triage", "incident-response-alert-read", "alert-acknowledgement", "alert-assignment", "alert-resolution", "alert-suppression", "alert-escalation", "worker-alert-delivery", "operator-alert-procedure", "public-alert-status", "prohibited-alert-access"];
  assert.deepEqual(boundary.alertClasses.map((item) => item.class), classNames, "policy alert classes are incomplete");
  assert(!boundary.alertClasses.flatMap((item) => item.actorClasses).some((actor) => /^(?:admin|generic-admin|alert-admin)$/i.test(actor)), "actor class is generic admin");
  assert.equal(boundary.actorCeilings.licenseeAdmin.foreignTenantAccess, false, "tenant admin gains cross-tenant alert access");
  assert.equal(boundary.actorCeilings.manufacturer.wholeLicenseeVisibility, false, "manufacturer gains whole-licensee alert visibility");
  assert.equal(boundary.actorCeilings.platformAdmin.roleAloneAuthorizesAccess, false, "platform role alone grants access");
  assert.equal(boundary.actorCeilings.platformAdmin.purposeRequired, true, "platform alert purpose is absent");
  assert.equal(boundary.actorCeilings.incidentResponse.authorizationExpiryRequired, true, "incident alert access lacks expiry");
  assert.equal(boundary.scopeModels.nullScopeBecomesGlobal, false, "alert scope becomes nullable wildcard");
  assert.equal(boundary.purposeRules.required, true, "alert purpose is absent");
  assert.equal(boundary.purposeRules.allowlistedCodesOnly, true, "alert purpose is unrestricted");
  assert.equal(boundary.purposeRules.freeTextEstablishesAuthority, false, "free-text alert purpose establishes authority");

  const acknowledgement = boundary.lifecycleTransitions.find((item) => item.class === "alert-acknowledgement");
  assert(acknowledgement?.sourceState.includes("acknowledgedAt IS NULL") && acknowledgement.targetState.includes("acknowledgedAt IS NOT NULL"), "acknowledgement lacks state transition");
  assert(/compare-and-set/i.test(acknowledgement.concurrency), "acknowledgement lacks compare-and-set or lock");
  assert.deepEqual(acknowledgement.allowedColumns, ["acknowledgedAt", "acknowledgedByUserId"], "acknowledgement mutates protected ownership columns");
  const assignment = boundary.lifecycleTransitions.find((item) => item.class === "alert-assignment");
  assert.equal(assignment?.targetState, "unsupported", "assignment changes tenant ownership");
  assert.equal(assignment?.allowedColumns.length, 0, "assignment changes tenant ownership");
  const resolution = boundary.lifecycleTransitions.find((item) => item.class === "alert-resolution");
  assert.equal(resolution?.sourceState, "unsupported", "resolution can occur from an invalid state");
  assert.equal(resolution?.targetState, "unsupported", "resolution can occur from an invalid state");
  const suppression = boundary.lifecycleTransitions.find((item) => item.class === "alert-suppression");
  assert.equal(suppression?.requiredReason, true, "suppression lacks reason or audit");
  assert(suppression?.auditEvent?.trim(), "suppression lacks reason or audit");
  assert.equal(boundary.concurrencyRules.applicationPrecheckAloneSufficient, false, "alert mutation relies on application pre-check");
  assert.equal(boundary.idempotencyReplaySemantics.conflictingReplayDenied, true, "alert mutation permits conflicting replay");

  assert.equal(boundary.publicAccessDisposition.allowed, false, "public alert access lacks proof binding");
  assert.equal(boundary.publicAccessDisposition.proofBindingRequiredIfReconsidered, true, "public alert access lacks proof binding");
  assert.equal(boundary.publicAccessDisposition.enumerationProtectionRequiredIfReconsidered, true, "public alert access lacks enumeration protection");
  assert.equal(boundary.actorCeilings.worker.humanImpersonationAllowed, false, "worker becomes human-attributed");
  assert.equal(boundary.actorCeilings.operator.directAlertTableAccess, false, "operator boundary is replaced by direct table access");
  assert(boundary.auditRequirements.required && boundary.auditRequirements.immutable && boundary.auditRequirements.sameTransactionAsReadOrMutation, "alert audit attribution is missing");

  const secretPattern = /details|rawDetection|secret|password|token|credential|privateKey|fingerprint|rawAudit|siemWebhook|customerPersonal/i;
  for (const [projectionName, columns] of Object.entries(boundary.allowedProjections)) {
    assert(!columns.some((column) => secretPattern.test(column)), `${projectionName} secret detection payload entered projection`);
  }
  assert(boundary.prohibitedFields.some((field) => field === "PolicyAlert.details") && boundary.prohibitedFields.some((field) => /siemWebhookSecret/.test(field)), "policy alert prohibited fields are incomplete");
  assert.equal(boundary.nestedProjectionRules.rawJsonReturned, false, "secret detection payload entered projection");

  const operatorIds = new Set(operatorManifest.boundaries.map((item) => item.id));
  const workerIds = new Set(workerManifest.boundaries.map((item) => item.id));
  for (const mapping of boundary.workerOperatorMappings) {
    if (mapping.alertClass === "worker-alert-delivery") assert(workerIds.has(mapping.boundaryId), `policy alert references unknown worker boundary ${mapping.boundaryId}`);
    else assert(operatorIds.has(mapping.boundaryId), `policy alert references unknown operator boundary ${mapping.boundaryId}`);
    assert.equal(mapping.ordinaryHumanContext, false, "worker becomes human-attributed");
    assert.equal(mapping.directHumanTableAccess, false, "operator boundary is replaced by direct table access");
  }

  const tableIds = new Set(tableManifest.tables.map((item) => item.id));
  const workflows = new Map(workflowManifest.workflows.map((item) => [item.id, item]));
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "policy alert affected workflow coverage drifted");
  assert.equal(new Set(boundary.affectedWorkflows).size, boundary.affectedWorkflows.length, "policy alert affected workflows are duplicated");
  for (const classification of boundary.workflowClassifications) {
    assert(classNames.includes(classification.primaryClass), `${classification.workflowId} has an invalid alert class`);
    assert(classification.actorClasses.length && !classification.actorClasses.some((actor) => /^(?:admin|generic-admin|alert-admin)$/i.test(actor)), `${classification.workflowId} actor class is generic admin`);
    assert(["mfa-verified", "step-up-verified", "system-verified"].includes(classification.requiredAssurance), `${classification.workflowId} lacks required alert assurance`);
    assert(classification.purposeCodes.length && classification.purposeCodes.every((code) => boundary.purposeCodes.some((item) => item.code === code)), `${classification.workflowId} alert purpose is absent`);
    assert(classification.requiredSelectors.length && classification.scopeRule?.trim(), `${classification.workflowId} alert scope is missing`);
    assert(classification.tableCommandProjections.length && classification.tableCommandProjections.every((projection) => tableIds.has(projection.tableId)), `${classification.workflowId} lacks exact alert projection`);
    for (const projection of classification.tableCommandProjections) {
      for (const columns of Object.values(projection.commands)) {
        assert.equal(new Set(columns).size, columns.length, `${classification.workflowId} alert projection contains duplicates`);
        if (projection.tableId === "table-policy-alert") assert(!columns.some((column) => secretPattern.test(column)), `${classification.workflowId} secret detection payload entered projection`);
      }
      for (const columns of Object.entries(projection.commands).filter(([command]) => command === "UPDATE").map(([, columns]) => columns)) {
        assert(!columns.some((column) => ["id", "licenseeId", "manufacturerId", "batchId", "qrCodeId", "policyRuleId", "createdAt"].includes(column)), `${classification.workflowId} mutation changes protected ownership columns`);
      }
    }
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, `policy alert boundary references missing workflow ${classification.workflowId}`);
    assert.equal(workflow.policyAlertActorCeilingBoundaryId, boundary.id, `${classification.workflowId} lacks policy alert boundary ID`);
    assert.equal(workflow.policyAlertClass, classification.primaryClass, `${classification.workflowId} alert class drifted`);
    assert.equal(workflow.policyAlertRequiredAssurance, classification.requiredAssurance, `${classification.workflowId} alert assurance drifted`);
    assert(!workflow.unresolvedDecisions.includes(boundary.decisionId), `${classification.workflowId} retains resolved policy alert decision`);
    assert.notEqual(workflow.contextBoundaryStatus, "implemented", `${classification.workflowId} is falsely context-boundary implemented`);
    for (const ruleId of workflow.commandRuleIds) {
      const rule = commandManifest.rules.find((item) => item.id === ruleId);
      assert.equal(rule?.policyAlertActorCeilingBoundaryId, boundary.id, `${ruleId} lacks policy alert boundary ID`);
      assert.equal(rule.minimumAssurance, classification.requiredAssurance, `${ruleId} alert assurance drifted`);
      assert.equal(rule.requiresAuditEvent, true, `${ruleId} alert attribution is missing`);
      const projection = classification.tableCommandProjections.find((item) => item.tableId === rule.tableId);
      assert.deepEqual(rule.allowedColumns, projection?.commands?.[rule.command] || [], `${ruleId} alert projection drifted`);
      if (classification.primaryClass === "worker-alert-delivery") {
        assert.equal(rule.authorizationBoundary, "restricted-worker", `${ruleId} worker alert delivery is ordinary human access`);
        assert(rule.actorClasses.every((actor) => actor === "worker"), `${ruleId} worker becomes human-attributed`);
      }
    }
  }

  const decision = decisionManifest.decisions.find((item) => item.id === boundary.decisionId);
  assert.equal(decision?.status, "resolved", "policy alert actor-ceiling decision is unresolved");
  assert.equal(decision.selectedBoundary, boundary.id, "policy alert decision boundary drifted");
  assert.equal(decision.resolution?.authority, "documents/security/rls-program/policy-alert-actor-ceiling.json", "policy alert decision lacks authority");
  assert.deepEqual(decision.affectedWorkflows, boundary.affectedWorkflows, "policy alert decision workflow coverage drifted");
  assert(boundary.implementationStatus?.trim() && boundary.postgresqlCertificationRequirements?.length >= 8, "policy alert decision is resolved with missing semantics");
  return true;
};

export const validatePublicReadContract = (boundary, workflowManifest, commandManifest, tableManifest, decisionManifest, preAuthManifest) => {
  const classes = ["static-public-content", "public-qr-verification", "signed-scan-verification", "proof-bound-public-status", "one-time-token-consumption", "email-link-verification", "public-support-tracking", "public-feedback-submission", "public-download", "pre-auth-security-function", "authenticated-only", "operator-only", "prohibited-public-access"];
  assert.equal(boundary?.schemaVersion, 1, "public-read schema version");
  assert.equal(boundary.id, PUBLIC_READ_CONTRACT_ID, "public-read boundary ID");
  assert.equal(boundary.decisionId, "decision-context-public-read-contract", "public-read decision ID");
  assert.deepEqual(boundary.publicAccessClasses, classes, "public access classes drifted");
  assert(!boundary.publicAccessClasses.some((value) => /generic|anonymous-read|public-database-read/.test(value)), "generic public-read class is allowed");
  assert.deepEqual(boundary.affectedWorkflows, boundary.workflowClassifications.map((item) => item.workflowId), "public affected workflow coverage drifted");
  assert.equal(new Set(boundary.affectedWorkflows).size, boundary.affectedWorkflows.length, "public affected workflows are duplicated");
  const publicCandidateWorkflowIds = workflowManifest.workflows
    .filter((workflow) => workflow.authenticationStage === "pre-authentication"
      || workflow.actorClasses?.some((actor) => ["anonymous", "pre-auth-runtime"].includes(actor))
      || workflow.preAuthBoundary?.boundaryMode === "exact-security-definer-function")
    .map((workflow) => workflow.id)
    .sort();
  assert.deepEqual([...boundary.affectedWorkflows].sort(), publicCandidateWorkflowIds, "public or pre-auth workflow lacks an exact public class");
  assert.equal(new Set(boundary.routeClassifications.flatMap((item) => [item.primaryClass])).size, classes.length, "not every public class has an exact route disposition");
  assert.equal(boundary.publicActorModel.humanActorContextExists, false, "public boundary installs a fake human actor");
  assert.equal(boundary.publicActorModel.callerContextTrusted, false, "public boundary trusts caller context");
  assert.equal(boundary.publicActorModel.blankScopeIsWildcard, false, "blank public scope becomes global");

  assert.match(boundary.proofTokenModels.qrRawCompatibility.normalization, /reject.*before any protected read/i, "malformed QR can reach protected reads");
  assert.equal(boundary.proofTokenModels.signedQr.fallbackAfterFailure, false, "invalid signature falls back to raw lookup");
  assert.match(boundary.proofTokenModels.signedQr.signature, /Ed25519/, "signed QR lacks approved signature validation");
  assert.equal(boundary.proofTokenModels.signedQr.unsignedClaimsEstablishAuthority, false, "unsigned token fields establish authority");
  assert.match(boundary.proofTokenModels.signedQr.signature, /JWT_SECRET fallback.*prohibited/i, "legacy signing secret fallback remains authoritative");
  assert(boundary.proofTokenModels.signedQr.requiredClaims.includes("exp"), "signed QR expiry is omitted");
  assert.match(boundary.qrVerificationContract.readiness, /Only a released.*customer-verifiable/i, "unreleased QR becomes publicly visible");
  assert.equal(boundary.proofTokenModels.supportStatus.referenceAloneSufficient, false, "support reference alone grants access");
  assert.equal(boundary.proofTokenModels.supportStatus.emailAloneSufficient, false, "email alone grants public access");
  assert.match(boundary.feedbackContract.tenantRouting, /Body\/query tenant IDs are rejected/i, "public feedback accepts caller-provided tenant authority");
  assert.equal(boundary.publicDownloadContract.databaseRequired, false, "static public download requires protected database access");
  assert(boundary.publicDownloadContract.artifactRequirements.some((item) => /below the release root/i.test(item)), "public download permits arbitrary paths");
  assert(boundary.policyGovernancePublicContentRules.authenticatedOnly.includes("TenantFeatureFlag"), "public policy content exposes internal feature flags");
  assert.equal(boundary.policyGovernancePublicContentRules.publicAlertDisposition, "prohibited-public-access per policy-alert-actor-ceiling-v1", "public alerts are exposed");

  const prohibited = boundary.prohibitedFields.join(" ");
  for (const field of ["passwordHash", "tokenHash", "MFA secrets", "risk score", "device/IP fingerprints", "feature flags", "customer PII"]) assert(prohibited.includes(field), `public prohibited field ${field} is missing`);
  const publicProjectionText = JSON.stringify(boundary.exactPublicProjections);
  for (const field of ["passwordHash", "riskScore", "licenseeId", "manufacturerId", "decisionId", "metadata"]) assert(!publicProjectionText.includes(field), `secret or tenant-private field ${field} enters public projection`);
  const rateClasses = new Set(boundary.rateLimits.map((item) => item.class));
  assert.equal(rateClasses.size, boundary.rateLimits.length, "public rate-limit classes are duplicated");
  for (const limit of boundary.rateLimits) assert(limit.windowSeconds > 0 && limit.ipMaximum > 0 && limit.actorResourceMaximum > 0, `${limit.class} rate limit is missing`);

  const functionIds = new Set(boundary.namedFunctionContracts.map((item) => item.id));
  assert.equal(functionIds.size, boundary.namedFunctionContracts.length, "public function contracts are duplicated");
  for (const fn of boundary.namedFunctionContracts) {
    assert(/^public-fn-[a-z0-9-]+$/.test(fn.id), `${fn.id} is generic or unstable`);
    assert.equal(fn.genericInputsAllowed, false, `${fn.id} is a generic pre-auth function`);
    assert.equal(fn.dynamicSqlAllowed, false, `${fn.id} permits dynamic SQL`);
    assert.equal(fn.publicExecuteAllowed, false, `${fn.id} grants PUBLIC execution`);
    assert.equal(fn.fixedSearchPath, "pg_catalog", `${fn.id} lacks fixed search path`);
    assert.equal(fn.maximumRows, 1, `${fn.id} permits a public list`);
    assert(fn.arguments?.length && fn.returnColumns?.length && fn.purpose?.trim(), `${fn.id} lacks an exact signature or projection`);
  }
  assert.equal(boundary.namedFunctionSecurity.securityDefiner, true, "public functions lack the reviewed execution model");
  assert.equal(boundary.namedFunctionSecurity.callerSetContextTrusted, false, "public functions trust caller-set context");
  assert.match(boundary.namedFunctionSecurity.owner, /NOLOGIN/, "public function owner is login-capable");
  const existingPreAuthIds = new Set(preAuthManifest.functions.map((item) => item.id));
  for (const mapping of boundary.preAuthMappings.filter((item) => ["one-time-token-consumption", "email-link-verification"].includes(item.class))) {
    const fn = preAuthManifest.functions.find((item) => item.id === mapping.functionId);
    assert(fn?.oneTimeToken === true && fn.expiryRequired === true && /lock/i.test(fn.rowLockingRequirements), `${mapping.functionId} token replay or expiry semantics are incomplete`);
  }
  const profileNames = new Set(Object.keys(boundary.projectionProfiles));
  const rateNames = new Set(boundary.rateLimits.map((item) => item.class));
  const tableById = new Map(tableManifest.tables.map((item) => [item.id, item]));
  const workflows = new Map(workflowManifest.workflows.map((item) => [item.id, item]));
  for (const classification of boundary.workflowClassifications) {
    assert(classes.includes(classification.primaryClass), `${classification.workflowId} has no exact public class`);
    assert(rateNames.has(classification.rateLimitClass), `${classification.workflowId} lacks a public rate-limit class`);
    assert(functionIds.has(classification.functionId) || existingPreAuthIds.has(classification.functionId), `${classification.workflowId} lacks an exact function contract`);
    if (classification.projectionProfile) {
      assert(profileNames.has(classification.projectionProfile), `${classification.workflowId} lacks an exact projection profile`);
      for (const projection of boundary.projectionProfiles[classification.projectionProfile]) {
        const table = tableById.get(projection.tableId);
        assert(table, `${classification.workflowId} references unknown ${projection.tableId}`);
        const columns = new Set(table.schemaEvidence.fields.map((field) => field.name));
        for (const values of Object.values(projection.commands)) for (const column of values) assert(columns.has(column), `${classification.workflowId} references unknown ${projection.tableId}.${column}`);
      }
    }
    const workflow = workflows.get(classification.workflowId);
    assert(workflow, `public-read contract references missing workflow ${classification.workflowId}`);
    assert.equal(workflow.publicReadContractBoundaryId, boundary.id, `${classification.workflowId} lacks public-read boundary reference`);
    assert.equal(workflow.publicAccessClass, classification.primaryClass, `${classification.workflowId} public class drifted`);
    assert.equal(workflow.publicReadFunctionId, classification.functionId, `${classification.workflowId} public function drifted`);
    assert(!workflow.unresolvedDecisions.includes(boundary.decisionId), `${classification.workflowId} retains resolved public-read decision`);
    assert.notEqual(workflow.contextBoundaryStatus, "implemented", `${classification.workflowId} is falsely implemented`);
    for (const ruleId of workflow.commandRuleIds) {
      const rule = commandManifest.rules.find((item) => item.id === ruleId);
      assert.equal(rule?.publicReadContractBoundaryId, boundary.id, `${ruleId} lacks public-read boundary ID`);
      assert.equal(rule.publicAccessClass, classification.primaryClass, `${ruleId} public class drifted`);
      assert.equal(rule.publicFunctionId, classification.functionId, `${ruleId} public function drifted`);
      assert.equal(rule.requiresNamedFunction, true, `${ruleId} permits direct public table access`);
      assert.equal(rule.minimumAssurance, "none", `${ruleId} invents authenticated public assurance`);
      assert.deepEqual(rule.actorClasses, ["anonymous", "pre-auth-runtime"], `${ruleId} trusts a role string or human actor`);
      assert.equal(rule.requiresAuditEvent, true, `${ruleId} omits public attribution`);
      if (classification.projectionProfile) {
        const projection = boundary.projectionProfiles[classification.projectionProfile].find((item) => item.tableId === rule.tableId);
        assert.deepEqual(rule.allowedColumns, projection?.commands?.[rule.command] || [], `${ruleId} public projection drifted`);
      }
    }
  }
  assert.deepEqual(boundary.preAuthMappings.map((item) => item.functionId).sort(), [...existingPreAuthIds].sort(), "public pre-auth mapping does not preserve the seven exact functions");
  assert(boundary.enumerationProtections.some((item) => /No public list endpoint/.test(item)), "public list pagination/cardinality is unbounded");
  assert.match(boundary.failureSemantics.accountOrInvitationRequest.body, /If the request is eligible/i, "account or invitation response reveals existence");
  assert.equal(boundary.auditScanAttribution.sameTransaction, true, "public attribution is not atomic");
  assert.equal(boundary.auditScanAttribution.payloadLogging, false, "public proof or payload is logged");
  assert.equal(boundary.architectureFreeze.workflowLevelAuthorizationFrozen, true, "workflow authorization architecture is not frozen");
  assert.equal(boundary.architectureFreeze.unresolvedBlockingContextDecisions, 0, "public decision leaves blocking context decisions");
  assert.equal(boundary.architectureFreeze.nextStage, "full-system-runtime-implementation", "public decision lacks the runtime next-stage marker");
  assert.equal(boundary.architectureFreeze.newBroadProductDecisionCategoriesAllowed, false, "architecture freeze permits vague new decision categories");
  const decision = decisionManifest.decisions.find((item) => item.id === boundary.decisionId);
  assert.equal(decision?.status, "resolved", "public-read decision is unresolved");
  assert.equal(decisionManifest.decisions.filter((item) => item.blockingStatus === "blocking" && item.status !== "resolved").length, 0, "architecture freeze retains an unresolved blocking decision");
  assert.equal(decision.selectedBoundary, boundary.id, "public-read decision boundary drifted");
  assert.equal(decision.resolution?.authority, "documents/security/rls-program/public-read-contract.json", "public-read decision lacks authority");
  assert.deepEqual(decision.affectedWorkflows, boundary.affectedWorkflows, "public-read decision workflow coverage drifted");
  assert.match(boundary.implementationStatus, /runtime.*pending/i, "public-read decision is falsely implemented");
  assert(boundary.postgresqlCertificationRequirements?.length >= 10, "public-read decision lacks PostgreSQL certification semantics");
  return true;
};
export const validatePreAuthFunctions = (manifest, workflowManifest, commandManifest, identityManifest, tableManifest) => {
  assert(manifest?.functions?.length, "pre-auth function manifest is missing");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  const tables = new Map(tableManifest.tables.map((table) => [table.id, table]));
  const identities = new Map(identityManifest.identities.map((identity) => [identity.id, identity]));
  const functionIds = new Set(manifest.functions.map((fn) => fn.id));
  assert.equal(functionIds.size, manifest.functions.length, "pre-auth function IDs must be unique");
  const selectedWorkflows = workflowManifest.workflows.filter((workflow) => workflow.authorizationBoundaryType === "pre-auth-security-function" || workflow.preAuthBoundary);
  assert.deepEqual(selectedWorkflows.map((workflow) => workflow.id).sort(), Object.keys(PREAUTH_WORKFLOW_BOUNDARIES).sort(), "a pre-auth workflow lacks a boundary or the reviewed selector drifted");
  const canonicalFunctions = new Map(buildPreAuthFunctionManifest().functions.map((fn) => [fn.id, fn]));
  const forbiddenArgument = /(?:table|sql|column|predicate|query|json|role|tenant|schema)/i;
  for (const fn of manifest.functions) {
    assert(/^preauth-fn-[a-z0-9-]+$/.test(fn.id) && /^[a-z][a-z0-9_]*$/.test(fn.sqlFunctionName), `${fn.id} has an unstable ID or function name`);
    assert.equal(fn.sqlSchema, "app_auth", `${fn.id} must use app_auth`);
    assert(fn.arguments.length && new Set(fn.arguments.map((item) => item.name)).size === fn.arguments.length, `${fn.id} lacks an exact argument list`);
    for (const item of fn.arguments) {
      assert(item.name && item.type && typeof item.nullable === "boolean", `${fn.id} has an incomplete argument`);
      assert(!forbiddenArgument.test(item.name) && !/^(?:json|jsonb|regclass|name)$/i.test(item.type), `${fn.id} accepts generic query input`);
    }
    assert.deepEqual(fn.arguments, canonicalFunctions.get(fn.id)?.arguments, `${fn.id} exact argument signature drifted`);
    assert(fn.returnColumns.length && new Set(fn.returnColumns.map((item) => item.name)).size === fn.returnColumns.length, `${fn.id} lacks exact return columns`);
    for (const item of fn.returnColumns) assert(item.name && item.type && typeof item.nullable === "boolean", `${fn.id} has an incomplete return column`);
    assert.deepEqual(fn.returnColumns, canonicalFunctions.get(fn.id)?.returnColumns, `${fn.id} exact return columns drifted`);
    assert.equal(fn.publicExecutionDenied, true, `${fn.id} allows PUBLIC execute`);
    assert.equal(fn.restrictedReadExecutionDenied, true, `${fn.id} allows restricted-read execute`);
    assert.equal(fn.appExecutionStatus.startsWith("denied"), true, `${fn.id} allows authenticated-app execution`);
    assert.equal(fn.fixedSearchPath, "pg_catalog,public", `${fn.id} search_path is not fixed`);
    assert.equal(fn.dynamicSqlAllowed, false, `${fn.id} permits dynamic SQL`);
    assert.equal(fn.genericQueryInputsAllowed, false, `${fn.id} permits generic query input`);
    assert.equal(fn.fullyQualifiedApplicationObjects, true, `${fn.id} may use unqualified application objects`);
    assert.equal(fn.callerOwnedFunctionsAllowed, false, `${fn.id} may call caller-owned functions`);
    assert.equal(fn.callerSetContextTrusted, false, `${fn.id} trusts caller-set app context`);
    assert.equal(identities.get(fn.ownerIdentity)?.loginExpectation, "NOLOGIN", `${fn.id} owner may LOGIN`);
    assert.deepEqual(fn.executableRuntimeIdentities, ["identity-pre-auth-app"], `${fn.id} has broad execution identities`);
    assert(["STABLE", "VOLATILE"].includes(fn.volatility) && ["SAFE", "UNSAFE"].includes(fn.parallelSafety), `${fn.id} lacks volatility/parallel classification`);
    assert(fn.inputNormalization && fn.duplicateStateBehavior && fn.rowLockingRequirements && fn.replayProtection && fn.transactionRequirements, `${fn.id} lacks fail-closed behavior`);
    assert(fn.allowScenarios.length && fn.denyScenarios.length && fn.p2TestRequirements.length, `${fn.id} lacks scenarios or P2 tests`);
    for (const workflowId of fn.supportingWorkflowIds) assert(workflows.has(workflowId), `${fn.id} references unknown workflow ${workflowId}`);
    for (const tableId of [...fn.tablesRead, ...fn.tablesWritten]) assert(tables.has(tableId), `${fn.id} references unknown table ${tableId}`);
    for (const entry of fn.exactAllowedColumns) {
      const table = tables.get(entry.tableId);
      assert(table && policyCommands.has(entry.command) && entry.columns.length, `${fn.id} has invalid table/command columns`);
      const schemaColumns = new Set(table.schemaEvidence.fields.map((field) => field.name));
      for (const name of entry.columns) assert(schemaColumns.has(name), `${fn.id} references unknown ${entry.tableId}.${name}`);
    }
    for (const exposure of fn.secretColumnExposures) assert(exposure.justification?.trim(), `${fn.id} exposes a secret without justification`);
    if (fn.oneTimeToken) {
      assert.equal(fn.expiryRequired, true, `${fn.id} token flow lacks expiry`);
      assert(!/not-applicable/i.test(fn.oneTimeConsumptionBehavior), `${fn.id} token flow lacks one-time semantics`);
      assert(fn.expiryChecks && !/not-applicable/i.test(fn.expiryChecks), `${fn.id} token flow lacks expiry checks`);
    }
  }
  const resetRequest = manifest.functions.find((fn) => fn.id === "preauth-fn-request-password-reset");
  assert.equal(resetRequest.externalResponseMode, "constant-success", "reset request reveals account existence");
  assert.equal(resetRequest.returnsAccountExistenceToExternalCaller, false, "reset request reveals account existence");
  const resetCompletion = manifest.functions.find((fn) => fn.id === "preauth-fn-consume-password-reset");
  assert(/FOR UPDATE/i.test(resetCompletion.rowLockingRequirements) && /same transaction|transaction/i.test(resetCompletion.oneTimeConsumptionBehavior), "reset completion is non-atomic");
  const invitation = manifest.functions.find((fn) => fn.id === "preauth-fn-consume-invitation");
  assert(/cannot create or promote SUPER_ADMIN\/PLATFORM_SUPER_ADMIN/i.test(invitation.roleCeiling), "invitation lacks platform-role ceiling");
  const verification = manifest.functions.find((fn) => fn.id === "preauth-fn-consume-email-verification");
  assert(/sole account authority/i.test(verification.tokenBindingRequirements), "email verification is not account-bound");
  const preAuth = identities.get("identity-pre-auth-app");
  assert.equal(preAuth.tablePrivilegeMode, "none", "pre-auth role has direct table privileges");
  assert.deepEqual(preAuth.directTablePrivileges, [], "pre-auth role has direct table privileges");
  assert.deepEqual(new Set(preAuth.approvedFunctionIds), functionIds, "pre-auth role function allowlist drifted");
  for (const workflow of selectedWorkflows) {
    assert(workflow.preAuthBoundary, `${workflow.id} pre-auth workflow lacks a boundary`);
    assert.equal(workflow.preAuthBoundary.status, "resolved", `${workflow.id} lacks a resolved pre-auth boundary`);
    assert(!workflow.unresolvedDecisions.includes("decision-pre-auth-boundary"), `${workflow.id} retains unresolved pre-auth semantics`);
    if (workflow.preAuthBoundary.boundaryMode === "exact-security-definer-function") {
      assert(functionIds.has(workflow.preAuthBoundary.functionId), `${workflow.id} references unknown function`);
      assert.equal(workflow.preAuthFunctionId, workflow.preAuthBoundary.functionId, `${workflow.id} lacks its exact named function reference`);
      for (const rule of commandManifest.rules.filter((item) => item.supportingWorkflowIds.includes(workflow.id))) {
        assert.equal(rule.requiresNamedFunction, true, `${workflow.id} command degraded to an ordinary policy`);
        assert.equal(rule.preAuthFunctionId, workflow.preAuthBoundary.functionId, `${workflow.id} command lacks its exact function`);
      }
    }
    if (workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context") {
      assert(!workflow.actorClasses.includes("pre-auth-runtime") && !workflow.runtimeIdentities.includes("identity-pre-auth-app"), `${workflow.id} moved workflow retains pre-auth access`);
      for (const rule of commandManifest.rules.filter((item) => item.supportingWorkflowIds.includes(workflow.id))) assert(!rule.actorClasses.includes("pre-auth-runtime") && !rule.runtimeIdentities.includes("identity-pre-auth-app"), `${workflow.id} moved rule retains pre-auth access`);
    }
  }
  return true;
};
export const validateWorkerBoundaries = (manifest, workflowManifest, commandManifest, identityManifest, tableManifest) => {
  assert.equal(manifest?.boundaries?.length, 3, "worker boundary manifest must contain the three registered execution paths");
  const boundaryIds = new Set(manifest.boundaries.map((boundary) => boundary.id));
  assert.equal(boundaryIds.size, manifest.boundaries.length, "worker boundary IDs must be unique");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  const rules = new Map(commandManifest.rules.map((rule) => [rule.id, rule]));
  const identities = new Map(identityManifest.identities.map((identity) => [identity.id, identity]));
  const tables = new Set(tableManifest.tables.map((table) => table.id));
  const selected = workflowManifest.workflows.filter((workflow) => ["worker", "scheduled"].includes(workflow.executionSurface) && workflow.authorizationBoundaryType === "restricted-worker");
  assert.deepEqual(selected.map((workflow) => workflow.id).sort(), manifest.boundaries.flatMap((boundary) => boundary.workflowIds).sort(), "a worker workflow lacks a boundary");
  const classes = new Set(["actor-derived-job", "tenant-scoped-system-job", "platform-scoped-system-job", "scheduled-maintenance-job", "operator-triggered-job", "migration-or-bootstrap-job", "legacy-or-retire"]);
  const genericInput = /(?:query|json|sql|table|column|predicate|role|tenant)/i;
  for (const boundary of manifest.boundaries) {
    assert(classes.has(boundary.workerClass), `${boundary.id} has unresolved worker class`);
    assert(["identity-worker", "identity-scheduled-job"].includes(boundary.runtimeIdentity), `${boundary.id} has invalid runtime identity`);
    assert.equal(boundary.assurance, "system-verified", `${boundary.id} uses human assurance`);
    assert.equal(boundary.platformAdminContextAllowed, false, `${boundary.id} sets platform-admin context`);
    assert.equal(boundary.humanImpersonationAllowed, false, `${boundary.id} impersonates a human actor`);
    assert(boundary.workflowIds.length === 1 && boundary.workflowIds.every((id) => workflows.has(id)), `${boundary.id} references unknown workflows`);
    const workflow = workflows.get(boundary.workflowIds[0]);
    assert.equal(workflow.workerBoundaryId, boundary.id, `${workflow.id} lacks worker-boundary ID`);
    assert.equal(workflow.scopeVerificationMethod, boundary.scopeVerificationMethod, `${workflow.id} scope verification drifted`);
    assert.match(boundary.durableJobTableOrPayloadSource, /durable|table-/i, `${boundary.id} trusts an unverified payload`);
    assert(!/payload (?:is|alone is) authority|trust (?:the )?json/i.test(boundary.scopeVerificationMethod), `${boundary.id} trusts an unverified payload`);
    assert(boundary.idempotencyStrategy?.keySource && boundary.idempotencyStrategy?.uniquenessBoundary && boundary.idempotencyStrategy?.conflictBehavior && boundary.idempotencyStrategy?.replayResult, `${boundary.id} lacks idempotency`);
    assert.equal(boundary.idempotencyStrategy.conflictingPayloadDenied, true, `${boundary.id} permits conflicting replay payloads`);
    assert.equal(boundary.conflictingReplayPayloadDenied, true, `${boundary.id} permits conflicting replay payloads`);
    assert(boundary.concurrencyControl?.type && boundary.concurrencyControl?.rule && boundary.concurrencyControl?.databaseEnforced, `${boundary.id} mutation lacks concurrency enforcement`);
    assert(boundary.retryPolicy?.maxAttempts > 0 && boundary.retryPolicy?.backoffSeconds && boundary.retryPolicy?.retryableStates?.length, `${boundary.id} lacks bounded retry semantics`);
    assert.equal(boundary.retryPolicy.duplicateSideEffectsAllowed, false, `${boundary.id} retries can duplicate side effects`);
    assert.equal(boundary.sideEffectsDeduplicated, true, `${boundary.id} retries can duplicate side effects`);
    assert(boundary.deadLetterBehavior && boundary.cancellationSemantics && boundary.replayProtection, `${boundary.id} lacks replay/dead-letter/cancellation semantics`);
    assert(Number.isInteger(boundary.maximumJobAgeSeconds) && boundary.maximumJobAgeSeconds > 0, `${boundary.id} lacks maximum job age`);
    assert.equal(boundary.unknownJobTypesRejected, true, `${boundary.id} accepts unknown job types`);
    assert(boundary.acceptedJobTypes.length && new Set(boundary.acceptedJobTypes).size === boundary.acceptedJobTypes.length, `${boundary.id} lacks exact job types`);
    assert(boundary.auditEventRequirement?.required && boundary.auditEventRequirement.fields.includes("job_id") && boundary.auditEventRequirement.fields.includes("system_identity"), `${boundary.id} audit lacks job identity`);
    assert.equal(boundary.auditEventRequirement.executorAttribution, boundary.runtimeIdentity, `${boundary.id} audit executor identity drifted`);
    assert.deepEqual(boundary.requiredTransactionContext.keys, WORKER_CONTEXT_KEYS, `${boundary.id} worker context keys drifted`);
    assert(boundary.requiredTransactionContext.transactionLocal && boundary.requiredTransactionContext.sameTransactionAsProtectedQueries && boundary.requiredTransactionContext.derivedFromVerifiedServerEvidence && boundary.requiredTransactionContext.clearsAtTransactionEnd, `${boundary.id} context is not transaction-local verified evidence`);
    assert.equal(boundary.requiredTransactionContext.platformAdminContextAllowed, false, `${boundary.id} sets platform-admin context`);
    assert(!boundary.requiredTransactionContext.keys.includes("app.role"), `${boundary.id} overloads human role context`);
    assert(boundary.exactCommandRuleIds.length && boundary.exactCommandRuleIds.every((id) => rules.has(id)), `${boundary.id} lacks exact command rules`);
    for (const tableCommand of boundary.tableCommands) for (const command of tableCommand.commands) assert(boundary.exactCommandRuleIds.some((id) => rules.get(id)?.tableId === tableCommand.tableId && rules.get(id)?.command === command), `${boundary.id} lacks exact ${tableCommand.tableId}:${command} command rule`);
    for (const ruleId of boundary.exactCommandRuleIds) {
      const rule = rules.get(ruleId);
      assert.equal(rule.workerBoundaryId, boundary.id, `${ruleId} lacks worker-boundary ID`);
      assert.equal(rule.minimumAssurance, "system-verified", `${ruleId} uses human assurance`);
      assert.deepEqual(rule.runtimeIdentities, [boundary.runtimeIdentity], `${ruleId} uses wrong runtime identity`);
    }
    for (const tableId of [...boundary.tablesRead, ...boundary.tablesWritten]) assert(tables.has(tableId), `${boundary.id} references unknown table ${tableId}`);
    if (boundary.runtimeIdentity === "identity-scheduled-job") assert.equal(workflow.executionSurface, "scheduled", `${boundary.id} scheduled boundary has wrong surface`);
    if (workflow.executionSurface === "scheduled") assert.equal(boundary.runtimeIdentity, "identity-scheduled-job", `${boundary.id} scheduled job uses worker identity`);
    if (boundary.id === "worker-boundary-scheduled-compliance-packs") {
      assert(!boundary.tableCommands.some((item) => item.tableId === "table-user"), `${boundary.id} retains human impersonation`);
      assert(boundary.tableCommands.some((item) => item.tableId === "table-scheduled-job-credential" && item.authority === "worker-fn-claim-compliance-pack-slice"), `${boundary.id} lacks durable scheduled identity`);
    }
    if (boundary.workerClass === "actor-derived-job") assert(boundary.actorFields.some((field) => /initiating_user_id/.test(field)) && boundary.actorFields.some((field) => /executing_system_identity/.test(field)), `${boundary.id} lacks initiating actor and executor identity`);
    const fn = boundary.namedFunctionRequirement;
    assert.equal(fn.genericQueryInputsAllowed, false, `${boundary.id} permits a generic worker function`);
    if (fn.required) {
      assert(/^worker-fn-[a-z0-9-]+$/.test(fn.functionId) && fn.sqlSchema === "app_rls" && /^[a-z][a-z0-9_]*$/.test(fn.sqlFunctionName), `${boundary.id} has invalid named worker function`);
      assert(fn.arguments.length && fn.arguments.every((item) => item.name && item.type && !genericInput.test(item.name) && !/^(?:json|jsonb|regclass|name)$/i.test(item.type)), `${boundary.id} permits a generic worker function`);
      assert.equal(fn.securityMode, boundary.runtimeIdentity === "identity-scheduled-job" ? "DEFINER" : "INVOKER", `${boundary.id} worker function may bypass caller RLS`);
      assert.equal(identities.get(fn.ownerIdentity)?.loginExpectation, "NOLOGIN", `${boundary.id} worker function owner may LOGIN`);
      assert.equal(fn.publicExecutionDenied, true, `${boundary.id} worker function allows PUBLIC execute`);
      assert.equal(fn.fixedSearchPath, boundary.runtimeIdentity === "identity-scheduled-job" ? "pg_catalog,public" : "pg_catalog", `${boundary.id} worker function search_path is not fixed`);
      assert.equal(fn.executableRuntimeIdentity, boundary.runtimeIdentity, `${boundary.id} worker function executor drifted`);
    }
    assert(boundary.allowedScenarios.length && boundary.deniedScenarios.length && boundary.p2TestRequirements.length, `${boundary.id} lacks scenarios or P2 tests`);
  }
  for (const rule of commandManifest.rules.filter((rule) => rule.requiresRestrictedWorkerBoundary || rule.actorClasses.some((actor) => ["worker", "scheduled-job"].includes(actor)))) assert(boundaryIds.has(rule.workerBoundaryId), `${rule.id} references worker access without a worker-boundary ID`);
  for (const identityId of ["identity-worker", "identity-scheduled-job"]) {
    const identity = identities.get(identityId);
    assert.deepEqual(new Set(identity.approvedWorkerBoundaryIds), new Set(manifest.boundaries.filter((boundary) => boundary.runtimeIdentity === identityId).map((boundary) => boundary.id)), `${identityId} boundary allowlist drifted`);
    assert.match(identity.tablePrivilegeMode, /command-specific/i, `${identityId} has broad table access`);
    assert.equal(identity.directPreAuthFunctionExecution, false, `${identityId} may execute pre-auth functions`);
  }
  assert.notEqual(identities.get("identity-worker").credentialSource, identities.get("identity-scheduled-job").credentialSource, "scheduled identity collapsed into worker identity");
  return true;
};
export const validateObjectOwnershipChain = (manifest, tableManifest, identityManifest, preAuthManifest, workerManifest) => {
  assert.equal(manifest?.status, "architecture-resolved", "object ownership chain is unresolved");
  assert.equal(manifest.postgresVersion, "18", "ownership contract must target PostgreSQL 18");
  const identities = new Map(identityManifest.identities.map((identity) => [identity.id, identity]));
  const ownerIds = new Set(["identity-table-owner", "identity-auth-function-owner"]);
  for (const ownerId of ownerIds) {
    const identity = identities.get(ownerId);
    assert.equal(identity.loginExpectation, "NOLOGIN", `${ownerId} protected table owner is LOGIN`);
    assert.equal(identity.roleAttributes?.login, false, `${ownerId} protected table owner is LOGIN`);
    assert.equal(identity.roleAttributes?.superuser, false, `${ownerId} owner may be superuser`);
    assert.equal(identity.roleAttributes?.bypassRls, false, `${ownerId} owner may use BYPASSRLS`);
  }
  const runtime = identityManifest.identities.filter((identity) => identity.loginExpectation !== "NOLOGIN");
  for (const identity of runtime) {
    assert.equal(identity.protectedObjectOwnershipAllowed, false, `${identity.id} runtime role receives ownership`);
    assert.deepEqual(identity.ownerRoleMemberships, [], `${identity.id} runtime role is a member of owner role`);
  }
  const migration = identities.get("identity-migration");
  assert.equal(migration.enduringObjectOwnershipAllowed, false, "migration is allowed to remain owner");
  assert.equal(migration.ownerMembershipResidueAllowed, false, "migration may retain owner membership");
  assert.equal(migration.migrationCompletionRequiresCatalogVerification, true, "migration catalog verification is removed");
  for (const table of tableManifest.tables) {
    assert.equal(table.physicalOwnerRole, "identity-table-owner", `${table.id} runtime or migration role receives ownership`);
    assert.equal(table.migrationOwnershipAllowedAtCompletion, false, `${table.id} migration is allowed to remain owner`);
    assert.equal(table.objectOwnershipRuleId, "ownership-tables", `${table.id} lacks ownership rule`);
  }
  assert.equal(manifest.objectClasses.length, 17, "a sequence/type/view ownership rule is missing");
  const classes = new Map(manifest.objectClasses.map((rule) => [rule.objectClass, rule]));
  for (const objectClass of ["tables", "table-owned-sequences", "standalone-sequences", "indexes", "constraints", "policies", "schemas", "functions", "procedures", "enum-types", "composite-types", "views", "materialized-views", "triggers", "publications", "subscriptions", "extensions"]) {
    const rule = classes.get(objectClass);
    assert(rule?.creationIdentity && rule.expectedOwner && rule.transferMechanism && rule.postTransferVerification && rule.rollbackBehavior, `${objectClass} ownership rule is missing`);
  }
  assert.equal(manifest.recommendedTransferModel.id, "clean-room-broker-per-object-transfer", "ownership transfer is not clean-room brokered");
  assert.equal(manifest.recommendedTransferModel.migrationOwnerMembership, "transactional-admin-phase-only", "migration receives standing owner membership");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.member, "identity-migration", "temporary membership targets the wrong identity");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.inherit, false, "temporary migration membership is inheriting");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.admin, false, "temporary migration membership has ADMIN");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.set, true, "temporary migration transfer lacks exact SET authority");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.runtimeCredentialUsed, false, "ownership transfer uses the migration runtime credential");
  assert.equal(manifest.recommendedTransferModel.temporaryMembership.revokedBeforeSuccess, true, "revocation step is removed");
  assert.equal(manifest.fallbackTransferModel.id, "none", "an ownership transfer fallback is enabled");
  assert.equal(manifest.fallbackTransferModel.successWithActiveMembershipAllowed, false, "migration failure may leave membership active");
  for (const rule of manifest.objectClasses) {
    assert.match(rule.rollbackBehavior, /drop the fresh green database/i, `${rule.id} retains object-level rollback`);
    assert.match(rule.rollbackBehavior, /blue database remains untouched/i, `${rule.id} may mutate blue during rollback`);
  }
  const schemas = new Map(manifest.schemaOwnershipRules.map((rule) => [rule.schema, rule]));
  assert.equal(schemas.get("app_auth")?.expectedOwner, "identity-auth-function-owner", "app_auth ownership changes");
  assert.equal(schemas.get("app_rls")?.expectedOwner, "identity-table-owner", "app_rls has the wrong owner");
  for (const schema of ["public", "app_rls", "app_auth", "prisma-created"]) {
    assert.equal(schemas.get(schema)?.publicCreate, false, `${schema} PUBLIC CREATE is restored`);
    assert.equal(schemas.get(schema)?.runtimeCreate, false, `${schema} runtime CREATE is allowed`);
  }
  const preAuth = new Map(manifest.approvedFunctionOwnerBoundaries.preAuth.map((fn) => [fn.functionId, fn]));
  assert.equal(preAuth.size, preAuthManifest.functions.length, "pre-auth function ownership allowlist drifted");
  for (const fn of preAuthManifest.functions) {
    assert.equal(preAuth.get(fn.id)?.owner, "identity-auth-function-owner", `${fn.id} pre-auth function has the wrong owner`);
    assert.equal(preAuth.get(fn.id)?.securityMode, "DEFINER", `${fn.id} pre-auth function security mode drifted`);
  }
  const workers = new Map(manifest.approvedFunctionOwnerBoundaries.worker.map((fn) => [fn.functionId, fn]));
  for (const boundary of workerManifest.boundaries.filter((item) => item.namedFunctionRequirement.required)) {
    const fn = workers.get(boundary.namedFunctionRequirement.functionId);
    const scheduled = boundary.runtimeIdentity === "identity-scheduled-job";
    assert.equal(fn?.owner, scheduled ? "identity-auth-function-owner" : "identity-table-owner", `${boundary.id} worker function has the wrong owner`);
    if (scheduled) assert.equal(fn?.securityMode, "DEFINER", `${boundary.id} scheduled function must remain SECURITY DEFINER`);
    else assert.equal(fn?.securityMode, "INVOKER", `${boundary.id} SECURITY INVOKER helper becomes SECURITY DEFINER`);
  }
  assert.deepEqual(manifest.defaultPrivilegeRules.publicGrants, [], "default privileges grant PUBLIC access broadly");
  assert.deepEqual(manifest.defaultPrivilegeRules.runtimeGrants, [], "default privileges grant table access broadly");
  assert.equal(manifest.defaultPrivilegeRules.commandGrantSource, "documents/security/rls-program/command-semantics.json", "runtime grants do not come from command semantics");
  assert.equal(manifest.migrationCompletionGate.catalogVerificationRequired, true, "migration catalog verification is removed");
  assert.equal(manifest.migrationCompletionGate.transferFailureReportsSuccess, false, "ownership-transfer failure can report success");
  assert.equal(manifest.migrationCompletionGate.revocationFailureReportsSuccess, false, "migration failure may leave membership active");
  assert.equal(manifest.migrationCompletionGate.ownershipResidueAllowed, 0, "migration is allowed to remain owner");
  assert.equal(manifest.migrationCompletionGate.runtimeOwnedObjectsAllowed, 0, "runtime role receives ownership");
  assert(manifest.catalogVerification.length >= 9, "migration catalog verification is removed");
  assert(manifest.catalogVerification.some((check) => /membership/i.test(`${check.id} ${check.proves}`)), "membership catalog verification is removed");
  assert.deepEqual(manifest.migrationOnlyTables.map((item) => item.tableId).sort(), ["table-batch-print-pack-token", "table-print-render-token"], "migration-only table ownership is unresolved");
  for (const table of manifest.migrationOnlyTables) assert.equal(table.owner, "identity-table-owner", `${table.tableId} remains migration-owned`);
  return true;
};
export const validateOperatorBoundaries = (manifest, workflowManifest, commandManifest, identityManifest) => {
  assert.equal(manifest?.status, "architecture-resolved", "operator administration is unresolved");
  assert.equal(manifest.arbitrarySqlAllowed, false, "arbitrary SQL is allowed");
  assert.deepEqual(new Set(manifest.actionClasses), new Set(OPERATOR_ACTION_CLASSES), "operator action classes drifted");
  const boundaries = new Map(manifest.boundaries.map((boundary) => [boundary.id, boundary]));
  assert.equal(boundaries.size, manifest.boundaries.length, "operator boundary IDs must be unique");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  const rules = new Map(commandManifest.rules.map((rule) => [rule.id, rule]));
  const identities = new Map(identityManifest.identities.map((identity) => [identity.id, identity]));
  const selectedWorkflows = workflowManifest.workflows.filter((workflow) => workflow.commandActorClasses?.some((actor) => ["operator-admin", "break-glass"].includes(actor)));
  const selectedRules = commandManifest.rules.filter((rule) => rule.actorClasses.some((actor) => ["operator-admin", "break-glass"].includes(actor)));
  assert(selectedWorkflows.length && selectedRules.length, "operator selector is empty");
  for (const workflow of selectedWorkflows) {
    assert(boundaries.has(workflow.operatorBoundaryId), `${workflow.id} operator rule lacks a boundary`);
    assert.equal(workflow.operatorBoundaryStatus, "resolved", `${workflow.id} operator boundary is unresolved`);
    assert(!workflow.unresolvedDecisions.includes("decision-operator-administration"), `${workflow.id} retains unresolved operator decision`);
  }
  for (const rule of selectedRules) {
    assert(rule.operatorBoundaryIds?.length && rule.operatorBoundaryIds.every((id) => boundaries.has(id)), `${rule.id} operator rule lacks a boundary`);
    assert.equal(rule.operatorBoundaryStatus, "resolved", `${rule.id} operator boundary is unresolved`);
  }
  const secretPattern = /password|token.?hash|secret|private.?key|backup.?code|credential.?public.?key/i;
  const sensitiveClasses = new Set(OPERATOR_ACTION_CLASSES.filter((actionClass) => !["read-diagnostics", "catalog-verification", "prohibited"].includes(actionClass)));
  for (const boundary of manifest.boundaries) {
    assert(/^operator-boundary-[a-z0-9-]+$/.test(boundary.id) && OPERATOR_ACTION_CLASSES.includes(boundary.actionClass), `${boundary.id} has invalid class or ID`);
    assert(boundary.environmentAvailability.length && boundary.environmentAvailability.every((environment) => ["development", "staging", "production"].includes(environment)), `${boundary.id} lacks environment availability`);
    assert(["operator-admin", "break-glass"].includes(boundary.actorClass) && ["identity-operator", "identity-production-break-glass"].includes(boundary.runtimeIdentity), `${boundary.id} has invalid actor or runtime identity`);
    assert(["named-procedure", "operator-command", "prohibited"].includes(boundary.exactCommandOrNamedProcedure?.kind) && boundary.exactCommandOrNamedProcedure?.identifier, `${boundary.id} lacks an exact command or named procedure`);
    assert.equal(boundary.exactCommandOrNamedProcedure.arbitraryArgumentsAllowed, false, `${boundary.id} allows arbitrary SQL or arguments`);
    assert.equal(boundary.arbitrarySqlAllowed, false, `${boundary.id} arbitrary SQL is allowed`);
    assert.equal(boundary.objectOwnershipAllowed, false, `${boundary.id} operator owns an object`);
    assert.equal(boundary.ownerRoleMembershipAllowed, false, `${boundary.id} operator has owner-role membership`);
    assert.equal(boundary.setRoleAllowed, false, `${boundary.id} SET ROLE is enabled`);
    assert.equal(boundary.bypassRlsAllowed, false, `${boundary.id} BYPASSRLS is enabled`);
    assert.equal(boundary.superuserAllowed, false, `${boundary.id} superuser is enabled`);
    assert.equal(boundary.schemaCreateAllowed, false, `${boundary.id} schema CREATE is enabled`);
    assert.equal(boundary.applicationImpersonationAllowed, false, `${boundary.id} application impersonation is enabled`);
    assert.equal(boundary.unrestrictedCrossTenantScope, false, `${boundary.id} cross-tenant scope is unbounded`);
    assert.equal(boundary.roleElevationAllowed, false, `${boundary.id} account recovery permits platform-admin promotion`);
    assert.equal(boundary.tenantReassignmentAllowed, false, `${boundary.id} tenant reassignment becomes allowed`);
    assert.equal(boundary.auditDeletionAllowed, false, `${boundary.id} audit deletion becomes permitted`);
    assert.equal(boundary.secretOutputAllowed, false, `${boundary.id} diagnostics expose password/token hashes`);
    assert.equal(boundary.sharedCredentialAllowed, false, `${boundary.id} break-glass becomes shared`);
    assert(boundary.requiredAssurance && boundary.approvalRequirement && boundary.approvalClass && typeof boundary.ticketRequirement === "boolean" && typeof boundary.purposeRequirement === "boolean", `${boundary.id} lacks assurance/approval/ticket/purpose semantics`);
    assert(boundary.maximumRowScope && !/unbounded|all tenants/i.test(boundary.maximumRowScope), `${boundary.id} cross-tenant scope is unbounded`);
    assert(boundary.expiryBehavior && boundary.revocationBehavior && boundary.retrySemantics && boundary.auditEventRequirement?.required && boundary.auditEventRequirement?.immutable, `${boundary.id} lacks expiry/revocation/retry/audit semantics`);
    assert(boundary.allowScenarios.length && boundary.denyScenarios.length && boundary.certificationTests.length, `${boundary.id} lacks scenarios or certification tests`);
    if (boundary.actionClass !== "prohibited") assert(boundary.maximumDurationMinutes > 0, `${boundary.id} lacks action expiry`);
    if (boundary.environmentAvailability.includes("production") && boundary.actionClass !== "prohibited") {
      assert.equal(boundary.ticketRequirement, true, `${boundary.id} production ticket requirement is removed`);
      assert.equal(boundary.purposeRequirement, true, `${boundary.id} production purpose requirement is removed`);
    }
    if (sensitiveClasses.has(boundary.actionClass)) assert.equal(boundary.approvalRequirement.required, true, `${boundary.id} sensitive action approval requirement is removed`);
    if (boundary.actorClass === "break-glass" && boundary.actionClass !== "prohibited") {
      assert.equal(boundary.environmentAvailability.length, 1, `${boundary.id} break-glass is not production-only`);
      assert.equal(boundary.environmentAvailability[0], "production", `${boundary.id} break-glass is not production-only`);
      assert.equal(boundary.automaticRevocation, true, `${boundary.id} break-glass expiry/revocation is removed`);
      assert(boundary.maximumDurationMinutes > 0 && boundary.maximumDurationMinutes <= manifest.maximumBreakGlassLifetimeMinutes, `${boundary.id} break-glass expiry is removed`);
      assert.equal(boundary.approvalRequirement.distinctApprovers, 2, `${boundary.id} break-glass lacks dual approval`);
    }
    if (["account-recovery", "mfa-repair", "session-revocation"].includes(boundary.actionClass)) {
      assert.equal(boundary.roleElevationAllowed, false, `${boundary.id} account recovery permits platform-admin promotion`);
      assert.equal(boundary.tenantReassignmentAllowed, false, `${boundary.id} recovery permits tenant reassignment`);
      assert(/one (?:exact|existing) account|one exact user|sessions for one exact account/i.test(boundary.maximumRowScope), `${boundary.id} recovery is not single-account scoped`);
    }
    if (["read-diagnostics", "catalog-verification"].includes(boundary.actionClass)) {
      assert.equal(boundary.secretOutputAllowed, false, `${boundary.id} diagnostics expose password/token hashes`);
      assert(!boundary.returnedFields.some((field) => secretPattern.test(field)), `${boundary.id} diagnostics expose password/token hashes`);
    }
    for (const workflowId of boundary.workflowIds) assert.equal(workflows.get(workflowId)?.operatorBoundaryId, boundary.id, `${boundary.id} references unmapped workflow`);
    for (const ruleId of boundary.exactCommandRuleIds) assert(rules.get(ruleId)?.operatorBoundaryIds?.includes(boundary.id), `${boundary.id} references unmapped command rule`);
  }
  const activation = boundaries.get("operator-boundary-rls-activation");
  assert(boundaries.has(activation?.rollbackBoundaryId), "production RLS activation lacks rollback");
  for (const requirement of ["stagingEvidenceRequired", "exactReleaseBindingRequired", "exactMigrationSetRequired", "currentCatalogBaselineRequired", "approvalRecordRequired", "rollbackArtifactRequired", "maintenanceWindowRequired", "independentCheckerRequired", "postActivationVerificationRequired"]) assert.equal(activation.productionRequirements?.[requirement], true, `production RLS activation loses ${requirement}`);
  const issuance = boundaries.get("operator-boundary-breakglass-issuance");
  assert.equal(issuance.lifecycle?.length, 11, "break-glass lifecycle is incomplete");
  assert.equal(manifest.maximumBreakGlassLifetimeMinutes, 30, "break-glass expiry is removed");
  const operator = identities.get("identity-operator");
  assert(operator && operator.loginExpectation === "LOGIN" && operator.standingCredential === true, "operator standing restricted identity is missing");
  assert.equal(operator.mayOwnProtectedObjects, false, "operator owns an object");
  assert.deepEqual(operator.ownerRoleMemberships, [], "operator has owner-role membership");
  assert.equal(operator.maySetRole, false, "operator SET ROLE is enabled");
  assert.equal(operator.mayUseBypassRls, false, "operator BYPASSRLS is enabled");
  assert.equal(operator.superuser, false, "operator superuser is enabled");
  assert.equal(operator.unrestrictedSqlAllowed, false, "operator arbitrary SQL is allowed");
  assert.deepEqual(operator.directTablePrivileges, [], "operator has unrestricted DML");
  const breakGlass = identities.get("identity-production-break-glass");
  assert.equal(breakGlass.standingCredential, false, "break-glass is standing");
  assert.equal(breakGlass.sharedCredential, false, "break-glass becomes shared");
  assert.equal(breakGlass.automaticRevocation, true, "break-glass expiry/revocation is removed");
  assert.equal(breakGlass.maximumLifetimeMinutes, 30, "break-glass expiry is removed");
  return true;
};
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
    ["identity-operator", "operator"],
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
