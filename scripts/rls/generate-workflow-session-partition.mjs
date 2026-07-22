import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EXPECTED_WORKFLOW_COUNT } from "./lib/workflow-inventory-baseline.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const workflows = JSON.parse(fs.readFileSync(path.join(programRoot, "workflows.json"), "utf8")).workflows;
const coordinationBaseCommit = "33cbe7ff019efefad242f654f0aa96c44c5b963c";
// Reviewed after the Session B repository handoff was merged into this
// integration branch. A changed set must still fail before artefacts are made.
// Explicit integration-owner handoff: the reviewed B01 SQL contract restored
// authService.refreshSession to the production inventory. No other Session B
// workflow ownership changes are accepted by this digest.
const originalSessionBWorkflowSetSha256 = "078751379c2b3cb9addc46318901bb9af6ccdc56b56748d7d305c84a785ae18f";
const workflowSetSha256 = (ids) => crypto.createHash("sha256").update(`${[...ids].sort().join("\n")}\n`).digest("hex");

const waves = [
  { id: "a-01-tenant-manufacturer-platform-reads", sessionId: "session-a", contract: "Database-revalidated tenant, manufacturer and bounded platform reads, including dashboards and analytics; filters only narrow trusted scope." },
  { id: "a-03-batch-qr-lifecycle", sessionId: "session-a", contract: "Batch, QR, range, allocation, scan and lifecycle operations through tenant-bound transactions and database-enforced state transitions." },
  { id: "a-04-printing-reissue-recovery-release", sessionId: "session-a", contract: "Printing, printer trust, reissue, recovery, sample verification and release lifecycles without weakening existing behavior." },
  { id: "a-08-runtime-idempotency-telemetry", sessionId: "session-a", contract: "Shared transaction idempotency and route telemetry with exact attribution, replay and tenant semantics." },
  { id: "a-09-system-integration-owner", sessionId: "session-a", contract: "The programme integration runner remains under the sole integration owner and cannot be delegated to an implementation worktree." },
  { id: "b-01-auth-preauth-session-account-security", sessionId: "session-b", contract: "Authentication, pre-authentication, sessions, MFA, WebAuthn, invitations, password reset, email verification and actor-owned account security." },
  { id: "b-02-public-proof-support-intake", sessionId: "session-b", contract: "Raw and signed QR verification, proof-bound public status, customer trust, ownership, support and intake with non-enumerable exact projections." },
  { id: "b-03-workers-scheduled-outbox-delivery", sessionId: "session-b", contract: "Workers, scheduled jobs, durable outbox and delivery with database-derived partitions, leases, bounded batches, idempotency and immutable attribution." },
  { id: "c-01-administration-general-mutations", sessionId: "session-c", contract: "Tenant and platform administration mutations with exact actor, assurance, lifecycle, concurrency, audit and column semantics." },
  { id: "c-02-audit-fraud-trace-alerts", sessionId: "session-c", contract: "Audit, fraud, trace, alert and export paths with exact projections, attribution, immutable history and bounded scope." },
  { id: "c-03-governance-policies-incidents-compliance", sessionId: "session-c", contract: "Governance, policies, incident response, compliance, evidence, approval and containment workflows under reviewed actor boundaries." },
  { id: "c-04-operator-recovery-startup-migration-cli", sessionId: "session-c", contract: "Finite operator, recovery, startup, migration and CLI procedures; test and seed paths remain frozen-product prohibited where already contracted." },
];
const waveById = new Map(waves.map((wave) => [wave.id, wave]));
const idMatches = (workflow, expression) => expression.test(workflow.id);
const isPlatformAdminStartup = (workflow) => workflow.executionSurface === "startup" && idMatches(workflow, /services-auth-super-admin-bootstrap-service/);
const isAuthAccountWorkflow = (workflow) => !isPlatformAdminStartup(workflow) && (Boolean(workflow.preAuthFunctionId) || idMatches(workflow, /backend-src-(?:controllers-(?:account-controller|auth-admin-security-controller|auth-controller|auth-session-controller|licensee-invite-controller)|middleware-auth|services-auth-)/));
const isPublicProofWorkflow = (workflow) => !isAuthAccountWorkflow(workflow) && (Boolean(workflow.publicReadContractBoundaryId || workflow.publicAccessClass) || (workflow.authenticationStage === "pre-authentication" && workflow.authorizationBoundaryType === "public-proof-boundary") || workflow.canonicalSourceFiles.some((file) => file.startsWith("backend/src/rls-waves/session-b/b02/")) || idMatches(workflow, /backend-src-(?:controllers-(?:public-intake-controller|support-controller|support-issue-controller|verify-)|services-(?:customer-trust-service|customer-verification-session-service|customer-webauthn-service|public-verification-post-scan-service|support-workflow-service|verification-decision-read-service|verification-decision-service))/));
const isWorkerDeliveryWorkflow = (workflow) => !isAuthAccountWorkflow(workflow) && !isPublicProofWorkflow(workflow) && (["worker", "scheduled"].includes(workflow.executionSurface) || Boolean(workflow.workerBoundaryId || workflow.producesWorkerBoundaryId) || idMatches(workflow, /backend-src-services-(?:analytics-rollup-service|audit-log-outbox-service|incident-email-service|notification-service|siem-outbox-service)/));
const isSessionBWorkflow = (workflow) => isAuthAccountWorkflow(workflow) || isPublicProofWorkflow(workflow) || isWorkerDeliveryWorkflow(workflow);
const isSystemIntegrationRunner = (workflow) => workflow.id === "workflow-cli-scripts-run-system-integration-mjs-main";

const rules = [
  { id: "b01-auth-preauth-account-contract", waveId: "b-01-auth-preauth-session-account-security", match: isAuthAccountWorkflow },
  { id: "b02-public-proof-support-contract", waveId: "b-02-public-proof-support-intake", match: isPublicProofWorkflow },
  { id: "b03-worker-schedule-delivery-contract", waveId: "b-03-workers-scheduled-outbox-delivery", match: isWorkerDeliveryWorkflow },
  { id: "a09-system-integration-owner", waveId: "a-09-system-integration-owner", match: isSystemIntegrationRunner },
  { id: "c04-registered-operator-recovery-cli-or-startup", waveId: "c-04-operator-recovery-startup-migration-cli", match: (workflow) => !isSessionBWorkflow(workflow) && !isSystemIntegrationRunner(workflow) && ["cli", "startup"].includes(workflow.executionSurface) },
  { id: "a04-printing-release-root", waveId: "a-04-printing-reissue-recovery-release", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:print-job-|printer-agent-job-controller|printer-gateway-controller)|printing-|services-(?:batch-print-lifecycle-reconciliation-service|batch-release-service|local-agent|network-direct-print-service|network-ipp-print-service|print|printer|replacement-chain-service|sample-scan-policy-service))/) },
  { id: "a03-batch-qr-root", waveId: "a-03-batch-qr-lifecycle", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:qr-controller|qr-log-controller|qr-request-controller)|services-(?:batch-allocation-service|batch-state-machine-service|legacy-qr-rotation-service|qr-allocation-service|qr-provenance-backfill-service|qr-service|qr-tracking-analytics-service|scan-insight-service|scan-log-reporting-service))/) },
  { id: "c02-audit-fraud-trace-root", waveId: "c-02-audit-fraud-trace-alerts", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:audit-controller|trace-policy-controller)|routes-audit-routes|services-(?:attention-queue-service|audit-csv-export-service|audit-export-redaction-service|audit-log-query-service|audit-service|fraud-report-query-service|immutable-audit-export-service|trace-event-service))/) },
  { id: "c03-governance-incident-compliance-root", waveId: "c-03-governance-policies-incidents-compliance", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:governance-controller|incident-controller|ir-alert-controller|ir-incident-controller|ir-policy-controller)|services-(?:compliance-pack-service|degradation-event-service|forensic-chain-service|governance-service|incident-service|ir-|policy-engine-service|sensitive-action-approval-service|soar-service|tamper-evidence-service))/) },
  { id: "c01-licensee-user-mutation-root", waveId: "c-01-administration-general-mutations", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-controllers-(?:licensee-controller|user-controller)/) && /^(?:http:)?(?:create|delete|restore|update)/i.test(workflow.entryPoint) },
  { id: "c01-manufacturer-link-mutation-root", waveId: "c-01-administration-general-mutations", match: (workflow) => !isSessionBWorkflow(workflow) && workflow.entryPoint === "internal:upsertManufacturerLicenseeLink" },
  { id: "a01-licensee-user-read-root", waveId: "a-01-tenant-manufacturer-platform-reads", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-controllers-(?:licensee-controller|user-controller)/) && /^(?:http:)?(?:assert|get|export|list)/i.test(workflow.entryPoint) },
  { id: "a01-tenant-read-service-root", waveId: "a-01-tenant-manufacturer-platform-reads", match: (workflow) => !isSessionBWorkflow(workflow) && workflow.entryPoint !== "internal:upsertManufacturerLicenseeLink" && idMatches(workflow, /backend-src-services-(?:access-control-service|analytics-service|dashboard-snapshot-service|manufacturer-scope-service)/) },
  { id: "a08-idempotency-telemetry-root", waveId: "a-08-runtime-idempotency-telemetry", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-telemetry-controller|services-idempotency-service)/) },
];

const assignments = workflows.map((workflow) => {
  const matchingRules = rules.filter((rule) => rule.match(workflow));
  if (matchingRules.length === 0) throw new Error(`Workflow has no explicit three-session contract: ${workflow.id}`);
  const matchingWaveIds = [...new Set(matchingRules.map((rule) => rule.waveId))];
  if (matchingWaveIds.length !== 1) throw new Error(`Workflow matches conflicting wave contracts: ${workflow.id} -> ${matchingWaveIds.join(", ")}`);
  const rule = matchingRules[0];
  const wave = waveById.get(rule.waveId);
  return {
    workflowId: workflow.id,
    sessionId: wave.sessionId,
    waveId: wave.id,
    assignmentRuleId: rule.id,
    corroboratingRuleIds: matchingRules.slice(1).map((candidate) => candidate.id),
    entryPoint: workflow.entryPoint,
    executionSurface: workflow.executionSurface,
    contract: wave.contract,
    canonicalSourceFiles: [...workflow.canonicalSourceFiles].sort(),
  };
}).sort((left, right) => left.workflowId.localeCompare(right.workflowId));

const countsById = new Map();
for (const assignment of assignments) countsById.set(assignment.workflowId, (countsById.get(assignment.workflowId) || 0) + 1);
const authoritativeIds = new Set(workflows.map((workflow) => workflow.id));
const missingWorkflowIds = [...authoritativeIds].filter((id) => !countsById.has(id)).sort();
const duplicateWorkflowIds = [...countsById].filter(([, count]) => count !== 1).map(([id]) => id).sort();
const unknownWorkflowIds = [...countsById.keys()].filter((id) => !authoritativeIds.has(id)).sort();
if (workflows.length !== EXPECTED_WORKFLOW_COUNT || assignments.length !== EXPECTED_WORKFLOW_COUNT || missingWorkflowIds.length || duplicateWorkflowIds.length || unknownWorkflowIds.length) {
  throw new Error(JSON.stringify({ authoritative: workflows.length, assigned: assignments.length, missingWorkflowIds, duplicateWorkflowIds, unknownWorkflowIds }));
}

const filesForSession = (sessionId) => new Set(assignments.filter((row) => row.sessionId === sessionId).flatMap((row) => row.canonicalSourceFiles));
const referencedA = filesForSession("session-a");
const referencedB = filesForSession("session-b");
const referencedC = filesForSession("session-c");
const sharedFiles = [...new Set([...referencedA, ...referencedB, ...referencedC])]
  .filter((file) => [referencedA, referencedB, referencedC].filter((files) => files.has(file)).length > 1)
  .sort();
const sessionAOwnedSharedFiles = [
  "backend/src/services/replacementChainService.ts",
  "backend/src/routes/index.ts",
];
const sessionBOwnedSharedFiles = [];
const sessionCOwnedSharedFiles = [
  "backend/src/controllers/incidentController.ts",
  "backend/src/controllers/tracePolicyController.ts",
  "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts",
  "backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts",
  "backend/src/services/compliancePackService.ts",
  "backend/src/services/governanceService.ts",
  "backend/src/services/manufacturerScopeService.ts",
];
const sessionAAdditionalProductionFiles = ["backend/src/lib/canonicalDbContext.ts"];
const expectedSharedFiles = [...sessionAOwnedSharedFiles, ...sessionBOwnedSharedFiles, ...sessionCOwnedSharedFiles].sort();
if (JSON.stringify(sharedFiles) !== JSON.stringify(expectedSharedFiles)) throw new Error(`Shared production-file inventory drifted: ${JSON.stringify(sharedFiles)}`);

const listSourceFiles = (relativeDirectory) => fs.readdirSync(path.join(repoRoot, relativeDirectory), { withFileTypes: true }).flatMap((entry) => {
  const relativePath = path.posix.join(relativeDirectory, entry.name);
  return entry.isDirectory() ? listSourceFiles(relativePath) : /\.(?:js|ts)$/.test(entry.name) ? [relativePath] : [];
});
const sessionBAdditionalProductionFiles = [
  ...listSourceFiles("backend/src/controllers/verify"),
  ...listSourceFiles("backend/src/services/auth").filter((file) => !file.endsWith("/superAdminBootstrapService.ts")),
  "backend/src/controllers/notificationController.ts",
  "backend/src/controllers/notificationEventsController.ts",
  "backend/src/middleware/customerVerifyAuth.ts",
  "backend/src/middleware/supportIssueUpload.ts",
  "backend/src/routes/modules/authRoutes.ts",
  "backend/src/routes/publicRoutes.ts",
  "backend/src/services/captchaService.ts",
  "backend/src/services/customerVerifyAuthService.ts",
  "backend/src/services/customerVerifyCookieService.ts",
  "backend/src/services/customerVerifyOAuthService.ts",
  "backend/src/services/incidentRateLimitService.ts",
  "backend/src/services/notificationVisibility.ts",
  "backend/src/services/supportIntakeMailService.ts",
];
for (const file of sessionBAdditionalProductionFiles) if (!fs.existsSync(path.join(repoRoot, file))) throw new Error(`Session B production ownership file is missing: ${file}`);
const sessionAProductionFiles = [...new Set([...referencedA]
  .filter((file) => !sessionBOwnedSharedFiles.includes(file) && !sessionCOwnedSharedFiles.includes(file))
  .concat(sessionAOwnedSharedFiles, sessionAAdditionalProductionFiles))].sort();
const sessionBProductionFiles = [...new Set([...referencedB]
  .filter((file) => !sessionAOwnedSharedFiles.includes(file) && !sessionCOwnedSharedFiles.includes(file))
  .concat(sessionBOwnedSharedFiles, sessionBAdditionalProductionFiles))].sort();
const sessionCProductionFiles = [...new Set([...referencedC]
  .filter((file) => !sessionAOwnedSharedFiles.includes(file) && !sessionAAdditionalProductionFiles.includes(file) && !sessionBOwnedSharedFiles.includes(file))
  .concat(sessionCOwnedSharedFiles))].sort();
const productionFilesBySession = new Map([
  ["session-a", sessionAProductionFiles],
  ["session-b", sessionBProductionFiles],
  ["session-c", sessionCProductionFiles],
]);
const productionFileOwners = new Map();
for (const [sessionId, files] of productionFilesBySession) for (const file of files) productionFileOwners.set(file, [...(productionFileOwners.get(file) || []), sessionId]);
const fileOwnershipOverlap = [...productionFileOwners].filter(([, owners]) => owners.length > 1).map(([file, owners]) => ({ file, owners }));
if (fileOwnershipOverlap.length) throw new Error(`Editable production files overlap: ${JSON.stringify(fileOwnershipOverlap)}`);

const sessionBExistingTestFiles = [
  "backend/tests/authAdminLoginMfaCycle.test.js",
  "backend/tests/authBootstrapRepository.test.js",
  "backend/tests/authInviteEmailSenderPolicy.test.js",
  "backend/tests/authLoginWithoutMfa.test.js",
  "backend/tests/authMfaChallengeStateMachine.test.js",
  "backend/tests/authMfaPostgres18.test.js",
  "backend/tests/authRlsBootstrap.test.js",
  "backend/tests/authSessionMetadata.test.js",
  "backend/tests/cookieTokenProtection.test.js",
  "backend/tests/csrfSecurity.test.js",
  "backend/tests/customerOtpDryRunHandoff.test.js",
  "backend/tests/customerVerificationSessionSecurity.test.js",
  "backend/tests/customerVerifyAuthCookieMode.test.js",
  "backend/tests/customerVerifyCookieSecurity.test.js",
  "backend/tests/helpers/publicEgressContract.js",
  "backend/tests/helpers/publicVerificationContract.js",
  "backend/tests/mailTransportService.test.js",
  "backend/tests/notificationVisibility.test.js",
  "backend/tests/ownershipTransferSecurity.test.js",
  "backend/tests/p1SignedScanTokenIntegration.test.js",
  "backend/tests/p2EmailCapture.test.js",
  "backend/tests/phaseESupportIntake.test.js",
  "backend/tests/publicEgressContract.test.js",
  "backend/tests/publicScanActorForeignKeyFallback.test.js",
  "backend/tests/publicScanFallback.test.js",
  "backend/tests/publicScanNotReadyNoMutation.test.js",
  "backend/tests/publicScanReplayHardening.test.js",
  "backend/tests/publicScanStrictFailClosed.test.js",
  "backend/tests/publicVerificationApiContract.test.js",
  "backend/tests/publicVerificationSessionStartToken.test.js",
  "backend/tests/publicVerifyExactLookup.test.js",
  "backend/tests/publicVerifyRateLimit.test.js",
  "backend/tests/publicVerifyStrictFailClosed.test.js",
  "backend/tests/qrManagedSignerBridge.test.js",
  "backend/tests/qrScanRefreshDedup.test.js",
  "backend/tests/qrTokenKeyNormalization.test.js",
  "backend/tests/qrTokenSigningProfile.test.js",
  "backend/tests/rlsAuthBootstrapP2.test.js",
  "backend/tests/scanSecurity.test.js",
  "backend/tests/scannerProbeRejection.test.js",
  "backend/tests/sensitiveAuthMiddleware.test.js",
  "backend/tests/verificationForensicExportService.test.js",
  "backend/tests/verificationProvenanceHardening.test.js",
  "backend/tests/verificationReplayService.test.js",
  "backend/tests/verificationTrustMetrics.test.js",
  "backend/tests/verificationTruthSemantics.test.js",
  "backend/tests/webauthnMfaProviderContract.test.js",
];
for (const file of sessionBExistingTestFiles) if (!fs.existsSync(path.join(repoRoot, file))) throw new Error(`Session B test ownership file is missing: ${file}`);

const sessionCExistingTestFiles = [
  "backend/tests/adminAccountRepairScript.test.js",
  "backend/tests/auditCsvExportContext.test.js",
  "backend/tests/auditLogQueryContext.test.js",
  "backend/tests/breakGlassGenerateGate.test.js",
  "backend/tests/compliancePackService.test.js",
  "backend/tests/duplicateRiskEngine.test.js",
  "backend/tests/fraudReportQueryContext.test.js",
  "backend/tests/governanceComplianceDownloadResilience.test.js",
  "backend/tests/incidentMvp.test.js",
  "backend/tests/incidentPdfExport.test.js",
  "backend/tests/irIncidentListFilters.test.js",
  "backend/tests/irPaginationQueryRegression.test.js",
  "backend/tests/launchSmokeSeedScript.test.js",
  "backend/tests/p3MigrationDrift.test.js",
  "backend/tests/p3MigrationReplay.test.js",
  "backend/tests/passwordSetupLinkScript.test.js",
  "backend/tests/phaseE2RoleTenantIdor.test.js",
  "backend/tests/prismaChecksumSmokeScript.test.js",
  "backend/tests/stagingRlsValidationSeedScript.test.js",
  "backend/tests/superAdminBootstrap.test.js",
  "backend/tests/traceTimelineContext.test.js",
];
for (const file of sessionCExistingTestFiles) if (!fs.existsSync(path.join(repoRoot, file))) throw new Error(`Session C test ownership file is missing: ${file}`);

const exclusiveGlobalPathRules = [
  "documents/security/rls-program/*.json except the exact Session B and Session C wave-local result manifests",
  "documents/security/rls-program/generated/**",
  "scripts/rls/generate-*.mjs",
  "scripts/rls/certify-*.mjs",
  "scripts/rls/lib/**",
  "scripts/rls/sql/**",
  "scripts/tests/full-database-rls-*.test.mjs",
  "backend/prisma/schema.prisma",
  "backend/prisma/migrations/**",
  "infra/terraform/staging-api/**",
  "scripts/aws/**staging**",
  "documents/security/rls-program/STAGING_FULL_RLS_*",
];
const workflowFamiliesForSession = (sessionId) => waves
  .filter((wave) => wave.sessionId === sessionId)
  .map((wave) => ({
    waveId: wave.id,
    contract: wave.contract,
    workflowIds: assignments.filter((row) => row.waveId === wave.id).map((row) => row.workflowId),
  }));
const sessions = [
  {
    id: "session-a",
    role: "sole-integration-owner",
    databaseNamespace: "mscqr_rls_wave_a_integration",
    workflowIds: assignments.filter((row) => row.sessionId === "session-a").map((row) => row.workflowId),
    workflowFamilies: workflowFamiliesForSession("session-a"),
    productionFiles: sessionAProductionFiles,
    ownedSharedFiles: [...sessionAOwnedSharedFiles, ...sessionAAdditionalProductionFiles].sort(),
    sessionBExclusiveProductionFiles: sessionBProductionFiles,
    sessionCExclusiveProductionFiles: sessionCProductionFiles,
    exclusiveGlobalPathRules,
  },
  {
    id: "session-b",
    role: "isolated-auth-public-worker-wave",
    branch: "rls-wave-auth-public-workers",
    worktree: "/Users/abhiramteja/Downloads/genuine-scan-rls-auth",
    databaseNamespace: "mscqr_rls_wave_b_auth_public_workers",
    workflowIds: assignments.filter((row) => row.sessionId === "session-b").map((row) => row.workflowId),
    workflowFamilies: workflowFamiliesForSession("session-b"),
    productionFiles: sessionBProductionFiles,
    existingTestFiles: sessionBExistingTestFiles,
    allowedNewPathRules: [
      "backend/src/rls-waves/session-b/**",
      "backend/tests/rls-wave-b/**",
      "documents/security/rls-program/waves/session-b-auth-public-workers-result.json",
      "documents/security/rls-program/waves/session-b/**",
    ],
    integrationOwnerOnlyFiles: [...sessionAOwnedSharedFiles, ...sessionCOwnedSharedFiles].sort(),
    forbiddenGlobalPathRules: exclusiveGlobalPathRules,
    waveLocalResultManifest: "documents/security/rls-program/waves/session-b-auth-public-workers-result.json",
    originalBranchPoint: "061b3134ba89db84e0564b893e920a2601c14452",
  },
  {
    id: "session-c",
    role: "isolated-admin-governance-operator-wave",
    branch: "rls-wave-admin-governance-operator",
    worktree: "/Users/abhiramteja/Downloads/genuine-scan-rls-admin",
    databaseNamespace: "mscqr_rls_wave_c_admin_governance_operator",
    workflowIds: assignments.filter((row) => row.sessionId === "session-c").map((row) => row.workflowId),
    workflowFamilies: workflowFamiliesForSession("session-c"),
    productionFiles: sessionCProductionFiles,
    existingTestFiles: sessionCExistingTestFiles,
    allowedNewPathRules: [
      "backend/src/rls-waves/session-c/**",
      "backend/tests/rls-wave-c/**",
      "documents/security/rls-program/waves/session-c-admin-governance-operator-result.json",
      "documents/security/rls-program/waves/session-c/**",
    ],
    integrationOwnerOnlyFiles: [...sessionAOwnedSharedFiles, ...sessionAAdditionalProductionFiles, ...sessionBOwnedSharedFiles].sort(),
    prohibitedSharedFiles: [...sessionAOwnedSharedFiles, ...sessionAAdditionalProductionFiles, ...sessionBOwnedSharedFiles].sort(),
    forbiddenGlobalPathRules: exclusiveGlobalPathRules,
    waveLocalResultManifest: "documents/security/rls-program/waves/session-c-admin-governance-operator-result.json",
    requiredBaseAncestor: coordinationBaseCommit,
  },
];

const sessionBWorkflowSetSha256 = workflowSetSha256(sessions.find((session) => session.id === "session-b").workflowIds);
if (sessionBWorkflowSetSha256 !== originalSessionBWorkflowSetSha256) {
  throw new Error(`Session B workflow ownership changed without an explicit handoff: ${sessionBWorkflowSetSha256}`);
}

const summary = {
  authoritativeWorkflowCount: workflows.length,
  assignmentCount: assignments.length,
  uniqueAssignmentCount: countsById.size,
  missingWorkflowIds,
  duplicateWorkflowIds,
  unknownWorkflowIds,
  genericCatchAllAssignments: assignments.filter((row) => /fallback|catch.?all|remaining|misc/i.test(`${row.waveId}:${row.assignmentRuleId}`)).map((row) => row.workflowId),
  sessionCounts: Object.fromEntries(sessions.map((session) => [session.id, session.workflowIds.length])),
  waveCounts: Object.fromEntries(waves.map((wave) => [wave.id, assignments.filter((row) => row.waveId === wave.id).length])),
  sessionBWorkflowSetSha256,
  sessionBWorkflowOwnershipPreserved: true,
  sharedReferencedProductionFiles: sharedFiles,
  editableProductionFileOverlap: fileOwnershipOverlap,
};
if (summary.genericCatchAllAssignments.length) throw new Error(`Generic catch-all assignments are prohibited: ${summary.genericCatchAllAssignments.join(", ")}`);

const stable = (value) => `${JSON.stringify(value, null, 2)}\n`;
const partition = {
  schemaVersion: 2,
  coordinationBaseCommit,
  authoritativeSource: "documents/security/rls-program/workflows.json",
  sessions: sessions.map(({ workflowIds, productionFiles, existingTestFiles, workflowFamilies, ...session }) => ({
    ...session,
    workflowCount: workflowIds.length,
    workflowFamilyCount: workflowFamilies.length,
    productionFileCount: productionFiles.length,
    existingTestFileCount: existingTestFiles?.length || 0,
  })),
  waves,
  assignments,
  fileOwnership: { sessionAOwnedSharedFiles, sessionAAdditionalProductionFiles, sessionBOwnedSharedFiles, sessionCOwnedSharedFiles },
  validationSummary: summary,
};
fs.mkdirSync(path.join(programRoot, "waves"), { recursive: true });
fs.writeFileSync(path.join(programRoot, "workflow-three-session-partition.json"), stable(partition));
for (const session of sessions) fs.writeFileSync(path.join(programRoot, `workflow-ownership-${session.id}.json`), stable({
  schemaVersion: 2,
  coordinationBaseCommit,
  ...session,
  workflowCount: session.workflowIds.length,
  workflowFamilyCount: session.workflowFamilies.length,
  productionFileCount: session.productionFiles.length,
  existingTestFileCount: session.existingTestFiles?.length || 0,
}));
console.log(stable(summary).trim());
