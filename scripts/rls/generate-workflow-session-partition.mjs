import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const workflows = JSON.parse(fs.readFileSync(path.join(programRoot, "workflows.json"), "utf8")).workflows;
const foundationCommit = "061b3134ba89db84e0564b893e920a2601c14452";

const waves = [
  { id: "a-01-tenant-manufacturer-platform-reads", sessionId: "session-a", contract: "Database-revalidated tenant, manufacturer and bounded platform reads, including dashboards and analytics; filters only narrow trusted scope." },
  { id: "a-02-tenant-platform-administration", sessionId: "session-a", contract: "Tenant and platform user/licensee administration with exact actor, assurance, lifecycle, concurrency, audit and column semantics." },
  { id: "a-03-batch-qr-lifecycle", sessionId: "session-a", contract: "Batch, QR, range, allocation, scan and lifecycle operations through tenant-bound transactions and database-enforced state transitions." },
  { id: "a-04-printing-reissue-recovery-release", sessionId: "session-a", contract: "Printing, printer trust, reissue, recovery, sample verification and release lifecycles without weakening existing behavior." },
  { id: "a-05-audit-fraud-trace-alerts", sessionId: "session-a", contract: "Audit, fraud, trace, alert and export paths with exact projections, attribution, immutable history and bounded scope." },
  { id: "a-06-governance-incidents-compliance", sessionId: "session-a", contract: "Governance, incident response, compliance, policy, evidence, approval and containment workflows under reviewed actor boundaries." },
  { id: "a-07-operator-migration-startup-cli", sessionId: "session-a", contract: "Finite operator, migration, startup and CLI procedures; test/seed paths remain frozen-product prohibited where already contracted." },
  { id: "a-08-runtime-idempotency-telemetry", sessionId: "session-a", contract: "Shared transaction idempotency and route telemetry with exact attribution, replay and tenant semantics." },
  { id: "b-01-auth-preauth-session-account-security", sessionId: "session-b", contract: "Authentication, pre-authentication, sessions, MFA, WebAuthn, invitations, password reset, email verification and actor-owned account security." },
  { id: "b-02-public-proof-support-intake", sessionId: "session-b", contract: "Raw and signed QR verification, proof-bound public status, customer trust, ownership, support and intake with non-enumerable exact projections." },
  { id: "b-03-workers-scheduled-outbox-delivery", sessionId: "session-b", contract: "Workers, scheduled jobs, durable outbox and delivery with database-derived partitions, leases, bounded batches, idempotency and immutable attribution." },
];
const waveById = new Map(waves.map((wave) => [wave.id, wave]));
const idMatches = (workflow, expression) => expression.test(workflow.id);
const isPlatformAdminStartup = (workflow) => workflow.executionSurface === "startup" && idMatches(workflow, /services-auth-super-admin-bootstrap-service/);
const isAuthAccountWorkflow = (workflow) => !isPlatformAdminStartup(workflow) && (Boolean(workflow.preAuthFunctionId) || idMatches(workflow, /backend-src-(?:controllers-(?:account-controller|auth-admin-security-controller|auth-controller|auth-session-controller|licensee-invite-controller)|middleware-auth|services-auth-)/));
const isPublicProofWorkflow = (workflow) => !isAuthAccountWorkflow(workflow) && (Boolean(workflow.publicReadContractBoundaryId || workflow.publicAccessClass) || (workflow.authenticationStage === "pre-authentication" && workflow.authorizationBoundaryType === "public-proof-boundary") || idMatches(workflow, /backend-src-(?:controllers-(?:public-intake-controller|support-controller|support-issue-controller|verify-)|services-(?:customer-trust-service|customer-verification-session-service|customer-webauthn-service|public-verification-post-scan-service|support-workflow-service|verification-decision-read-service|verification-decision-service))/));
const isWorkerDeliveryWorkflow = (workflow) => !isAuthAccountWorkflow(workflow) && !isPublicProofWorkflow(workflow) && (["worker", "scheduled"].includes(workflow.executionSurface) || Boolean(workflow.workerBoundaryId || workflow.producesWorkerBoundaryId) || idMatches(workflow, /backend-src-services-(?:analytics-rollup-service|audit-log-outbox-service|incident-email-service|notification-service|siem-outbox-service)/));
const isSessionBWorkflow = (workflow) => isAuthAccountWorkflow(workflow) || isPublicProofWorkflow(workflow) || isWorkerDeliveryWorkflow(workflow);

const rules = [
  { id: "b01-auth-preauth-account-contract", waveId: "b-01-auth-preauth-session-account-security", match: isAuthAccountWorkflow },
  { id: "b02-public-proof-support-contract", waveId: "b-02-public-proof-support-intake", match: isPublicProofWorkflow },
  { id: "b03-worker-schedule-delivery-contract", waveId: "b-03-workers-scheduled-outbox-delivery", match: isWorkerDeliveryWorkflow },
  { id: "a07-registered-cli-or-startup", waveId: "a-07-operator-migration-startup-cli", match: (workflow) => !isSessionBWorkflow(workflow) && ["cli", "startup"].includes(workflow.executionSurface) },
  { id: "a04-printing-release-root", waveId: "a-04-printing-reissue-recovery-release", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:print-job-|printer-agent-job-controller|printer-gateway-controller)|printing-|services-(?:batch-print-lifecycle-reconciliation-service|batch-release-service|local-agent|network-direct-print-service|network-ipp-print-service|print|printer|replacement-chain-service|sample-scan-policy-service))/) },
  { id: "a03-batch-qr-root", waveId: "a-03-batch-qr-lifecycle", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:qr-controller|qr-log-controller|qr-request-controller)|services-(?:batch-allocation-service|batch-state-machine-service|legacy-qr-rotation-service|qr-allocation-service|qr-provenance-backfill-service|qr-service|qr-tracking-analytics-service|scan-insight-service|scan-log-reporting-service))/) },
  { id: "a05-audit-fraud-trace-root", waveId: "a-05-audit-fraud-trace-alerts", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:audit-controller|trace-policy-controller)|routes-audit-routes|services-(?:attention-queue-service|audit-csv-export-service|audit-export-redaction-service|audit-log-query-service|audit-service|fraud-report-query-service|immutable-audit-export-service|trace-event-service))/) },
  { id: "a06-governance-incident-compliance-root", waveId: "a-06-governance-incidents-compliance", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-(?:governance-controller|incident-controller|ir-alert-controller|ir-incident-controller|ir-policy-controller)|services-(?:compliance-pack-service|degradation-event-service|forensic-chain-service|governance-service|incident-service|ir-|policy-engine-service|sensitive-action-approval-service|soar-service|tamper-evidence-service))/) },
  { id: "a02-licensee-user-mutation-root", waveId: "a-02-tenant-platform-administration", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-controllers-(?:licensee-controller|user-controller)/) && /^(?:http:)?(?:create|delete|restore|update)/i.test(workflow.entryPoint) },
  { id: "a01-licensee-user-read-root", waveId: "a-01-tenant-manufacturer-platform-reads", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-controllers-(?:licensee-controller|user-controller)/) && /^(?:http:)?(?:assert|get|export|list)/i.test(workflow.entryPoint) },
  { id: "a01-tenant-read-service-root", waveId: "a-01-tenant-manufacturer-platform-reads", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-services-(?:access-control-service|analytics-service|dashboard-snapshot-service|manufacturer-scope-service)/) },
  { id: "a08-idempotency-telemetry-root", waveId: "a-08-runtime-idempotency-telemetry", match: (workflow) => !isSessionBWorkflow(workflow) && idMatches(workflow, /backend-src-(?:controllers-telemetry-controller|services-idempotency-service)/) },
];

const assignments = workflows.map((workflow) => {
  const matchingRules = rules.filter((rule) => rule.match(workflow));
  if (matchingRules.length === 0) throw new Error(`Workflow has no explicit two-session contract: ${workflow.id}`);
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
if (workflows.length !== 428 || assignments.length !== 428 || missingWorkflowIds.length || duplicateWorkflowIds.length || unknownWorkflowIds.length) {
  throw new Error(JSON.stringify({ authoritative: workflows.length, assigned: assignments.length, missingWorkflowIds, duplicateWorkflowIds, unknownWorkflowIds }));
}

const filesForSession = (sessionId) => new Set(assignments.filter((row) => row.sessionId === sessionId).flatMap((row) => row.canonicalSourceFiles));
const referencedA = filesForSession("session-a");
const referencedB = filesForSession("session-b");
const sharedFiles = [...referencedA].filter((file) => referencedB.has(file)).sort();
const sessionAOwnedSharedFiles = [
  "backend/src/controllers/incidentController.ts",
  "backend/src/services/compliancePackService.ts",
  "backend/src/services/governanceService.ts",
  "backend/src/services/replacementChainService.ts",
];
const sessionBOwnedSharedFiles = ["backend/src/middleware/auth.ts"];
const expectedSharedFiles = [...sessionAOwnedSharedFiles, ...sessionBOwnedSharedFiles].sort();
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
const sessionAProductionFiles = [...new Set([...referencedA].filter((file) => !sessionBOwnedSharedFiles.includes(file)).concat(sessionAOwnedSharedFiles))].sort();
const sessionBProductionFiles = [...new Set([...referencedB].filter((file) => !sessionAOwnedSharedFiles.includes(file)).concat(sessionBOwnedSharedFiles, sessionBAdditionalProductionFiles))].sort();
const fileOwnershipOverlap = sessionAProductionFiles.filter((file) => sessionBProductionFiles.includes(file));
if (fileOwnershipOverlap.length) throw new Error(`Editable production files overlap: ${fileOwnershipOverlap.join(", ")}`);

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

const exclusiveGlobalPathRules = [
  "documents/security/rls-program/*.json except documents/security/rls-program/waves/session-b-auth-public-workers-result.json",
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
const sessions = [
  {
    id: "session-a",
    role: "sole-integration-owner",
    databaseNamespace: "mscqr_rls_wave_a_integration",
    workflowIds: assignments.filter((row) => row.sessionId === "session-a").map((row) => row.workflowId),
    productionFiles: sessionAProductionFiles,
    ownedSharedFiles: sessionAOwnedSharedFiles,
    sessionBExclusiveProductionFiles: sessionBProductionFiles,
    exclusiveGlobalPathRules,
  },
  {
    id: "session-b",
    role: "isolated-auth-public-worker-wave",
    branch: "rls-wave-auth-public-workers",
    worktree: "/Users/abhiramteja/Downloads/genuine-scan-rls-auth",
    databaseNamespace: "mscqr_rls_wave_b_auth_public_workers",
    workflowIds: assignments.filter((row) => row.sessionId === "session-b").map((row) => row.workflowId),
    productionFiles: sessionBProductionFiles,
    existingTestFiles: sessionBExistingTestFiles,
    allowedNewPathRules: [
      "backend/src/rls-waves/session-b/**",
      "backend/tests/rls-wave-b/**",
      "documents/security/rls-program/waves/session-b-auth-public-workers-result.json",
      "documents/security/rls-program/waves/session-b/**",
    ],
    integrationOwnerOnlyFiles: sessionAOwnedSharedFiles,
    forbiddenGlobalPathRules: exclusiveGlobalPathRules,
    waveLocalResultManifest: "documents/security/rls-program/waves/session-b-auth-public-workers-result.json",
  },
];

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
  sharedReferencedProductionFiles: sharedFiles,
  editableProductionFileOverlap: fileOwnershipOverlap,
};
if (summary.genericCatchAllAssignments.length) throw new Error(`Generic catch-all assignments are prohibited: ${summary.genericCatchAllAssignments.join(", ")}`);

const stable = (value) => `${JSON.stringify(value, null, 2)}\n`;
const partition = { schemaVersion: 1, foundationCommit, authoritativeSource: "documents/security/rls-program/workflows.json", sessions: sessions.map(({ workflowIds, productionFiles, existingTestFiles, ...session }) => ({ ...session, workflowCount: workflowIds.length, productionFileCount: productionFiles.length, existingTestFileCount: existingTestFiles?.length || 0 })), waves, assignments, fileOwnership: { sessionAOwnedSharedFiles, sessionBOwnedSharedFiles }, validationSummary: summary };
fs.mkdirSync(path.join(programRoot, "waves"), { recursive: true });
fs.writeFileSync(path.join(programRoot, "workflow-two-session-partition.json"), stable(partition));
for (const session of sessions) fs.writeFileSync(path.join(programRoot, `workflow-ownership-${session.id}.json`), stable({ schemaVersion: 1, foundationCommit, ...session, workflowCount: session.workflowIds.length }));
console.log(stable(summary).trim());
