import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";

export const WORKFLOW_DELEGATIONS = Object.freeze([
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-a/tenantDirectoryRepository.ts", function: "readLicenseeDirectory" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/licenseeController.ts", function: "getLicensees" },
    reason: "The registered list controller owns the licensee-directory workflow; the repository supplies its exact SQL projection.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-a/tenantDirectoryRepository.ts", function: "readLicenseeDetail" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/licenseeController.ts", function: "getLicensee" },
    reason: "The registered detail controller owns the exact-licensee workflow; the repository supplies its exact SQL projection.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-a/tenantDirectoryRepository.ts", function: "readUserDirectory" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/userController.ts", function: "getUsers" },
    reason: "The registered user controller owns directory listing; the repository supplies its exact SQL projection.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/actorRevalidationRepository.ts", function: "revalidateAuthenticatedActor" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/middleware/auth.ts", function: "hydrateTenantIfNeeded" },
    reason: "Authentication middleware owns actor hydration; the B01 repository supplies exact live actor revalidation.",
  },
  ...[
    ["loadAuthenticatedActor", "http", "backend/src/controllers/authController.ts", "me"],
    ["loadAuthenticatedPasswordActor", "http", "backend/src/controllers/accountController.ts", "changeMyPassword"],
    ["requireRecentMfaSession", "http", "backend/src/middleware/auth.ts", "requireRecentAdminMfa"],
    ["loadRecentAuthSessionRiskInputs", "internal", "backend/src/services/auth/sessionRiskService.ts", "assessAuthSessionRisk"],
    ["recordAuthSessionRiskSignal", "internal", "backend/src/services/auth/sessionRiskService.ts", "persistAuthSessionRisk"],
    ["updateAuthenticatedProfile", "http", "backend/src/controllers/accountController.ts", "updateMyProfile"],
    ["prepareAuthenticatedEmailChange", "internal", "backend/src/services/auth/emailVerificationService.ts", "requestEmailChangeVerification"],
    ["proveAuthenticatedPasswordStepUp", "http", "backend/src/controllers/authSessionController.ts", "passwordStepUpController"],
    ["requireRecentSensitiveSession", "http", "backend/src/controllers/accountController.ts", "updateMyProfile"],
    ["changeAuthenticatedPassword", "http", "backend/src/controllers/accountController.ts", "changeMyPassword"],
  ].map(([functionName, executionSurface, sourceFile, canonicalFunction]) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts", function: functionName },
    canonical: { executionSurface, sourceFile, function: canonicalFunction },
    reason: "The registered authentication workflow owns the operation; the B01 repository supplies its exact authenticated SQL capability.",
  })),
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c01/administrationRepository.ts", function: "call" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/licenseeController.ts", function: "createLicensee" },
    reason: "The administration repository dispatches a fixed exact-function registry shared by the RF3 mutation controllers; the create-licensee root owns the grouped implementation evidence.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/invitationRepository.ts", function: "prepareInvitation" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/inviteService.ts", function: "createInvite" },
    reason: "The invitation service owns invite creation; the B01 repository supplies its exact authenticated SQL capability.",
  },
  ...[
    ["createRefreshTokenRecord", "createRefreshToken"],
    ["findRefreshTokenByIdentifier", "findRefreshTokenById"],
    ["listActiveRefreshTokenRecords", "listActiveRefreshTokensForUser"],
    ["revokeAllRefreshTokenRecords", "revokeAllUserRefreshTokens"],
    ["revokeRefreshTokenByIdentifier", "revokeRefreshTokenById"],
  ].map(([functionName, canonicalFunction]) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts", function: functionName },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/refreshTokenService.ts", function: canonicalFunction },
    reason: "The refresh-token service owns the registered operation; the B01 repository supplies its exact session-credential SQL capability.",
  })),
  ...[
    ["getPrimarySuperadminEmail", "internal", "backend/src/services/incidentEmailService.ts", "sendIncidentEmail"],
    ["getSuperadminAlertEmails", "internal", "backend/src/services/incidentEmailService.ts", "getSuperadminAlertEmails"],
    ["resolveIncidentEmailActor", "internal", "backend/src/services/incidentEmailService.ts", "sendIncidentEmail"],
    ["createRoleNotifications", "internal", "backend/src/services/notificationService.ts", "createRoleNotifications"],
    ["createUserNotification", "internal", "backend/src/services/notificationService.ts", "createUserNotification"],
    ["markNotificationEmailed", "internal", "backend/src/services/notificationService.ts", "createUserNotification"],
    ["listNotificationsForUser", "internal", "backend/src/services/notificationService.ts", "listNotificationsForUser"],
    ["markNotificationRead", "internal", "backend/src/services/notificationService.ts", "markNotificationRead"],
    ["markAllNotificationsRead", "internal", "backend/src/services/notificationService.ts", "markAllNotificationsRead"],
    ["resolveIncidentNotificationScope", "internal", "backend/src/services/notificationService.ts", "notifyIncidentLifecycle"],
    ["claimIncidentEmailDelivery", "internal", "backend/src/services/incidentEmailService.ts", "sendIncidentEmail"],
    ["completeIncidentEmailDelivery", "internal", "backend/src/services/incidentEmailService.ts", "sendIncidentEmail"],
  ].map(([functionName, executionSurface, sourceFile, canonicalFunction]) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: functionName },
    canonical: { executionSurface, sourceFile, function: canonicalFunction },
    reason: "The registered notification or incident-email workflow owns the operation; B03 supplies its exact authenticated SQL capability.",
  })),
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c02/riskAnalyticsRepository.ts", function: "readRiskAnalyticsSnapshot" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/analyticsService.ts", function: "getRiskAnalytics" },
    reason: "The analytics service owns the registered risk workflow; the repository supplies its exact SQL snapshot.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "verifyRawQr" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/verify/verificationHandlers.ts", function: "verifyQRCode" },
    reason: "The public verification controller owns raw-code verification; the B02 repository supplies its exact public SQL transaction.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "verifySignedQr" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/verify/verificationHandlers.ts", function: "verifyQRCode" },
    reason: "The public verification controller owns signed verification; the B02 repository supplies its exact public SQL transaction.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "startVerificationSession" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/customerVerificationSessionService.ts", function: "createCustomerVerificationSession" },
    reason: "The customer verification service owns session creation; the B02 repository supplies its exact public SQL mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "readVerificationSession" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/customerVerificationSessionService.ts", function: "getCustomerVerificationSession" },
    reason: "The customer verification service owns session retrieval; the B02 repository supplies its exact proof-bound SQL read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "submitProductFeedback" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/verify/feedbackHandlers.ts", function: "submitProductFeedback" },
    reason: "The feedback controller owns product feedback; the B02 repository supplies its exact public SQL mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "submitPublicIncident" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/verify/feedbackHandlers.ts", function: "reportFraud" },
    reason: "The fraud-report controller owns concern submission; the B02 repository supplies its exact public SQL mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "submitRequestAccess" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/publicIntakeController.ts", function: "submitPublicRequestAccess" },
    reason: "The public intake controller owns access requests; the B02 repository supplies its exact public SQL mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts", function: "submitPublicSupport" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/publicIntakeController.ts", function: "submitPublicSupportIssue" },
    reason: "The public intake controller owns support requests; the B02 repository supplies its exact public SQL mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/authenticatedRepositories.ts", function: "listSupportTicketRows" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/supportController.ts", function: "listSupportTickets" },
    reason: "The registered controller owns support-ticket listing; the B02 repository supplies its scoped transaction reads.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b02/authenticatedRepositories.ts", function: "loadSupportTicketRow" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/supportController.ts", function: "getSupportTicket" },
    reason: "The registered controller owns support-ticket detail; the B02 repository supplies its scoped transaction read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/services/auditCsvExportService.ts", function: "readAuditCsvExport" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/auditController.ts", function: "exportLogsCsv" },
    reason: "The controller owns the registered HTTP export workflow; the service only implements its database read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/services/auditLogQueryService.ts", function: "queryAuditLogs" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/auditController.ts", function: "getLogs" },
    reason: "The controller owns the registered HTTP audit-log workflow; the service only implements its database read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/services/fraudReportQueryService.ts", function: "queryFraudReports" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/auditController.ts", function: "getFraudReports" },
    reason: "The controller owns the registered HTTP fraud-report workflow; the service only implements its database read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/services/auth/refreshTokenService.ts", function: "revoke" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/refreshTokenService.ts", function: "rotateRefreshToken" },
    reason: "Revocation is an implementation step of refresh-token rotation, not an HTTP workflow.",
  },
  ...[
    "claimRefreshTokenRotation",
    "loadRefreshSessionState",
    "createRefreshMfaChallengeRecord",
    "revokeRefreshTokenRotationScope",
    "completeRefreshTokenRotation",
  ].map((functionName) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts", function: functionName },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/authService.ts", function: "refreshSession" },
    reason: "The auth service owns the registered refresh-session workflow; the B01 repository supplies its exact pre-auth SQL implementation.",
  })),
  ...[
    "createAuthenticatedSessionCapability",
    "revokeAuthenticatedSessionByRefreshToken",
    "revokeAuthenticatedSessionsForUser",
  ].map((functionName) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/services/auth/authenticatedSessionCapabilityService.ts", function: functionName },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/authService.ts", function: "refreshSession" },
    reason: "The auth service owns the reviewed session-credential lifecycle; this helper only implements capability issue or revocation through exact app_auth boundaries.",
  })),
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts", function: "verifyCapability" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/compliancePackService.ts", function: "listCompliancePackJobs" },
    reason: "Capability verification is shared C03 transaction bootstrap evidence; it is not a separately registered business workflow.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts", function: "withC03ResourceTransaction" },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The resource wrapper's only named SQL access revalidates compliance-pack job scope; it is implementation evidence for the registered scheduled compliance lifecycle, not a separate workflow.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts", function: "loadIncidentEvidenceFileInTransaction" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/incidentController.ts", function: "serveIncidentEvidenceFile" },
    reason: "The registered controller owns incident-evidence delivery; the C03 repository performs its transaction-bound named-function read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts", function: "listIncidentPolicyAlertsInTransaction" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/irAlertController.ts", function: "listIrAlerts" },
    reason: "The registered controller owns incident-response alert listing; the C03 repository performs its transaction-bound named-function read.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts", function: "linkPolicyAlertToIncidentInTransaction" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/irAlertController.ts", function: "patchIrAlert" },
    reason: "The registered controller owns incident-response alert escalation; the C03 repository performs its transaction-bound named-function mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c02/auditTraceRepository.ts", function: "respondToFraudReportInTransaction" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/auditController.ts", function: "respondToFraudReport" },
    reason: "The registered controller owns fraud-response handling; the C02 repository performs its transaction-bound named-function mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts", function: "createPublicIncidentReportInTransaction" },
    canonical: { executionSurface: "http", sourceFile: "backend/src/controllers/incidentController.ts", function: "reportIncident" },
    reason: "The public controller owns public incident submission; the C03 repository performs its pre-auth named-function mutation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts", function: "listCompliancePackJobsInTransaction" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/compliancePackService.ts", function: "listCompliancePackJobs" },
    reason: "The service owns the internal compliance-job workflow; the C03 repository implements its scoped reads.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts", function: "startCompliancePackJobInTransaction" },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled service owns the durable compliance-pack claim workflow; the C03 repository performs its transaction-bound job creation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts", function: "completeCompliancePackJobInTransaction" },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled service owns durable completion; the C03 repository performs its transaction-bound state transition.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts", function: "failCompliancePackJobInTransaction" },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled service owns durable failure handling; the C03 repository performs its transaction-bound state transition.",
  },
  ...[
    "loadCompliancePackJobInTransaction",
    "completeCompliancePackRebuildInTransaction",
  ].map((functionName) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts", function: functionName },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled service owns the compliance-pack lifecycle; the repository helper contributes read or rebuild implementation evidence to that canonical workflow.",
  })),
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: "claimCompliancePackSlice" },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled compliance service owns the registered workflow; B03 contributes its database-verifiable partition claim boundary.",
  },
  ...[
    "completeScheduledCompliancePackJob",
    "failScheduledCompliancePackJob",
  ].map((functionName) => ({
    delegated: { executionSurface: "scheduled", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: functionName },
    canonical: { executionSurface: "scheduled", sourceFile: "backend/src/services/compliancePackService.ts", function: "startCompliancePackScheduler" },
    reason: "The scheduled compliance service owns the registered workflow; B03 contributes its database-verifiable claim and terminal transition boundaries.",
  })),
  {
    delegated: { executionSurface: "worker", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: "enqueueAuditLogOutbox" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auditLogOutboxService.ts", function: "queueAuditLogOutbox" },
    reason: "The audit outbox service owns durable enqueue; the B03 repository supplies its exact SQL implementation and is reachable through the registered worker module.",
  },
  {
    delegated: { executionSurface: "worker", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: "enqueueSecurityEventOutbox" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/siemOutboxService.ts", function: "queueSecurityEvent" },
    reason: "The SIEM outbox service owns durable enqueue; the B03 repository supplies its exact SQL implementation and is reachable through the registered worker module.",
  },
  ...[
    "claimAuditLogOutboxSlice",
    "consumeAuditLogOutbox",
    "failAuditLogOutbox",
  ].map((functionName) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: functionName },
    canonical: { executionSurface: "worker", sourceFile: "backend/src/services/auditLogOutboxService.ts", function: "flushAuditLogOutbox" },
    reason: "The registered audit recovery worker owns claim and terminal delivery; the B03 repository contributes exact digest-bound SQL implementation evidence.",
  })),
  ...[
    "claimSecurityEventOutboxSlice",
    "completeSecurityEventOutbox",
    "failSecurityEventOutbox",
  ].map((functionName) => ({
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b03/repositoryFunctions.ts", function: functionName },
    canonical: { executionSurface: "worker", sourceFile: "backend/src/services/siemOutboxService.ts", function: "flushSecurityEventOutbox" },
    reason: "The registered SIEM worker owns claim and terminal delivery; the B03 repository contributes exact digest-bound SQL implementation evidence.",
  })),
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts", function: "listTenantFeatureFlagsInTransaction" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/governanceService.ts", function: "listTenantFeatureFlags" },
    reason: "The service owns the internal feature-flag workflow; the C03 repository implements its scoped read.",
  },
  {
    delegated: { executionSurface: "startup", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "lookupPasswordBootstrapUser" },
    canonical: { executionSurface: "startup", sourceFile: "backend/src/services/auth/authBootstrapRepository.ts", function: "findPreCandidatePasswordUser" },
    reason: "The bootstrap facade remains the canonical pre-auth login owner; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "recordPasswordLoginFailure" },
    canonical: { executionSurface: "startup", sourceFile: "backend/src/services/auth/authBootstrapRepository.ts", function: "recordPasswordLoginFailure" },
    reason: "The bootstrap facade remains the canonical pre-auth login owner; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "requestPasswordResetBoundary" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/passwordResetService.ts", function: "requestPasswordReset" },
    reason: "The password-reset service owns the public request flow; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "consumePasswordResetBoundary" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/passwordResetService.ts", function: "resetPasswordWithToken" },
    reason: "The password-reset service owns token consumption; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "lookupInvitationBoundary" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/inviteService.ts", function: "getInvitePreview" },
    reason: "The invitation service owns preview delivery; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "consumeInvitationBoundary" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/inviteService.ts", function: "acceptInvite" },
    reason: "The invitation service owns token consumption; B01 provides its exact named-function implementation.",
  },
  {
    delegated: { executionSurface: "internal", sourceFile: "backend/src/rls-waves/session-b/b01/preAuthRepository.ts", function: "consumeEmailVerificationBoundary" },
    canonical: { executionSurface: "internal", sourceFile: "backend/src/services/auth/emailVerificationService.ts", function: "confirmEmailVerification" },
    reason: "The email-verification service owns token consumption; B01 provides its exact named-function implementation.",
  },
]);

const VALID_SURFACES = new Set(["http", "worker", "scheduled", "startup", "cli", "internal"]);
export const delegationKey = ({ executionSurface, sourceFile, function: functionName }) => `${executionSurface}:${sourceFile}:${functionName}`;
export const canonicalWorkflowKey = (canonical) => delegationKey(canonical);

const isSourcePath = (value) => typeof value === "string" && /^backend\/(?:src|scripts)\/.+\.(?:[cm]?js|ts)$/.test(value) && !value.includes("..") && !path.isAbsolute(value);
const functionExists = (file, functionName, ts) => {
  const source = fs.readFileSync(file, "utf8");
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  let found = false;
  const visit = (node) => {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name?.getText(ast) === functionName) found = true;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === functionName
      && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) found = true;
    if (ts.isExportSpecifier(node) && (node.name.text === functionName || node.propertyName?.text === functionName)) found = true;
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return found;
};

export const validateWorkflowDelegations = ({ entries = WORKFLOW_DELEGATIONS, repoRoot, sourceExists = fs.existsSync, hasFunction } = {}) => {
  if (!repoRoot) throw new Error("workflow delegation registry validation requires repoRoot");
  const require = createRequire(import.meta.url);
  const ts = hasFunction ? null : require(path.join(repoRoot, "backend/node_modules/typescript"));
  const seen = new Set();
  for (const entry of entries) {
    for (const [label, value] of Object.entries({ delegated: entry?.delegated, canonical: entry?.canonical })) {
      if (!value || !VALID_SURFACES.has(value.executionSurface)) throw new Error(`workflow delegation ${label} has invalid execution surface`);
      if (!isSourcePath(value.sourceFile)) throw new Error(`workflow delegation ${label} has malformed source path`);
      if (!/^[A-Za-z_$][\w$]*$/.test(value.function || "")) throw new Error(`workflow delegation ${label} has missing source function`);
      const file = path.join(repoRoot, value.sourceFile);
      if (!sourceExists(file)) throw new Error(`workflow delegation ${label} source file is missing: ${value.sourceFile}`);
      if (!(hasFunction || ((candidate, name) => functionExists(candidate, name, ts)))(file, value.function)) throw new Error(`workflow delegation ${label} function is missing: ${value.sourceFile}:${value.function}`);
    }
    const key = delegationKey(entry.delegated);
    if (seen.has(key)) throw new Error(`workflow delegation has duplicate delegated source key: ${key}`);
    seen.add(key);
    if (key === canonicalWorkflowKey(entry.canonical)) throw new Error(`workflow delegation cannot delegate to itself: ${key}`);
    if (!entry.reason || typeof entry.reason !== "string") throw new Error(`workflow delegation lacks reason: ${key}`);
  }
  return [...entries].sort((a, b) => delegationKey(a.delegated).localeCompare(delegationKey(b.delegated)));
};

export const resolveWorkflowDelegation = (access, entries = WORKFLOW_DELEGATIONS) => entries.find((entry) => delegationKey(entry.delegated) === delegationKey(access)) || null;
