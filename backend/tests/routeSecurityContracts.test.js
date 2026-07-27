const assert = require("assert");
const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");

const readNormalized = (relativePath) =>
  fs
    .readFileSync(path.join(repoRoot, relativePath), "utf8")
    .replace(/\s+/g, " ")
    .trim();

const indexSource = readNormalized("src/index.ts");
const appSource = readNormalized("src/app.ts");
const authRoutesSource = readNormalized("src/routes/modules/authRoutes.ts");
const authSecurityControllerSource = readNormalized("src/controllers/authAdminSecurityController.ts");
const authClaimsContextSource = readNormalized("src/services/auth/authClaimsRlsContext.ts");
const routesSource = readNormalized("src/routes/index.ts");
const realtimeRoutesSource = readNormalized("src/routes/modules/realtimeRoutes.ts");
const governanceRoutesSource = readNormalized("src/routes/modules/governanceRoutes.ts");
const auditRoutesSource = readNormalized("src/routes/auditRoutes.ts");

assert(!indexSource.includes("app.use(cookieParser())"), "app root should not mount cookie parsing globally");
assert(!appSource.includes("app.use(cookieParser())"), "app root should not mount cookie parsing globally");
assert(!authRoutesSource.includes("router.use(cookieParser());"), "auth routes should not hide cookie parsing behind router.use");
assert(!routesSource.includes("cookiePublicRouter.use(cookieParser());"), "cookie-aware verify routes should not hide cookie parsing behind router.use");
assert(!routesSource.includes("protectedRouter.use(cookieParser());"), "protected routes should not hide cookie parsing behind router.use");
assert(!authRoutesSource.includes("const createJsonRateLimitHandler"), "auth routes should use shared rate-limit telemetry handlers");
assert(!realtimeRoutesSource.includes("const createJsonRateLimitHandler"), "realtime routes should use shared rate-limit telemetry handlers");
assert(!governanceRoutesSource.includes("const createJsonRateLimitHandler"), "governance routes should use shared rate-limit telemetry handlers");
assert(!auditRoutesSource.includes("const createJsonRateLimitHandler"), "audit routes should use shared rate-limit telemetry handlers");
assert(!routesSource.includes("const createJsonRateLimitHandler"), "main routes should use shared rate-limit telemetry handlers");
assert(
  appSource.includes("app.use(express.urlencoded({ extended: false, limit: \"1mb\" })); app.use(express.json({ limit: \"1mb\" })); app.use(sanitizeRequestInput);"),
  "app root should mount request sanitization globally after body parsers and before routes"
);

[
  "...loginLimiters",
  "...inviteAcceptanceLimiters",
  "...verifyEmailLimiters",
  "...forgotPasswordLimiters",
].forEach((pattern) => {
  assert(!authRoutesSource.includes(pattern), `auth routes should not use spread-applied limiter bundle ${pattern}`);
});

assert(
  auditRoutesSource.includes('"/logs/export", auditLogsExportPreAuthRouteLimiter, authenticate, requireAuditViewer, requireRecentAdminMfa, enforceTenantIsolation,'),
  "audit CSV export must require the approved platform-admin MFA ceiling before tenant isolation"
);
assert(
  auditRoutesSource.includes('"/logs", auditLogsReadPreAuthRouteLimiter, authenticate, requireAuditViewer, requireRecentAdminMfa, enforceTenantIsolation,'),
  "audit log reads must require the approved MFA ceiling before tenant isolation"
);

[
  "...verifyCodeLimiters",
  "...verifyOtpRequestLimiters",
  "...verifyOtpVerifyLimiters",
  "...connectorManifestLimiters",
  "...connectorDownloadLimiters",
  "...supportTicketTrackLimiters",
  "...telemetryLimiters",
  "...cspReportLimiters",
  "...publicStatusLimiters",
  "...gatewayHeartbeatLimiters",
  "...gatewayJobLimiters",
  "...printMutationLimiters",
  "...exportLimiters",
].forEach((pattern) => {
  assert(!routesSource.includes(pattern), `main routes should not use spread-applied limiter bundle ${pattern}`);
});

assert(!auditRoutesSource.includes("...auditExportLimiters"), "audit routes should not use spread-applied audit export limiters");

assert(authRoutesSource.includes("const sessionReadPreAuthRouteLimiter = createSharedRateLimiter("), "auth routes should define a shared pre-auth session limiter");
assert(authRoutesSource.includes("const secureSessionPreAuthRouteLimiter = createSharedRateLimiter("), "auth routes should define a shared pre-auth secure-session limiter");
assert(authRoutesSource.includes("const mfaPreAuthRouteLimiter = createSharedRateLimiter("), "auth routes should define a shared pre-auth MFA limiter");
assert(authRoutesSource.includes("const adminInvitePreAuthRouteLimiter = createSharedRateLimiter("), "auth routes should define a shared pre-auth invite limiter");
assert(realtimeRoutesSource.includes("const dashboardReadPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "realtime routes should define a shared pre-auth dashboard read limiter");
assert(realtimeRoutesSource.includes("const printerAgentHeartbeatPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "realtime routes should define a shared pre-auth printer heartbeat limiter");
assert(governanceRoutesSource.includes("const governanceReadPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "governance routes should define a shared pre-auth governance read limiter");
assert(governanceRoutesSource.includes("const governanceApprovalMutationPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "governance routes should define a shared pre-auth approval limiter");
assert(auditRoutesSource.includes("const auditLogsReadPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "audit routes should define a shared pre-auth audit read limiter");
assert(auditRoutesSource.includes("const auditFraudReportsRespondPreAuthRouteLimiter: RequestHandler = createSharedRateLimiter("), "audit routes should define a shared pre-auth audit fraud mutation limiter");

[
  'router.get("/auth/sessions", sessionReadPreAuthRouteLimiter, authenticate, sessionReadRouteLimiter, listSessions);',
  'router.post("/auth/sessions/revoke-all", secureSessionPreAuthRouteLimiter, authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);',
  'router.post("/auth/mfa/backup-codes/rotate", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, rotateAdminMfaBackupCodesController);',
  'router.post("/auth/mfa/setup/begin", mfaPreAuthRouteLimiter, authenticateAnySession, requireRecentAdminMfaForSetup, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminMfaSetupController);',
  'router.post("/auth/mfa/setup/confirm", mfaPreAuthRouteLimiter, authenticateAnySession, requireRecentAdminMfaForSetup, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, confirmAdminMfaSetupController);',
  'router.post("/auth/invite", adminInvitePreAuthRouteLimiter, authenticate, requireAdministrationMutator, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);',
].forEach((pattern) => {
  assert(authRoutesSource.includes(pattern), `auth route contract missing: ${pattern}`);
});

assert.strictEqual(
  authClaimsContextSource.includes('mode: "FIRST_ENROLLMENT"') && authClaimsContextSource.includes('mode: "REPLACEMENT"'),
  true,
  "atomic claim-bound TOTP operations must use explicit enrollment and replacement modes"
);
assert(!authSecurityControllerSource.includes("console.error"), "auth security controllers must not serialize raw WebAuthn errors");

[
  '"/dashboard/stats", dashboardReadPreAuthRouteLimiter, authenticate,',
  '"/dashboard/attention-queue", dashboardReadPreAuthRouteLimiter, authenticate,',
  '"/events/dashboard", dashboardStreamPreAuthRouteLimiter, authenticateSSE,',
  '"/events/notifications", notificationReadPreAuthRouteLimiter, authenticateSSE,',
  '"/notifications", notificationReadPreAuthRouteLimiter, authenticate,',
  '"/notifications/read-all", notificationMutationPreAuthRouteLimiter, authenticate, notificationMutationRouteLimiter,',
  '"/manufacturer/printer-agent/status", printerAgentReadPreAuthRouteLimiter, authenticate,',
  '"/manufacturer/printer-agent/events", printerAgentStreamPreAuthRouteLimiter, authenticateSSE,',
  '"/manufacturer/printer-agent/heartbeat", printerAgentHeartbeatPreAuthRouteLimiter, authenticate,',
].forEach((pattern) => {
  assert(realtimeRoutesSource.includes(pattern), `realtime route contract missing: ${pattern}`);
});

[
  '"/governance/feature-flags", governanceReadPreAuthRouteLimiter, authenticate,',
  '"/governance/compliance/report", governanceExportPreAuthRouteLimiter, authenticate,',
  '"/governance/feature-flags", governanceMutationPreAuthRouteLimiter, authenticate,',
  '"/governance/approvals/:id/approve", governanceApprovalMutationPreAuthRouteLimiter, authenticate,',
  '"/governance/approvals/:id/reject", governanceApprovalMutationPreAuthRouteLimiter, authenticate,',
].forEach((pattern) => {
  assert(governanceRoutesSource.includes(pattern), `governance route contract missing: ${pattern}`);
});

[
  '"/logs", auditLogsReadPreAuthRouteLimiter, authenticate,',
  '"/logs/export", auditLogsExportPreAuthRouteLimiter, authenticate,',
  '"/stream", auditStreamPreAuthRouteLimiter, authenticateSSE,',
  '"/fraud-reports", auditFraudReportsReadPreAuthRouteLimiter, authenticate,',
  '"/fraud-reports/:id/respond", auditFraudReportsRespondPreAuthRouteLimiter, authenticate,',
].forEach((pattern) => {
  assert(auditRoutesSource.includes(pattern), `audit route contract missing: ${pattern}`);
});

[
  '"/verify/session/:id/intake", verifySessionMutationPreAuthRouteLimiter, requireCustomerVerifyAuth, verifyCustomerCookieRouteLimiter,',
  '"/verify/session/:id/reveal", verifySessionMutationPreAuthRouteLimiter, requireCustomerVerifyAuth, verifyCustomerCookieRouteLimiter,',
  '"/verify/auth/session", verifySessionPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  '"/verify/auth/logout", verifyCustomerCookiePreAuthRouteLimiter, optionalCustomerVerifyAuth, verifyCustomerCookieRouteLimiter,',
  '"/verify/auth/passkey/register/begin", verifyCustomerCookiePreAuthRouteLimiter, requireCustomerVerifyAuth,',
  '"/verify/auth/passkey/assertion/begin", verifyCustomerMutationPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  '"/verify/session/:id/claim", verifyClaimPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  '"/telemetry/route-transition", telemetryMutationPreAuthRouteLimiter, optionalAuth,',
  '"/telemetry/csp-report", cspTelemetryPreAuthRouteLimiter, optionalAuth,',
  '"/internal/release", internalReleasePreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/security/abuse/rate-limits", securityOpsReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/security/abuse/rate-limits/alerts", securityOpsReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/licensees/export", licenseeExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/licensees", licenseeReadPreAuthRouteLimiter, authenticate, requireTenantDirectoryReader,',
  '"/licensees", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/users", adminDirectoryMutationPreAuthRouteLimiter, authenticate, requireAdministrationMutator,',
  '"/manufacturers", adminDirectoryReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/qr/codes/export", qrExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/qr/requests", qrRequestReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/trace/timeline", policyReadPreAuthRouteLimiter, authenticate,',
  '"/support/tickets", supportReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/incidents", incidentReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/ir/incidents", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/account/profile", accountMutationPreAuthRouteLimiter, authenticate, accountMutationRouteLimiter,',
  '"/manufacturer/print-jobs", printMutationPreAuthRouteLimiter, authenticate, requireManufacturer,',
  '"/manufacturer/printers", printMutationPreAuthRouteLimiter, authenticate, requireOpsUser,',
  '"/manufacturer/printers/:id", printMutationPreAuthRouteLimiter, authenticate, requireOpsUser,',
  '"/manufacturer/printers/:id/test", printMutationPreAuthRouteLimiter, authenticate, requireOpsUser,',
  '"/manufacturer/printers/:id/test-label", printMutationPreAuthRouteLimiter, authenticate, requireOpsUser,',
  '"/manufacturer/printers/:id/discover", printMutationPreAuthRouteLimiter, authenticate, requireOpsUser,',
  '"/manufacturer/print-jobs/:id/direct-print/tokens", printMutationPreAuthRouteLimiter, authenticate, requireManufacturer,',
  '"/manufacturer/print-jobs/:id/confirm", printMutationPreAuthRouteLimiter, authenticate, requireManufacturer,',
  '"/manufacturer/print-jobs/:id/sample-scan", printMutationPreAuthRouteLimiter, authenticate, requireManufacturer,',
].forEach((pattern) => {
  assert(routesSource.includes(pattern), `main route contract missing: ${pattern}`);
});

console.log("route security contract tests passed");
