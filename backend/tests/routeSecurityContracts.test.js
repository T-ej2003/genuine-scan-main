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
const authRoutesSource = readNormalized("src/routes/modules/authRoutes.ts");
const routesSource = readNormalized("src/routes/index.ts");
const realtimeRoutesSource = readNormalized("src/routes/modules/realtimeRoutes.ts");
const governanceRoutesSource = readNormalized("src/routes/modules/governanceRoutes.ts");
const auditRoutesSource = readNormalized("src/routes/auditRoutes.ts");

assert(!indexSource.includes("app.use(cookieParser())"), "app root should not mount cookie parsing globally");
assert(!authRoutesSource.includes("router.use(cookieParser());"), "auth routes should not hide cookie parsing behind router.use");
assert(!routesSource.includes("cookiePublicRouter.use(cookieParser());"), "cookie-aware verify routes should not hide cookie parsing behind router.use");
assert(!routesSource.includes("protectedRouter.use(cookieParser());"), "protected routes should not hide cookie parsing behind router.use");
assert(!authRoutesSource.includes("const createJsonRateLimitHandler"), "auth routes should use shared rate-limit telemetry handlers");
assert(!realtimeRoutesSource.includes("const createJsonRateLimitHandler"), "realtime routes should use shared rate-limit telemetry handlers");
assert(!governanceRoutesSource.includes("const createJsonRateLimitHandler"), "governance routes should use shared rate-limit telemetry handlers");
assert(!auditRoutesSource.includes("const createJsonRateLimitHandler"), "audit routes should use shared rate-limit telemetry handlers");
assert(!routesSource.includes("const createJsonRateLimitHandler"), "main routes should use shared rate-limit telemetry handlers");

[
  "...loginLimiters",
  "...inviteAcceptanceLimiters",
  "...verifyEmailLimiters",
  "...forgotPasswordLimiters",
].forEach((pattern) => {
  assert(!authRoutesSource.includes(pattern), `auth routes should not use spread-applied limiter bundle ${pattern}`);
});

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

assert(authRoutesSource.includes("const sessionReadPreAuthRouteLimiter = rateLimit("), "auth routes should define a pre-auth session limiter");
assert(authRoutesSource.includes("const secureSessionPreAuthRouteLimiter = rateLimit("), "auth routes should define a pre-auth secure-session limiter");
assert(authRoutesSource.includes("const mfaPreAuthRouteLimiter = rateLimit("), "auth routes should define a pre-auth MFA limiter");
assert(authRoutesSource.includes("const adminInvitePreAuthRouteLimiter = rateLimit("), "auth routes should define a pre-auth invite limiter");
assert(realtimeRoutesSource.includes("const dashboardReadPreAuthRouteLimiter: RequestHandler = rateLimit("), "realtime routes should define a pre-auth dashboard read limiter");
assert(realtimeRoutesSource.includes("const printerAgentHeartbeatPreAuthRouteLimiter: RequestHandler = rateLimit("), "realtime routes should define a pre-auth printer heartbeat limiter");
assert(governanceRoutesSource.includes("const governanceReadPreAuthRouteLimiter: RequestHandler = rateLimit("), "governance routes should define a pre-auth governance read limiter");
assert(governanceRoutesSource.includes("const governanceApprovalMutationPreAuthRouteLimiter: RequestHandler = rateLimit("), "governance routes should define a pre-auth approval limiter");
assert(auditRoutesSource.includes("const auditLogsReadPreAuthRouteLimiter: RequestHandler = rateLimit("), "audit routes should define a pre-auth audit read limiter");
assert(auditRoutesSource.includes("const auditFraudReportsRespondPreAuthRouteLimiter: RequestHandler = rateLimit("), "audit routes should define a pre-auth audit fraud mutation limiter");

[
  'router.get("/auth/sessions", sessionReadPreAuthRouteLimiter, authenticate, sessionReadRouteLimiter, listSessions);',
  'router.post("/auth/sessions/revoke-all", secureSessionPreAuthRouteLimiter, authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);',
  'router.post("/auth/mfa/backup-codes/rotate", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, rotateAdminMfaBackupCodesController);',
  'router.post("/auth/invite", adminInvitePreAuthRouteLimiter, authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);',
].forEach((pattern) => {
  assert(authRoutesSource.includes(pattern), `auth route contract missing: ${pattern}`);
});

[
  '"/dashboard/stats", dashboardReadPreAuthRouteLimiter, authenticate,',
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
  '"/verify/auth/logout", verifyCustomerCookiePreAuthRouteLimiter, verifyCustomerCookieRouteLimiter,',
  '"/verify/auth/passkey/register/begin", verifyCustomerCookiePreAuthRouteLimiter, requireCustomerVerifyAuth,',
  '"/verify/auth/passkey/assertion/begin", verifyCustomerMutationPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  '"/verify/:code/claim", verifyClaimPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  '"/telemetry/route-transition", telemetryMutationPreAuthRouteLimiter, optionalAuth,',
  '"/telemetry/csp-report", cspTelemetryPreAuthRouteLimiter, optionalAuth,',
  '"/internal/release", internalReleasePreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/security/abuse/rate-limits", securityOpsReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/security/abuse/rate-limits/alerts", securityOpsReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/licensees/export", licenseeExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/licensees", licenseeReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/licensees", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/users", adminDirectoryMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/manufacturers", adminDirectoryReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/qr/codes/export", qrExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/qr/requests", qrRequestReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/trace/timeline", policyReadPreAuthRouteLimiter, authenticate,',
  '"/support/tickets", supportReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/incidents", incidentReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  '"/ir/incidents", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  '"/account/profile", accountMutationPreAuthRouteLimiter, authenticate, accountMutationRouteLimiter,',
].forEach((pattern) => {
  assert(routesSource.includes(pattern), `main route contract missing: ${pattern}`);
});

console.log("route security contract tests passed");
