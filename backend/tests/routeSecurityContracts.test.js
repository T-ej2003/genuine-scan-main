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
assert(routesSource.includes("const publicReadRouter = Router();"), "public read router should be explicit");
assert(routesSource.includes("const publicMutationRouter = Router();"), "public mutation router should be explicit");
assert(routesSource.includes("const cookieReadRouter = Router();"), "cookie read router should be explicit");
assert(routesSource.includes("const cookieMutationRouter = Router();"), "cookie mutation router should be explicit");
assert(routesSource.includes("const protectedReadRouter = Router();"), "protected read router should be explicit");
assert(routesSource.includes("const protectedMutationRouter = Router();"), "protected mutation router should be explicit");

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

[
  "...limiters.exportLimiters",
  "...limiters.incidentSupportMutationLimiters",
].forEach((pattern) => {
  assert(!governanceRoutesSource.includes(pattern), `governance routes should not use injected limiter bundle ${pattern}`);
});

assert(!auditRoutesSource.includes("...auditExportLimiters"), "audit routes should not use spread-applied audit export limiters");

assert(
  authRoutesSource.includes('router.post("/auth/login", loginIpLimiter, loginActorLimiter, login);'),
  "login should declare explicit public auth limiters inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/accept-invite", inviteAcceptanceIpLimiter, inviteAcceptanceActorLimiter, acceptInviteController);'
  ),
  "accept-invite should declare explicit public invite limiters inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/sessions/revoke-all", authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);'
  ),
  "revoke-all should declare auth, rate limits, and CSRF inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnSetupController);'
  ),
  "admin webauthn setup should declare MFA limiter and CSRF inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);'
  ),
  "admin invite should declare its limiter and CSRF inline"
);

assert(
  routesSource.includes(
    'cookieReadRouter.get("/verify/:code", verifyCodeIpLimiter, verifyCodeActorLimiter, optionalCustomerVerifyAuth, verifyQRCode);'
  ),
  "verify code lookup should declare explicit public verify limiters inline"
);
assert(
  routesSource.includes(
    'cookieMutationRouter.post( "/verify/session/:id/intake", requireCustomerVerifyAuth, verifyCustomerCookieRouteLimiter, verifyCustomerCookieMutationIpLimiter, verifyCustomerCookieMutationActorLimiter, requireCustomerVerifyCsrf, submitCustomerVerificationIntake );'
  ),
  "verify intake should declare auth, rate limits, and CSRF inline"
);
assert(
  routesSource.includes(
    'cookieReadRouter.get( "/verify/auth/session", optionalCustomerVerifyAuth, verifySessionRouteLimiter, verifyCustomerSessionReadIpLimiter, verifyCustomerSessionReadActorLimiter, getCustomerVerifyAuthSession );'
  ),
  "verify auth session should declare its read limiters inline"
);
assert(
  routesSource.includes(
    'cookieMutationRouter.post( "/verify/auth/passkey/register/begin", requireCustomerVerifyAuth, verifyCustomerCookieRouteLimiter, verifyCustomerCookieMutationIpLimiter, verifyCustomerCookieMutationActorLimiter, requireCustomerVerifyCsrf, beginCustomerPasskeyRegistration );'
  ),
  "verify passkey registration should declare auth, rate limits, and CSRF inline"
);
assert(
  routesSource.includes(
    'cookieMutationRouter.post( "/verify/:code/claim", optionalCustomerVerifyAuth, verifyClaimRouteLimiter, verifyClaimIpLimiter, verifyClaimActorLimiter, requireCustomerVerifyCsrf, claimProductOwnership );'
  ),
  "claim flow should declare its limiter and CSRF inline"
);
assert(
  routesSource.includes(
    'protectedReadRouter.get("/internal/release", authenticate, requirePlatformAdmin, internalReleaseRouteLimiter, internalReleaseIpLimiter, internalReleaseActorLimiter, internalReleaseMetadata);'
  ),
  "internal release route should declare authentication and rate limiting inline"
);
assert(
  routesSource.includes(
    'router.post("/print-gateway/direct/claim", gatewayJobRouteLimiter, gatewayJobIpLimiter, gatewayJobActorLimiter, claimGatewayDirectJob);'
  ),
  "gateway claim should declare explicit gateway limiters inline"
);
assert(
  routesSource.includes(
    'protectedMutationRouter.post( "/manufacturer/print-jobs", authenticate, requireManufacturer, requireRecentSensitiveAuth, enforceTenantIsolation, printMutationRouteLimiter, printMutationIpLimiter, printMutationActorLimiter, requireCsrf, createPrintJob );'
  ),
  "manufacturer print job creation should declare explicit print limiters inline"
);
assert(
  routesSource.includes(
    'protectedReadRouter.get( "/audit/export/batches/:id/package", authenticate, requireAnyAdmin, protectedReadRouteLimiter, exportReadRouteLimiter, exportReadIpLimiter, exportReadActorLimiter,'
  ),
  "audit export package route should declare explicit export limiters inline"
);
assert(
  routesSource.includes(
    'protectedMutationRouter.patch("/account/profile", authenticate, protectedMutationRouteLimiter, requireRecentSensitiveAuth, requireCsrf, updateMyProfile);'
  ),
  "account profile mutation should declare a direct limiter and CSRF inline"
);
assert(
  routesSource.includes(
    'protectedReadRouter.get("/ir/policies", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, listIrPolicies);'
  ),
  "protected reads should declare a direct route limiter inline"
);
assert(
  routesSource.includes('publicReadRouter.get("/health", publicStatusIpLimiter, publicStatusActorLimiter, healthCheck);'),
  "public health route should remain outside the cookie-auth mutation lane"
);

assert(
  governanceRoutesSource.includes(
    'router.get( "/governance/compliance/report", authenticate, requirePlatformAdmin, governanceExportIpLimiter, governanceExportActorLimiter, generateComplianceReportController );'
  ),
  "governance report export should declare explicit export limiters inline"
);
assert(
  realtimeRoutesSource.includes(
    'router.post( "/manufacturer/printer-agent/heartbeat", authenticate, requireManufacturer, requireRecentSensitiveAuth, enforceTenantIsolation, printerAgentHeartbeatIpLimiter, printerAgentHeartbeatActorLimiter, requireCsrf, reportPrinterHeartbeat );'
  ),
  "printer-agent heartbeat should declare explicit mutation limiters inline"
);
assert(
  auditRoutesSource.includes(
    'router.get( "/logs/export", authenticate, requireAuditViewer, enforceTenantIsolation, auditExportIpLimiter, auditExportActorLimiter, exportLogsCsv );'
  ),
  "audit export should declare explicit export limiters inline"
);

console.log("route security contract tests passed");
