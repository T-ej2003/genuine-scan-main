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
  routesSource.includes('publicReadRouter.get("/health", ...publicStatusLimiters, healthCheck);'),
  "public health route should remain outside the cookie-auth mutation lane"
);

console.log("route security contract tests passed");
