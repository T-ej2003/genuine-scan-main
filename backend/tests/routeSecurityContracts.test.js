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
assert(authRoutesSource.includes("router.use(cookieParser());"), "auth router should own its cookie parsing lane");
assert(routesSource.includes("const cookiePublicRouter = Router();"), "cookie-aware public router should be explicit");
assert(routesSource.includes("const protectedRouter = Router();"), "protected router should be explicit");
assert(routesSource.includes("cookiePublicRouter.use(cookieParser());"), "cookie-aware public router should parse cookies locally");
assert(routesSource.includes("protectedRouter.use(cookieParser());"), "protected router should parse cookies locally");

assert(
  authRoutesSource.includes(
    'router.post("/auth/sessions/revoke-all", authenticate, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);'
  ),
  "revoke-all should declare auth, rate limits, and CSRF inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnSetupController);'
  ),
  "admin webauthn setup should declare MFA limiter and CSRF inline"
);
assert(
  authRoutesSource.includes(
    'router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);'
  ),
  "admin invite should declare its limiter and CSRF inline"
);

assert(
  routesSource.includes(
    'cookiePublicRouter.post( "/verify/session/:id/intake", requireCustomerVerifyAuth, verifyCustomerCookieMutationIpLimiter, verifyCustomerCookieMutationActorLimiter, requireCustomerVerifyCsrf, submitCustomerVerificationIntake );'
  ),
  "verify intake should declare auth, rate limits, and CSRF inline"
);
assert(
  routesSource.includes(
    'cookiePublicRouter.get( "/verify/auth/session", optionalCustomerVerifyAuth, verifyCustomerSessionReadIpLimiter, verifyCustomerSessionReadActorLimiter, getCustomerVerifyAuthSession );'
  ),
  "verify auth session should declare its read limiters inline"
);
assert(
  routesSource.includes(
    'cookiePublicRouter.post( "/verify/auth/passkey/register/begin", requireCustomerVerifyAuth, verifyCustomerCookieMutationIpLimiter, verifyCustomerCookieMutationActorLimiter, requireCustomerVerifyCsrf, beginCustomerPasskeyRegistration );'
  ),
  "verify passkey registration should declare auth, rate limits, and CSRF inline"
);
assert(
  routesSource.includes(
    'cookiePublicRouter.post( "/verify/:code/claim", optionalCustomerVerifyAuth, verifyClaimIpLimiter, verifyClaimActorLimiter, requireCustomerVerifyCsrf, claimProductOwnership );'
  ),
  "claim flow should declare its limiter and CSRF inline"
);
assert(
  routesSource.includes(
    'protectedRouter.get("/internal/release", authenticate, requirePlatformAdmin, internalReleaseIpLimiter, internalReleaseActorLimiter, internalReleaseMetadata);'
  ),
  "internal release route should declare authentication and rate limiting inline"
);
assert(
  routesSource.includes('router.get("/health", ...publicStatusLimiters, healthCheck);'),
  "public health route should remain outside the cookie-auth mutation lane"
);

console.log("route security contract tests passed");
