import { readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const readNormalized = (relativePath) =>
  readFileSync(path.join(repoRoot, relativePath), "utf8")
    .replace(/\s+/g, " ")
    .trim();

const files = {
  authRoutes: readNormalized("backend/src/routes/modules/authRoutes.ts"),
  realtimeRoutes: readNormalized("backend/src/routes/modules/realtimeRoutes.ts"),
  governanceRoutes: readNormalized("backend/src/routes/modules/governanceRoutes.ts"),
  auditRoutes: readNormalized("backend/src/routes/auditRoutes.ts"),
  indexRoutes: readNormalized("backend/src/routes/index.ts"),
};

const requirements = [
  {
    file: "authRoutes",
    description: "auth session listing must keep a pre-auth session limiter before authenticate",
    pattern: 'router.get("/auth/sessions", sessionReadPreAuthRouteLimiter, authenticate, sessionReadRouteLimiter, listSessions);',
  },
  {
    file: "authRoutes",
    description: "admin invite must keep a pre-auth invite limiter before authenticate",
    pattern: 'router.post("/auth/invite", adminInvitePreAuthRouteLimiter, authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);',
  },
  {
    file: "realtimeRoutes",
    description: "dashboard stats must keep a pre-auth limiter before authenticate",
    pattern: '"/dashboard/stats", dashboardReadPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "realtimeRoutes",
    description: "notification mutation must keep a pre-auth limiter before authenticate",
    pattern: '"/notifications/read-all", notificationMutationPreAuthRouteLimiter, authenticate, notificationMutationRouteLimiter,',
  },
  {
    file: "realtimeRoutes",
    description: "printer heartbeat must keep a pre-auth limiter before authenticate",
    pattern: '"/manufacturer/printer-agent/heartbeat", printerAgentHeartbeatPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "governanceRoutes",
    description: "governance read routes must keep a pre-auth limiter before authenticate",
    pattern: '"/governance/feature-flags", governanceReadPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "governanceRoutes",
    description: "governance export routes must keep a pre-auth limiter before authenticate",
    pattern: '"/governance/compliance/report", governanceExportPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "governanceRoutes",
    description: "governance approval routes must keep a pre-auth limiter before authenticate",
    pattern: '"/governance/approvals/:id/approve", governanceApprovalMutationPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "auditRoutes",
    description: "audit logs must keep a pre-auth limiter before authenticate",
    pattern: '"/logs", auditLogsReadPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "auditRoutes",
    description: "audit export must keep a pre-auth limiter before authenticate",
    pattern: '"/logs/export", auditLogsExportPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "auditRoutes",
    description: "audit fraud respond must keep a pre-auth limiter before authenticate",
    pattern: '"/fraud-reports/:id/respond", auditFraudReportsRespondPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "indexRoutes",
    description: "verify auth session must keep a pre-auth limiter before optional auth",
    pattern: '"/verify/auth/session", verifySessionPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  },
  {
    file: "indexRoutes",
    description: "verify claim must keep a pre-auth limiter before customer auth checks",
    pattern: '"/verify/:code/claim", verifyClaimPreAuthRouteLimiter, optionalCustomerVerifyAuth,',
  },
  {
    file: "indexRoutes",
    description: "telemetry route transition must keep a pre-auth limiter before optional auth",
    pattern: '"/telemetry/route-transition", telemetryMutationPreAuthRouteLimiter, optionalAuth,',
  },
  {
    file: "indexRoutes",
    description: "internal release must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/internal/release", internalReleasePreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "licensee reads must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/licensees", licenseeReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "licensee mutations must keep a pre-auth limiter before authenticate",
    pattern: 'protectedMutationRouter.post("/licensees", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "qr exports must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/qr/codes/export", qrExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "policy reads must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/trace/timeline", policyReadPreAuthRouteLimiter, authenticate,',
  },
  {
    file: "indexRoutes",
    description: "support reads must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/support/tickets", supportReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "incident reads must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/incidents", incidentReadPreAuthRouteLimiter, authenticate, requireAnyAdmin,',
  },
  {
    file: "indexRoutes",
    description: "IR reads must keep a pre-auth limiter before authenticate",
    pattern: 'protectedReadRouter.get("/ir/incidents", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin,',
  },
  {
    file: "indexRoutes",
    description: "account mutations must keep a pre-auth limiter before authenticate",
    pattern: 'protectedMutationRouter.patch("/account/profile", accountMutationPreAuthRouteLimiter, authenticate, accountMutationRouteLimiter,',
  },
];

const failures = requirements.filter(({ file, pattern }) => !files[file].includes(pattern));

if (failures.length > 0) {
  console.error("Route rate-limit contract check failed:");
  for (const failure of failures) {
    console.error(`- ${failure.description}`);
  }
  process.exit(1);
}

console.log("Route rate-limit contract check passed.");
