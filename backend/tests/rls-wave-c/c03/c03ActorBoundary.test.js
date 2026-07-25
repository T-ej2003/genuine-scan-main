const assert = require("assert");
const fs = require("fs");
const path = require("path");

const distRoot = path.resolve(__dirname, "../../../dist");
const repoRoot = path.resolve(__dirname, "../../../..");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

const ids = {
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000201",
  foreignLicensee: "00000000-0000-4000-8000-000000000202",
  actor: "00000000-0000-4000-8000-000000000301",
  session: "00000000-0000-4000-8000-000000000401",
  resource: "00000000-0000-4000-8000-000000000501",
  request: "00000000-0000-4000-8000-000000000601",
  capability: "A".repeat(43),
};

let queryResult = [];
let queryResults = [];
let queryError = null;
let lastQuery = "";
const tx = {
  $queryRaw: async (strings) => {
    lastQuery = Array.from(strings).join("?");
    if (queryError) throw queryError;
    return queryResults.length ? queryResults.shift() : queryResult;
  },
};
mockModule("config/database.js", { __esModule: true, default: { $transaction: async (callback) => callback(tx) } });

const {
  C03AccessError,
  c03AccessErrorFromDatabase,
  c03CanonicalDbContext,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} = require("../../../dist/rls-waves/session-c/c03/c03ActorBoundary");

const actorRow = (overrides = {}) => ({
  sessionId: ids.session,
  userId: ids.actor,
  role: "LICENSEE_ADMIN",
  organizationId: ids.org,
  licenseeId: ids.licensee,
  assurance: "ADMIN_MFA",
  ...overrides,
});

const boundary = (overrides = {}) => ({
  databaseSessionCapability: ids.capability,
  requestId: ids.request,
  purpose: "compliance-pack-start",
  licenseeId: ids.licensee,
  allowedRoles: ["LICENSEE_ADMIN"],
  requiredAssurance: "mfa-verified",
  ...overrides,
});

const run = async () => {
  const auditService = fs.readFileSync(path.join(repoRoot, "backend/src/services/auditService.ts"), "utf8");
  const transactionalAudit = auditService.slice(
    auditService.indexOf("export const createAuditLogInTransaction"),
    auditService.indexOf("export const createAuditLog =", auditService.indexOf("export const createAuditLogInTransaction"))
  );
  assert.match(transactionalAudit, /queueAuditLogOutbox\(payload, undefined, tx/);
  assert.doesNotMatch(transactionalAudit, /INSERT INTO public\."AuditLog"|SecurityEventOutbox|appendForensicChainFromAuditLog/);

  queryResult = [actorRow()];
  const context = await withC03ActorTransaction(boundary(), async (_db, verified) => verified);
  assert.equal(context.userId, ids.actor);
  assert.equal(context.licenseeId, ids.licensee);
  assert.equal(context.databaseSessionCapability, ids.capability);
  assert.deepEqual(c03CanonicalDbContext(context), {
    userId: ids.actor,
    role: "LICENSEE_ADMIN",
    organizationId: ids.org,
    licenseeId: ids.licensee,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId: ids.request,
    purpose: "compliance-pack-start",
  });
  assert.match(lastQuery, /app_rls\.c03_require_authenticated_actor/);
  assert.doesNotMatch(lastQuery, /install_actor_context|c03_revalidate_actor_scope/);

  assert.deepEqual(c03CanonicalDbContext({
    ...context,
    role: "PLATFORM_SUPER_ADMIN",
    organizationId: ids.org,
    licenseeId: ids.licensee,
  }), {
    userId: ids.actor,
    role: "PLATFORM_SUPER_ADMIN",
    organizationId: null,
    licenseeId: null,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId: ids.request,
    purpose: "compliance-pack-start",
  });
  const incidentDenied = c03AccessErrorFromDatabase({
    code: "P2010",
    meta: { code: "42501", message: "ERROR: C03_INCIDENT_DENIED" },
  });
  assert(incidentDenied instanceof C03AccessError);
  assert.equal(incidentDenied.statusCode, 404);
  assert.equal(incidentDenied.message, "Incident not found");
  assert.equal(c03AccessErrorFromDatabase({
    code: "P2010",
    meta: { code: "42501", message: "ERROR: C03_UNREVIEWED_DENIAL" },
  }), null);

  queryResults = [
    [actorRow({ role: "SUPER_ADMIN", organizationId: null, licenseeId: null })],
    [{
      userId: ids.actor,
      role: "SUPER_ADMIN",
      organizationId: ids.org,
      licenseeId: ids.licensee,
    }],
  ];
  const platformResourceContext = await withC03ResourceTransaction({
    ...boundary({
      role: undefined,
      licenseeId: undefined,
      purpose: "compliance-pack-download",
      allowedRoles: ["SUPER_ADMIN"],
    }),
    resourceId: ids.resource,
    resourceType: "compliancePackJob",
  }, async (_db, verified) => verified);
  assert.equal(platformResourceContext.organizationId, ids.org);
  assert.equal(platformResourceContext.licenseeId, ids.licensee);

  await assert.rejects(
    () => withC03ActorTransaction(boundary({ databaseSessionCapability: "forged" }), async () => null),
    (error) => error instanceof C03AccessError && error.statusCode === 401
  );
  await assert.rejects(
    () => withC03ActorTransaction(boundary({ licenseeId: ids.foreignLicensee }), async () => null),
    /Access denied to this licensee/
  );

  queryResult = [actorRow({ role: "MANUFACTURER" })];
  await assert.rejects(
    () => withC03ActorTransaction(boundary(), async () => null),
    /Access denied/
  );
  queryResult = [actorRow({ assurance: "PASSWORD" })];
  await assert.rejects(
    () => withC03ActorTransaction(boundary(), async () => null),
    /Fresh administrator MFA/
  );
  queryResult = [];
  await assert.rejects(
    () => withC03ActorTransaction(boundary(), async () => null),
    (error) => error instanceof C03AccessError && error.statusCode === 401
  );

  queryResult = [actorRow()];
  const resource = await withC03ResourceTransaction({
    ...boundary(),
    purpose: "compliance-pack-download",
    resourceId: ids.resource,
    resourceType: "compliancePackJob",
  }, async (_db, verified) => verified);
  assert.equal(resource.sessionId, ids.session);
  assert.match(lastQuery, /app_rls\.c03_revalidate_compliance_pack_job_actor_scope/);

  queryResults = [
    [actorRow({ role: "SUPER_ADMIN", organizationId: null, licenseeId: null })],
    [{
      userId: ids.actor,
      role: "SUPER_ADMIN",
      organizationId: ids.org,
      licenseeId: ids.licensee,
    }],
  ];
  const approval = await withC03ResourceTransaction({
    ...boundary(),
    purpose: "sensitive-action-approval-reject",
    resourceId: ids.resource,
    resourceType: "sensitiveActionApproval",
    allowedRoles: ["SUPER_ADMIN"],
  }, async (_db, verified) => verified);
  assert.equal(approval.licenseeId, ids.licensee);
  assert.equal(approval.organizationId, ids.org);
  assert.match(lastQuery, /app_rls\.c03_bind_sensitive_approval_actor/);

  queryError = new Error("AUTHENTICATED_SESSION_REVOKED");
  await assert.rejects(
    () => withC03ResourceTransaction({
      ...boundary(),
      resourceId: ids.resource,
      resourceType: "compliancePackJob",
    }, async () => null),
    /AUTHENTICATED_SESSION_REVOKED/
  );

  console.log("C03 capability transaction boundary tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
