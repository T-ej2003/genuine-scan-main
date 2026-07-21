const assert = require("assert");
const path = require("path");

const distRoot = path.resolve(__dirname, "../../../dist");
const resolved = (relativePath) => require.resolve(path.join(distRoot, relativePath));
const mockModule = (relativePath, exportsValue) => {
  const filename = resolved(relativePath);
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

const ids = {
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000201",
  foreignLicensee: "00000000-0000-4000-8000-000000000202",
  actor: "00000000-0000-4000-8000-000000000301",
  incident: "00000000-0000-4000-8000-000000000401",
  request: "00000000-0000-4000-8000-000000000501",
};

let queryResult = [];
let queryError = null;
let lastQuery = "";
const tx = {
  $executeRaw: async () => 1,
  $queryRaw: async (strings) => {
    lastQuery = Array.from(strings).join("?");
    if (queryError) throw queryError;
    return queryResult;
  },
};
const database = {
  $transaction: async (callback) => callback(tx),
};

mockModule("config/database.js", { __esModule: true, default: database });
mockModule("services/auth/authService.js", { getAdminStepUpWindowMinutes: () => 15 });

const {
  C03AccessError,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} = require("../../../dist/rls-waves/session-c/c03/c03ActorBoundary");

const platform = (overrides = {}) => ({
  userId: ids.actor,
  role: "PLATFORM_SUPER_ADMIN",
  orgId: null,
  licenseeId: null,
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date(),
  ...overrides,
});

const actorRow = (overrides = {}) => ({
  userId: ids.actor,
  role: "PLATFORM_SUPER_ADMIN",
  organizationId: ids.org,
  licenseeId: ids.licensee,
  ...overrides,
});

const selectorBoundary = (overrides = {}) => ({
  user: platform(),
  requestId: ids.request,
  purpose: "incident-response-policy-list",
  licenseeId: ids.licensee,
  allowedRoles: ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN"],
  requiredAssurance: "mfa-verified",
  ...overrides,
});

const run = async () => {
  queryResult = [actorRow()];
  const selector = await withC03ActorTransaction(selectorBoundary(), async (_db, context) => context);
  assert.equal(selector.licenseeId, ids.licensee);
  assert.match(lastQuery, /c03_revalidate_actor_scope/);

  await assert.rejects(
    () => withC03ActorTransaction(selectorBoundary({ user: platform({ role: "MANUFACTURER" }) }), async () => null),
    (error) => error instanceof C03AccessError && error.statusCode === 403
  );
  await assert.rejects(
    () => withC03ActorTransaction(selectorBoundary({ user: platform({ authAssurance: "PASSWORD", mfaVerifiedAt: null }) }), async () => null),
    /Fresh administrator MFA/
  );
  await assert.rejects(
    () => withC03ActorTransaction(selectorBoundary({ user: platform({ sessionStage: "MFA_PENDING" }) }), async () => null),
    (error) => error instanceof C03AccessError && error.statusCode === 401
  );

  const tenantUser = platform({
    role: "LICENSEE_ADMIN",
    orgId: ids.org,
    licenseeId: ids.licensee,
  });
  await assert.rejects(
    () => withC03ActorTransaction(selectorBoundary({
      user: tenantUser,
      licenseeId: ids.foreignLicensee,
      allowedRoles: ["LICENSEE_ADMIN"],
    }), async () => null),
    /Access denied to this licensee/
  );

  queryResult = [];
  await assert.rejects(
    () => withC03ActorTransaction(selectorBoundary(), async () => null),
    /no longer authorized/
  );

  queryResult = [actorRow()];
  const resource = await withC03ResourceTransaction({
    user: platform(),
    requestId: ids.request,
    purpose: "incident-response-detail",
    resourceId: ids.incident,
    resourceType: "incident",
    allowedRoles: ["PLATFORM_SUPER_ADMIN"],
    requiredAssurance: "step-up-verified",
  }, async (_db, context) => context);
  assert.equal(resource.licenseeId, ids.licensee);
  assert.match(lastQuery, /c03_revalidate_incident_actor_scope/);

  queryError = new Error("function app_rls.c03_revalidate_incident_actor_scope does not exist");
  await assert.rejects(
    () => withC03ResourceTransaction({
      user: platform(),
      requestId: ids.request,
      purpose: "incident-response-detail",
      resourceId: ids.incident,
      resourceType: "incident",
      allowedRoles: ["PLATFORM_SUPER_ADMIN"],
      requiredAssurance: "step-up-verified",
    }, async () => null),
    /does not exist/
  );

  console.log("C03 actor and resource boundary tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
