const assert = require("assert");
const fs = require("fs");
const path = require("path");

const distRoot = path.resolve(__dirname, "../../../dist");
const controllerSource = fs.readFileSync(
  path.resolve(__dirname, "../../../src/controllers/approvalController.ts"),
  "utf8"
);
const approvalSql = fs.readFileSync(
  path.resolve(__dirname, "../../../src/rls-waves/session-c/c03/c03ApprovalFunctions.sql"),
  "utf8"
);
const approvalRepository = require(path.join(distRoot, "rls-waves/session-c/c03/c03ApprovalRepository.js"));
const incidentRepository = require(path.join(distRoot, "rls-waves/session-c/c03/c03IncidentRepository.js"));
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let actorBoundary = null;
let resourceBoundary = null;
let createInput = null;
let approveNote = null;
let approvalRepositoryError = null;
class C03AccessError extends Error {
  constructor(message, statusCode = 403) {
    super(message);
    this.statusCode = statusCode;
  }
}
mockModule("rls-waves/session-c/c03/c03ActorBoundary.js", {
  C03AccessError,
  withC03ActorTransaction: async (boundary, callback) => {
    actorBoundary = boundary;
    return callback({});
  },
  withC03ResourceTransaction: async (boundary, callback) => {
    resourceBoundary = boundary;
    return callback({});
  },
});
mockModule("rls-waves/session-c/c03/c03ApprovalRepository.js", {
  createSensitiveApprovalInTransaction: async (_tx, input) => {
    createInput = input;
    return { id: "approval-1", status: "PENDING" };
  },
  listSensitiveApprovalsInTransaction: async () => [],
  approveSensitiveApprovalInTransaction: async (_tx, _approvalId, note) => {
    if (approvalRepositoryError) throw approvalRepositoryError;
    approveNote = note;
    return { approval: { status: "EXECUTED" } };
  },
  rejectSensitiveApprovalInTransaction: async () => ({ status: "REJECTED" }),
});

const service = require("../../../dist/services/sensitiveActionApprovalService");

const ids = {
  actor: "00000000-0000-4000-8000-000000000301",
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000201",
  approval: "00000000-0000-4000-8000-000000000401",
  request: "00000000-0000-4000-8000-000000000501",
};

const user = (overrides = {}) => ({
  userId: ids.actor,
  role: "PLATFORM_SUPER_ADMIN",
  orgId: null,
  licenseeId: null,
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date(),
  ...overrides,
});
const actor = { userId: ids.actor, role: "PLATFORM_SUPER_ADMIN", orgId: null, licenseeId: null };
const databaseSessionCapability = "A".repeat(43);

const create = (overrides = {}) => service.createSensitiveActionApproval({
  actionKey: service.SENSITIVE_ACTION_KEYS.QR_BLOCK,
  actor,
  licenseeId: ids.licensee,
  entityType: "QRCode",
  entityId: ids.approval,
  payload: { qrId: ids.approval },
  securityContext: { databaseSessionCapability, requestId: ids.request },
  ...overrides,
});

const run = async () => {
  assert.equal(
    (controllerSource.match(/databaseSessionCapability:\s*c03DatabaseSessionCapability\(req\)/g) || []).length,
    3,
    "all active sensitive-approval routes must pass the authenticated database capability"
  );
  assert.doesNotMatch(approvalSql, /SensitiveActionApproval"%ROWTYPE|RETURNING\s+\*|to_jsonb\(a\)/i);
  assert.equal(
    (controllerSource.match(/requestId:\s*c03RequestId\(req\)/g) || []).length,
    3,
    "all active sensitive-approval routes must pass the canonical request ID"
  );

  await assert.rejects(
    () => create({ securityContext: undefined }),
    (error) => error instanceof C03AccessError && error.statusCode === 401
  );
  assert.equal(actorBoundary, null, "missing caller context must fail before database boundary");

  actorBoundary = null;
  await assert.rejects(
    () => create({ actionKey: "UNKNOWN_ACTION" }),
    (error) => error instanceof C03AccessError && error.statusCode === 400
  );
  assert.equal(actorBoundary, null, "invalid action must fail before database boundary");

  await assert.rejects(
    () => service.listSensitiveActionApprovals({
      actor,
      licenseeId: ids.licensee,
      limit: Number.NaN,
      securityContext: { databaseSessionCapability, requestId: ids.request },
    }),
    /pagination is invalid/
  );

  const created = await create();
  assert.equal(created.status, "PENDING");
  assert.equal(actorBoundary.purpose, "sensitive-action-approval-request");
  assert.equal(actorBoundary.databaseSessionCapability, databaseSessionCapability);
  assert.equal(actorBoundary.licenseeId, ids.licensee);
  assert.equal(actorBoundary.requiredAssurance, "password-verified");
  assert(!("userId" in createInput), "database input must derive requester attribution from canonical context");
  assert(!("licenseeId" in createInput), "database input must derive tenant ownership from canonical context");
  assert(!("role" in createInput), "database input must not trust caller role text");

  await service.approveSensitiveActionApproval({
    approvalId: ids.approval,
    actor,
    reviewNote: "  reviewed  ",
    securityContext: { databaseSessionCapability, requestId: ids.request },
  });
  assert.equal(resourceBoundary.resourceType, "sensitiveActionApproval");
  assert.equal(resourceBoundary.resourceId, ids.approval);
  assert.equal(resourceBoundary.requiredAssurance, "mfa-verified");
  assert.equal(approveNote, "reviewed");

  approvalRepositoryError = {
    code: "P2010",
    meta: { code: "42501", message: "ERROR: C03_APPROVAL_DENIED" },
  };
  await assert.rejects(
    () => service.approveSensitiveActionApproval({
      approvalId: ids.approval,
      actor,
      securityContext: { databaseSessionCapability, requestId: ids.request },
    }),
    (error) => error instanceof C03AccessError && error.statusCode === 400 && /cannot approve/i.test(error.message)
  );
  approvalRepositoryError = {
    code: "P2010",
    meta: { code: "42501", message: "ERROR: C03_SCOPE_DENIED" },
  };
  await assert.rejects(
    () => service.approveSensitiveActionApproval({
      approvalId: ids.approval,
      actor,
      securityContext: { databaseSessionCapability, requestId: ids.request },
    }),
    (error) => error instanceof C03AccessError && error.statusCode === 400 && /cannot approve/i.test(error.message)
  );
  const unrelatedDatabaseError = {
    code: "P2010",
    meta: { code: "42501", message: "ERROR: unrelated permission failure" },
  };
  approvalRepositoryError = unrelatedDatabaseError;
  await assert.rejects(
    () => service.approveSensitiveActionApproval({
      approvalId: ids.approval,
      actor,
      securityContext: { databaseSessionCapability, requestId: ids.request },
    }),
    (error) => error === unrelatedDatabaseError
  );
  approvalRepositoryError = null;

  resourceBoundary = null;
  await assert.rejects(
    () => service.approveSensitiveActionApproval({
      approvalId: ids.approval,
      actor,
      reviewNote: "x".repeat(501),
      securityContext: { databaseSessionCapability, requestId: ids.request },
    }),
    /review note is too long/
  );
  assert.equal(resourceBoundary, null, "invalid note must fail before database boundary");

  const duplicateResultTx = { $queryRaw: async () => [{ result: {} }, { result: {} }] };
  await assert.rejects(
    () => approvalRepository.createSensitiveApprovalInTransaction(duplicateResultTx, {}),
    /invalid database result/
  );
  await assert.rejects(
    () => incidentRepository.getIncidentDetailInTransaction(duplicateResultTx, ids.approval),
    /invalid database result/
  );

  console.log("C03 sensitive approval boundary tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
