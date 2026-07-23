const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

const createdQuantities = [];
mockModule("config/database.js", {
  __esModule: true,
  default: {
    qrAllocationRequest: {
      create: async ({ data }) => {
        createdQuantities.push(data.quantity);
        return { id: `request-${data.quantity}`, ...data };
      },
    },
  },
});
mockModule("services/auditService.js", { createAuditLog: async () => null });
mockModule("services/notificationService.js", {
  createRoleNotifications: async () => null,
  createUserNotification: async () => null,
});
mockModule("rls-waves/session-c/c01/qrSystemRepository.js", { approveAllocationRequest: async () => ({}) });

const response = () => ({
  statusCode: 200,
  body: null,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

(async () => {
  const { createQrAllocationRequest } = require("../dist/controllers/qrRequestController");
  const request = (quantity) => ({
    user: { userId: "licensee-admin", role: UserRole.LICENSEE_ADMIN, licenseeId: "licensee-a" },
    body: { quantity, batchName: "Release request" },
    ip: "127.0.0.1",
  });

  for (const quantity of [199_999, 200_000]) {
    const res = response();
    await createQrAllocationRequest(request(quantity), res);
    assert.equal(res.statusCode, 201, `${quantity} must remain creatable and approvable`);
  }
  for (const quantity of [200_001, 5_000_000]) {
    const res = response();
    await createQrAllocationRequest(request(quantity), res);
    assert.equal(res.statusCode, 400, `${quantity} must be rejected before an unapprovable request is persisted`);
  }
  assert.deepEqual(createdQuantities, [199_999, 200_000]);

  const sql = fs.readFileSync(path.resolve(__dirname, "../src/rls-waves/session-c/c01/qrSystem.sql"), "utf8");
  const ui = fs.readFileSync(path.resolve(__dirname, "../../src/pages/QRRequests.tsx"), "utf8");
  assert.match(sql, /requested_quantity NOT BETWEEN 1 AND 200000/);
  assert.match(ui, /quantity > 200_000/);
  assert.match(ui, /max=\{200000\}/);
  console.log("QR allocation creation and approval limits are aligned");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
