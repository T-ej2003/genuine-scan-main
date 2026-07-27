const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";
const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};
const response = () => ({
  statusCode: 200, body: null,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

(async () => {
  const calls = [];
  const denied = Object.assign(new Error("TENANT_DIRECTORY_DENIED"), { code: "42501" });
  let reject = false;
  mockModule("rls-waves/session-a/tenantDirectoryRepository.js", {
    isTenantDirectoryDenied: (error) => error === denied,
    readLicenseeDirectory: async (input) => {
      calls.push(["licensees", input]);
      if (reject) throw denied;
      return input.detail ? { id: input.requestedLicenseeId } : [{ id: "licensee-a" }];
    },
    readUserDirectory: async (input) => {
      calls.push(["users", input]);
      if (reject) throw denied;
      return { users: [{ id: "user-a", role: UserRole.MANUFACTURER_ADMIN }], total: 1 };
    },
  });

  const { getLicensee, getLicensees } = require("../dist/controllers/licenseeController");
  const { getUsers } = require("../dist/controllers/userController");
  const base = { databaseSessionCapability: "c".repeat(43), requestId: "directory-request", query: {}, params: {}, body: {} };

  const listRes = response();
  await getLicensees({ ...base, user: { role: UserRole.SUPER_ADMIN, userId: "platform" } }, listRes);
  assert.deepStrictEqual(listRes.body, { success: true, data: [{ id: "licensee-a" }] });

  const id = "00000000-0000-4000-8000-0000000000aa";
  const detailRes = response();
  await getLicensee({ ...base, params: { id }, user: { role: UserRole.LICENSEE_ADMIN, userId: "admin" } }, detailRes);
  assert.deepStrictEqual(detailRes.body, { success: true, data: { id } });

  const usersRes = response();
  await getUsers({ ...base, query: { licenseeId: id, role: "MANUFACTURER_ADMIN", limit: "20", offset: "2" }, user: { role: UserRole.MANUFACTURER_ADMIN, userId: "maker" } }, usersRes);
  assert.deepStrictEqual(usersRes.body, { success: true, data: [{ id: "user-a", role: UserRole.MANUFACTURER_ADMIN }], meta: { total: 1, limit: 20, offset: 2 } });
  assert.strictEqual(calls.at(-1)[1].roleFilter, UserRole.MANUFACTURER_ADMIN);

  const legacyFilterRes = response();
  await getUsers({ ...base, query: { licenseeId: id, role: "MANUFACTURER" }, user: { role: UserRole.LICENSEE_ADMIN, userId: "admin" } }, legacyFilterRes);
  assert.strictEqual(legacyFilterRes.statusCode, 200);
  assert.strictEqual(calls.at(-1)[1].roleFilter, UserRole.MANUFACTURER_ADMIN);
  assert.deepStrictEqual(legacyFilterRes.body.data, [{ id: "user-a", role: UserRole.MANUFACTURER_ADMIN }]);
  assert.strictEqual(calls.length, 4);
  assert.ok(calls.every(([, input]) => input.capability === "c".repeat(43) && input.requestId === "directory-request"));

  reject = true;
  const deniedRes = response();
  await getUsers({ ...base, user: { role: UserRole.LICENSEE_ADMIN, userId: "admin" } }, deniedRes);
  assert.strictEqual(deniedRes.statusCode, 404);

  const { requireTenantDirectoryReader } = require("../dist/middleware/rbac");
  for (const role of [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.MANUFACTURER_ADMIN]) {
    let called = false;
    requireTenantDirectoryReader({ user: { role } }, response(), () => { called = true; });
    assert.strictEqual(called, true, `${role} must be admitted`);
  }
  for (const role of [UserRole.ORG_ADMIN, UserRole.MANUFACTURER, UserRole.MANUFACTURER_USER]) {
    const res = response();
    requireTenantDirectoryReader({ user: { role } }, res, () => assert.fail(`${role} must be denied`));
    assert.strictEqual(res.statusCode, 403);
  }
  console.log("Tenant directory controller tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
