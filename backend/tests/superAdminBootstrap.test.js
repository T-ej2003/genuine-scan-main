const assert = require("node:assert/strict");
const argon2 = require("argon2");

const { bootstrapConfiguredSuperAdmin } = require("../dist/services/auth/superAdminBootstrapService");

const reset = () => {
  delete process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED;
  delete process.env.SUPER_ADMIN_EMAIL;
  delete process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD;
};

(async () => {
  reset();
  assert.equal((await bootstrapConfiguredSuperAdmin()).status, "disabled");

  process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "true";
  process.env.SUPER_ADMIN_EMAIL = "bootstrap@example.invalid";
  process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD = "Correct horse battery staple";
  const blocked = await bootstrapConfiguredSuperAdmin();
  assert.equal(blocked.status, "blocked");
  assert.match(blocked.reason, /migration database identity/i);

  let bootstrapArguments;
  const database = (row) => ({
    $transaction: async (run) => run({
      $executeRaw: async () => 1,
      $queryRaw: async (query) => {
        bootstrapArguments = query.values;
        return [row];
      },
    }),
  });
  process.env.NODE_ENV = "production";
  const created = await bootstrapConfiguredSuperAdmin(database({
    status: "created",
    userId: "00000000-0000-4400-8000-000000000001",
    email: "bootstrap@example.invalid",
    role: "SUPER_ADMIN",
    autoVerified: true,
    reason: null,
    auditEventId: "00000000-0000-4400-8000-000000000002",
  }));
  assert.deepEqual(created, {
    status: "created",
    userId: "00000000-0000-4400-8000-000000000001",
    email: "bootstrap@example.invalid",
    autoVerified: true,
  });
  assert.equal(bootstrapArguments[0], "bootstrap@example.invalid");
  assert.notEqual(bootstrapArguments[1], process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD);
  assert.equal(await argon2.verify(bootstrapArguments[1], process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD), true);
  const duplicate = await bootstrapConfiguredSuperAdmin(database({
    status: "skipped_existing",
    userId: "00000000-0000-4400-8000-000000000001",
    email: "bootstrap@example.invalid",
    role: "SUPER_ADMIN",
    autoVerified: null,
    reason: null,
    auditEventId: "00000000-0000-4400-8000-000000000003",
  }));
  assert.equal(duplicate.status, "skipped_existing");
  console.log("super admin bootstrap fail-closed tests passed");
})().catch((error) => { console.error(error); process.exit(1); });
