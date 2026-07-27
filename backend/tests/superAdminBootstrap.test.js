const assert = require("node:assert/strict");

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
  console.log("super admin bootstrap fail-closed tests passed");
})().catch((error) => { console.error(error); process.exit(1); });
