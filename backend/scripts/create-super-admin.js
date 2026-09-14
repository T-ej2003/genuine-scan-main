const { PrismaClient } = require("@prisma/client");
const { bootstrapConfiguredSuperAdmin } = require("../dist/services/auth/superAdminBootstrapService");

async function main() {
  const databaseUrl = String(process.env.SUPER_ADMIN_BOOTSTRAP_DATABASE_URL || "").trim();
  if (!databaseUrl) throw new Error("SUPER_ADMIN_BOOTSTRAP_DATABASE_URL is required.");
  if (!String(process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD || "")) {
    throw new Error("SUPER_ADMIN_BOOTSTRAP_PASSWORD is required.");
  }
  process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "true";
  const migration = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  try {
    const result = await bootstrapConfiguredSuperAdmin(migration);
    if (result.status !== "created") {
      throw new Error("Configured super-admin bootstrap was rejected.");
    }
    console.log(JSON.stringify({ status: result.status, email: result.email, role: "SUPER_ADMIN" }));
  } finally {
    await migration.$disconnect();
  }
}

main()
  .catch(() => {
    console.error("Create super admin failed.");
    process.exit(1);
  });
