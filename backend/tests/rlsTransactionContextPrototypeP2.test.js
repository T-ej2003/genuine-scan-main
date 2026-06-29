const assert = require("node:assert/strict");
const { PrismaClient } = require("@prisma/client");
const { withRlsPrototypeTransaction } = require("../dist/lib/rlsTransactionContextPrototype");

const {
  P2TestDbSkip,
  dropP2TestDatabase,
  resolveP2TestDatabase,
} = require("./helpers/p2TestDb");

const command = "MSCQR_RLS_CONTEXT_PROTOTYPE_TEST=true npm --prefix backend run test:rls:context-prototype";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_RLS_CONTEXT_PROTOTYPE_TEST) && !isTruthy(process.env.MSCQR_RLS_PROTOTYPE_TEST)) {
  console.log(`RLS transaction-context prototype P2 test skipped. Run with: ${command}`);
  process.exit(0);
}

const readContext = async (client) => {
  const rows = await client.$queryRaw`
    SELECT
      current_setting('app.user_id', true) AS user_id,
      current_setting('app.role', true) AS role,
      current_setting('app.licensee_id', true) AS licensee_id,
      current_setting('app.manufacturer_id', true) AS manufacturer_id,
      current_setting('app.organization_id', true) AS organization_id,
      current_setting('app.is_platform_admin', true) AS is_platform_admin
  `;
  return rows[0];
};

const expectClearedContext = async (client, message) => {
  const context = await readContext(client);
  assert.notEqual(context.user_id, "user-a", `${message}: app.user_id leaked`);
  assert.notEqual(context.role, "LICENSEE_ADMIN", `${message}: app.role leaked`);
  assert.notEqual(context.licensee_id, "licensee-a", `${message}: app.licensee_id leaked`);
  assert.notEqual(context.manufacturer_id, "manufacturer-a", `${message}: app.manufacturer_id leaked`);
  assert.notEqual(context.organization_id, "org-a", `${message}: app.organization_id leaked`);
  assert.notEqual(context.is_platform_admin, "true", `${message}: app.is_platform_admin leaked`);
};

const main = async () => {
  let databaseInfo = null;
  let prisma = null;

  process.env.NODE_ENV = "test";

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    prisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });

    await expectClearedContext(prisma, "before transaction");

    await withRlsPrototypeTransaction(
      prisma,
      {
        userId: "user-a",
        role: "LICENSEE_ADMIN",
        licenseeId: "licensee-a",
        manufacturerId: "manufacturer-a",
        organizationId: "org-a",
      },
      async (tx) => {
        const context = await readContext(tx);
        assert.equal(context.user_id, "user-a", "context should exist inside transaction");
        assert.equal(context.role, "LICENSEE_ADMIN", "role should exist inside transaction");
        assert.equal(context.licensee_id, "licensee-a", "licensee context should exist inside transaction");
        assert.equal(context.manufacturer_id, "manufacturer-a", "manufacturer context should exist inside transaction");
        assert.equal(context.organization_id, "org-a", "organization context should exist inside transaction");
        assert.equal(context.is_platform_admin, "false", "platform admin must default to false");
      }
    );

    await expectClearedContext(prisma, "after transaction");

    await withRlsPrototypeTransaction(
      prisma,
      {
        userId: "user-b",
        role: "MANUFACTURER",
        manufacturerId: "manufacturer-b",
      },
      async (tx) => {
        const context = await readContext(tx);
        assert.equal(context.user_id, "user-b", "second transaction should get its own user context");
        assert.equal(context.role, "MANUFACTURER", "second transaction should get its own role");
        assert.equal(context.licensee_id, "", "licensee context should be reset when omitted");
        assert.equal(context.manufacturer_id, "manufacturer-b", "second transaction should get its own manufacturer");
        assert.equal(context.organization_id, "", "organization context should be reset when omitted");
        assert.equal(context.is_platform_admin, "false", "second transaction must not inherit platform admin");
      }
    );

    await withRlsPrototypeTransaction(
      prisma,
      {
        userId: "platform-admin",
        role: "SUPER_ADMIN",
      },
      async (tx) => {
        const context = await readContext(tx);
        assert.equal(context.is_platform_admin, "false", "platform admin context must be explicit");
      }
    );

    await withRlsPrototypeTransaction(
      prisma,
      {
        userId: "platform-admin",
        role: "SUPER_ADMIN",
        isPlatformAdmin: true,
      },
      async (tx) => {
        const context = await readContext(tx);
        assert.equal(context.is_platform_admin, "true", "explicit platform admin context should be visible");
      }
    );

    await expectClearedContext(prisma, "after explicit platform admin transaction");

    await withRlsPrototypeTransaction(
      prisma,
      {
        role: "public_verification",
      },
      async (tx) => {
        const context = await readContext(tx);
        assert.equal(context.role, "public_verification", "public verification role should be explicit");
        assert.equal(context.is_platform_admin, "false", "public verification must not become platform admin by default");
      }
    );

    await assert.rejects(
      () =>
        withRlsPrototypeTransaction(
          prisma,
          {
            role: "public_verification",
            isPlatformAdmin: true,
          },
          async () => {}
        ),
      /public_verification context cannot be platform admin/
    );

    await expectClearedContext(prisma, "after rejected public verification context");

    console.log("RLS transaction-context prototype P2 tests passed");
  } catch (error) {
    if (error instanceof P2TestDbSkip && !isTruthy(process.env.P2_TEST_DATABASE_REQUIRED)) {
      console.log(`RLS transaction-context prototype P2 test skipped: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    if (prisma?.$disconnect) await prisma.$disconnect().catch(() => {});
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
