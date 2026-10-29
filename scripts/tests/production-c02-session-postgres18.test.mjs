import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { buildC02SessionPrerequisitePackage } from "../aws/production-c02-session-package.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const requireBackend = createRequire(new URL("../../backend/package.json", import.meta.url));
const { PrismaClient } = requireBackend("@prisma/client");
const { executeC02SessionInstallTransaction, installed, readback } =
  createRequire(import.meta.url)("../aws/production-c02-session-executor.cjs");
const { assertPrintingSessionPrerequisite } =
  requireBackend("./dist/rls-waves/session-c/c02/printingSessionPrerequisite");

const raw = process.env.MSCQR_C02_TEST_URL;
assert.ok(raw, "An explicit disposable PostgreSQL 18 URL is required");
const target = new URL(raw);
assert.ok(["127.0.0.1", "localhost", "::1"].includes(target.hostname));
assert.match(target.pathname, /^\/mscqr_pr771_c02_local$/);
assert.equal(target.username, "mscqr_rls_cert_admin");
assert.equal(target.password, "");
const rolePrefix = "mscqr_rls_cert_";
const pkg = buildC02SessionPrerequisitePackage({ sourceSha: "a".repeat(40), repositoryRoot: root, rolePrefix });
const contract = { admin: "mscqr_rls_cert_admin", database: "mscqr_pr771_c02_local",
  schemaOwner: "mscqr_rls_cert_owner", authOwner: "mscqr_rls_cert_auth_owner", appRole: "mscqr_rls_cert_app",
  allowSuperuser: true };
const admin = new PrismaClient({ datasources: { db: { url: target.toString() } } });
const appUrl = new URL(target); appUrl.username = contract.appRole;
const app = new PrismaClient({ datasources: { db: { url: appUrl.toString() } } });

try {
  const initial = await readback(admin, pkg, contract);
  assert.equal(initial.migration_ready, true);
  assert.equal(initial.force_rls, true);
  assert.equal(initial.function_body_sha256, null);
  assert.equal(initial.policy_count, 0);
  assert.deepEqual(initial.grants, []);
  await assert.rejects(assertPrintingSessionPrerequisite(app, rolePrefix), /PRINTING_SESSION_PREREQUISITE_MISSING/);

  await assert.rejects(admin.$transaction((tx) => executeC02SessionInstallTransaction({ tx, pkg, contract,
    checkpoint: async (stage) => { if (stage === "temporary-schema-grant") throw new Error("injected interruption"); } })),
  /injected interruption/);
  assert.equal((await readback(admin, pkg, contract)).function_body_sha256, null,
    "An interrupted C02 transaction must leave no function behind");

  const applied = await admin.$transaction((tx) => executeC02SessionInstallTransaction({ tx, pkg, contract }),
    { maxWait: 10000, timeout: 120000 });
  assert.equal(applied.status, "APPLIED");
  assert.ok(installed(await readback(admin, pkg, contract), pkg));
  await assertPrintingSessionPrerequisite(app, rolePrefix);
  const repeated = await admin.$transaction((tx) => executeC02SessionInstallTransaction({ tx, pkg, contract }));
  assert.equal(repeated.status, "ALREADY_CONVERGED");

  await assert.rejects(app.$executeRawUnsafe(`UPDATE public."PrinterAgentSession" SET "lastMessageSeq"=1 WHERE false`));
  await assert.rejects(app.$executeRawUnsafe(`INSERT INTO public."PrinterAgentSession"(id) VALUES ('not-authorized')`));

  await assert.rejects(admin.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_rls_cert_owner");
    await tx.$executeRawUnsafe('REVOKE UPDATE ("lastMessageSeq") ON public."PrinterAgentSession" FROM mscqr_rls_cert_auth_owner');
    await tx.$executeRawUnsafe("RESET ROLE");
    await assert.rejects(assertPrintingSessionPrerequisite(tx, rolePrefix), /PRINTING_SESSION_PREREQUISITE_MISSING/);
    throw new Error("rollback grant probe");
  }), /rollback grant probe/);
  await assertPrintingSessionPrerequisite(app, rolePrefix);
  console.log("C02 session prerequisite PostgreSQL 18 installation and restricted-role readback passed");
} finally {
  await app.$disconnect();
  await admin.$disconnect();
}
