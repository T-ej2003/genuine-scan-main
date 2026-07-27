const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const backend = path.resolve(__dirname,"../../..");
const read = (relative) => fs.readFileSync(path.join(backend,relative),"utf8");

const breakGlass = read("scripts/break-glass-mfa-reset.ts");
assert(breakGlass.includes("resetAccountMfaBreakGlass"));
assert(breakGlass.includes("dual-approved-break-glass"));
assert(!breakGlass.includes("prisma.user"));

const print = read("scripts/mscqr-print-test.js");
assert(print.includes("runPrintDiagnostic"));
assert(print.includes("qrPayloadsReturned: false"));
assert(!print.includes("createPrintJobRecords"));

for (const relative of ["prisma/seed.ts","scripts/seed-enterprise-e2e.ts","scripts/seed-launch-smoke-users.js","scripts/repair-admin-accounts.js"]) {
  const source=read(relative);
  assert.match(source,/prohibit/i,`${relative} must fail closed`);
  assert(!source.includes("PrismaClient"),`${relative} must refuse before constructing a database client`);
}

const enterpriseFixture=read("tests/fixtures/seedEnterpriseE2E.ts");
assert(enterpriseFixture.includes("assertSafeTestDatabaseUrl(seedDatabaseUrl)"));
assert(enterpriseFixture.includes("E2E_SEED_DATABASE_URL"));
assert(enterpriseFixture.includes("UserRole.MANUFACTURER_ADMIN"));
assert(!enterpriseFixture.includes("process.env.DATABASE_URL"));

const qualityGate=read("../.github/workflows/quality-gate.yml");
assert(qualityGate.includes("image: postgres:18.4"));
assert(qualityGate.includes("node scripts/enterprise-e2e-db.mjs prepare"));
assert(qualityGate.includes("node scripts/enterprise-e2e-db.mjs cleanup"));
console.log("operator and CLI shared-boundary tests passed");
