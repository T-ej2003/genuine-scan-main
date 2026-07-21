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
console.log("operator and CLI shared-boundary tests passed");
