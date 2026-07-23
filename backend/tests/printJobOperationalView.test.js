const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..", "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const handlers = read("backend/src/controllers/print-job/queryHandlers.ts");
const repository = read("backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts");
const sql = read("backend/src/rls-waves/session-c/c02/printingLifecycle.sql");

assert(handlers.includes("readPrintingProjection"), "print-job reads must use the capability boundary");
assert(handlers.includes('operation: "JOB"'), "detail reads must use the exact JOB projection");
assert(handlers.includes('operation: "JOB_LIST"'), "list reads must use the exact JOB_LIST projection");
assert(!handlers.includes("prisma.printJob"), "print-job handlers must not read protected jobs directly");
assert(repository.includes("app_rls.printing_readiness"), "repository must call the reviewed SQL projection");
assert(sql.includes('j."reprintOfJobId",j."approvedByUserId",j."reprintReason"'), "job-list projection must preserve replacement lineage");
assert(sql.includes('j."rangeStart",j."rangeEnd"'), "job-list projection must preserve the requested range");
assert(sql.includes("ORDER BY j.\"createdAt\" DESC,j.id DESC"), "job-list ordering must be deterministic");

console.log("print job operational boundary tests passed");
