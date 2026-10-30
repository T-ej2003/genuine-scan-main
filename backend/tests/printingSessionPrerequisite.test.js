const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { assertPrintingSessionPrerequisite, printingSessionPrerequisiteSql } = require("../dist/rls-waves/session-c/c02/printingSessionPrerequisite");

const ready = { migrationReady: true, functionReady: true, rlsReady: true, policiesReady: true, grantsReady: true };
const run = async () => {
  let reads = 0;
  const database = { $queryRawUnsafe: async (sql) => {
    reads++;
    assert.match(sql, /pg_catalog\.pg_policy/);
    assert.match(sql, /relforcerowsecurity/);
    assert.match(sql, /lastMessageSeq/);
    return [ready];
  } };
  await assertPrintingSessionPrerequisite(database);
  assert.equal(reads, 1);
  for (const name of Object.keys(ready)) {
    await assert.rejects(assertPrintingSessionPrerequisite({ $queryRawUnsafe: async () => [{ ...ready, [name]: false }] }),
      /PRINTING_SESSION_PREREQUISITE_MISSING/, `${name} must block activation`);
  }
  await assert.rejects(assertPrintingSessionPrerequisite({ $queryRawUnsafe: async () => [] }),
    /PRINTING_SESSION_PREREQUISITE_READBACK_INVALID/);
  assert.throws(() => printingSessionPrerequisiteSql("untrusted_"), /ROLE_INVALID/);
  const source = fs.readFileSync(path.resolve(__dirname, "../../scripts/rls/sql/generated/20-context-helpers.sql"), "utf8");
  const start = source.indexOf("CREATE OR REPLACE FUNCTION app_rls.printing_connector_session(");
  const bodyStart = source.indexOf("AS $fn$", start) + 7;
  const bodyEnd = source.indexOf("$fn$;", bodyStart);
  assert(start >= 0 && bodyStart > start && bodyEnd > bodyStart);
  const body = source.slice(bodyStart, bodyEnd);
  const digest = (value) => createHash("sha256").update(value).digest("hex");
  assert.match(printingSessionPrerequisiteSql("mscqr_rls_cert_"), new RegExp(digest(body)));
  assert.match(printingSessionPrerequisiteSql(), new RegExp(digest(body.replaceAll("mscqr_rls_cert_app", "mscqr_prd_rls_phase2_app"))));
  const startup = fs.readFileSync(path.resolve(__dirname, "../src/index.ts"), "utf8");
  const preflight = startup.indexOf("await assertPrintingSessionPrerequisite(prisma)");
  const listener = startup.indexOf("server = app.listen(PORT");
  assert(preflight > 0 && listener > preflight, "C02 readback must complete before backend activation");
  console.log("printing session prerequisite tests passed");
};
run().catch((error) => { console.error(error); process.exitCode = 1; });
