const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");
const sql = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicVerificationFunctions.sql"), "utf8");

assert.match(repository, /SELECT \* FROM app_public\.verify_raw_qr/);
assert.match(sql, /FROM public\."QRCode" q WHERE q\.code=p_requested_code/);
assert.doesNotMatch(sql.slice(sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_raw_qr"),
  sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_signed_qr")), /displayCode|serialNumber|labelSerial/);
assert.match(sql, /p_requested_code<>btrim\(p_requested_code\)/);
assert.doesNotMatch(sql, /lower\(p_requested_code\)|upper\(p_requested_code\)/);

console.log("public verification exact immutable-code lookup contract passed");
