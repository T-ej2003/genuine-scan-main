const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");
const sql = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicVerificationFunctions.sql"), "utf8");

assert.match(repository, /SELECT \* FROM app_public\.verify_raw_qr/);
assert.match(sql, /FROM public\."QRCode" q WHERE q\.code=p_requested_code/);
const rawFunction = sql.slice(sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_raw_qr"),
  sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_signed_qr"));
const signedFunction = sql.slice(sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_signed_qr"),
  sql.indexOf("CREATE OR REPLACE FUNCTION app_public.record_qr_verification"));
assert.doesNotMatch(rawFunction, /displayCode|serialNumber|labelSerial/);
assert.match(sql, /p_requested_code<>btrim\(p_requested_code\)/);
assert.doesNotMatch(sql, /lower\(p_requested_code\)|upper\(p_requested_code\)/);
assert.match(rawFunction, /IF qr_id IS NULL THEN[\s\S]*pg_sleep\(0\.015 \+ random\(\)\*0\.010\)/);
assert.doesNotMatch(signedFunction, /pg_sleep/);
assert(rawFunction.indexOf("length(p_requested_code)>128") < rawFunction.indexOf("pg_sleep("));

const executeFunction = sql.slice(sql.indexOf("CREATE OR REPLACE FUNCTION app_public.public_verify_execute"),
  sql.indexOf("CREATE OR REPLACE FUNCTION app_public.verify_raw_qr"));
assert.match(executeFunction, /scan_history_eligible:=classification IN \('FIRST_SCAN','LEGIT_REPEAT','SUSPICIOUS_DUPLICATE'\)/);
assert.match(executeFunction, /IF scan_history_eligible THEN[\s\S]*INSERT INTO public\."QrScanLog"[\s\S]*UPDATE public\."QRCode"/);

console.log("public verification exact immutable-code lookup contract passed");
