const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFile, spawnSync } = require("node:child_process");
const { promisify } = require("node:util");

const execute = promisify(execFile);
const enabled = process.env.MSCQR_SCHEDULED_IDENTITY_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_SCHEDULED_IDENTITY_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_SCHEDULED_IDENTITY_POSTGRES18_TEST";
const ids = {
  credential: "00000000-0000-4000-8000-000000003001",
  rotated: "00000000-0000-4000-8000-000000003002",
  expired: "00000000-0000-4000-8000-000000003003",
};
const schedule = "daily-compliance-cert";
const request = (suffix) => `00000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;

const connection = (raw) => {
  const parsed = new URL(String(raw || ""));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert(!/(staging|prod|amazonaws|rds)/i.test(raw));
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  return { url: parsed.toString(), password };
};
const psql = (url, sql, expectFailure = false) => {
  const target = connection(url);
  const result = spawnSync("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password || process.env.PGPASSWORD || "" },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) { assert.notEqual(result.status, 0, "denial probe unexpectedly succeeded"); return output; }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};
const concurrent = async (url, sql) => {
  const target = connection(url);
  const run = () => execute("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password || process.env.PGPASSWORD || "" },
  }).then(({ stdout }) => stdout.trim()).catch((error) => `${error.stdout || ""}${error.stderr || ""}${error.message || ""}`.trim());
  return Promise.all([run(), run()]);
};

async function main() {
  if (!enabled) return console.log("scheduled-job identity PostgreSQL 18 proof skipped");
  assert(confirmed, "scheduled-job identity PostgreSQL 18 proof confirmation is required");
  const bootstrap = process.env.MSCQR_SCHEDULED_IDENTITY_BOOTSTRAP_URL;
  const operator = process.env.MSCQR_SCHEDULED_IDENTITY_OPERATOR_URL;
  const scheduled = process.env.MSCQR_SCHEDULED_IDENTITY_RUNTIME_URL;
  const app = process.env.MSCQR_SCHEDULED_IDENTITY_APP_URL;
  for (const url of [bootstrap, operator, scheduled, app]) connection(url);
  assert.equal(Number(psql(bootstrap, "select current_setting('server_version_num')::int / 10000")), 18);

  const capability = crypto.randomBytes(32).toString("base64url");
  const capabilityHash = crypto.createHash("sha256").update(capability).digest("hex");
  const rotatedCapability = crypto.randomBytes(32).toString("base64url");
  const rotatedHash = crypto.createHash("sha256").update(rotatedCapability).digest("hex");

  assert.match(psql(scheduled, 'SELECT id FROM public."ScheduledJobCredential"', true), /permission denied/i);
  assert.match(psql(scheduled, 'INSERT INTO public."ScheduledJobCredential" (id,"identityName","jobFamily","scheduleId","capabilityHash","expiresAt","updatedAt") VALUES (\'x\',\'identity-scheduled-job\',\'compliance-pack\',\'x\',repeat(\'a\',64),transaction_timestamp()+interval \'1 day\',transaction_timestamp())', true), /permission denied/i);
  assert.match(psql(scheduled, 'UPDATE public."CompliancePackJob" SET status=status', true), /permission denied/i);
  assert.match(psql(scheduled, "SELECT app_rls.scheduled_job_prepare('" + capability + "','" + schedule + "','claim','" + request(1) + "')", true), /permission denied/i);
  assert.match(psql(scheduled, "SELECT app_rls.install_actor_context('00000000-0000-4000-8000-000000000301','PLATFORM_SUPER_ADMIN','','','','system-verified','x','x')", true), /permission denied/i);
  assert.match(psql(app, `SELECT * FROM app_rls.claim_compliance_pack_slice('${capability}','${schedule}',transaction_timestamp()::timestamp,1)`, true), /permission denied|SCHEDULED_JOB_IDENTITY_DENIED/i);

  const catalog = JSON.parse(psql(bootstrap, `SELECT json_build_object(
    'ownerLogin',(SELECT rolcanlogin FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerBypass',(SELECT rolbypassrls FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname='mscqr_rls_cert_auth_owner' AND c.relkind IN ('r','p')),
    'credentialForce',(SELECT relforcerowsecurity FROM pg_class WHERE oid='public."ScheduledJobCredential"'::regclass),
    'publicExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname LIKE '%scheduled%' AND has_function_privilege('public',p.oid,'EXECUTE')),
    'scheduledExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND has_function_privilege('mscqr_rls_cert_scheduled',p.oid,'EXECUTE')),
    'operatorExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND has_function_privilege('mscqr_rls_cert_operator',p.oid,'EXECUTE'))
  )`));
  assert.deepEqual(catalog, { ownerLogin: false, ownerBypass: false, ownerTables: 0, credentialForce: true, publicExecute: 0, scheduledExecute: 4, operatorExecute: 2 });

  assert.equal(psql(operator, `SELECT app_rls.provision_scheduled_job_credential('${ids.credential}','${schedule}','${capabilityHash}',transaction_timestamp()+interval '1 day',NULL,'${request(2)}')`), ids.credential);
  assert.equal(psql(bootstrap, `SELECT ("capabilityHash"='${capabilityHash}')::text||':'||(to_jsonb(c)::text LIKE '%${capability}%')::text FROM public."ScheduledJobCredential" c WHERE id='${ids.credential}'`), "true:false");
  assert.match(psql(scheduled, `SELECT * FROM app_rls.claim_compliance_pack_slice('bad','${schedule}',transaction_timestamp()::timestamp,1)`, true), /SCHEDULED_JOB_IDENTITY_DENIED/i);
  assert.match(psql(scheduled, `BEGIN; SELECT set_config('app.scheduled_verified','1',true),set_config('app.scheduled_credential_id','${ids.credential}',true),set_config('app.scheduled_capability_hash','${capabilityHash}',true); SELECT id FROM public."Licensee"; ROLLBACK`, true), /permission denied/i);

  const beforeRollback = JSON.parse(psql(bootstrap, `SELECT json_build_object('jobs',(SELECT count(*) FROM public."CompliancePackJob" WHERE "triggerType"='SCHEDULED'),'keys',(SELECT count(*) FROM public."ActionIdempotencyKey" WHERE action='scheduled-compliance-pack'),'outbox',(SELECT count(*) FROM public."AuditLogOutbox" WHERE payload->'details'->>'systemIdentity'='identity-scheduled-job'))`));
  psql(scheduled, `BEGIN; SELECT count(*) FROM app_rls.claim_compliance_pack_slice('${capability}','${schedule}',transaction_timestamp()::timestamp,1); ROLLBACK`);
  const afterRollback = JSON.parse(psql(bootstrap, `SELECT json_build_object('jobs',(SELECT count(*) FROM public."CompliancePackJob" WHERE "triggerType"='SCHEDULED'),'keys',(SELECT count(*) FROM public."ActionIdempotencyKey" WHERE action='scheduled-compliance-pack'),'outbox',(SELECT count(*) FROM public."AuditLogOutbox" WHERE payload->'details'->>'systemIdentity'='identity-scheduled-job'))`));
  assert.deepEqual(afterRollback, beforeRollback);

  const race = await concurrent(scheduled, `SELECT count(*) FROM app_rls.claim_compliance_pack_slice('${capability}','${schedule}',transaction_timestamp()::timestamp,1)`);
  assert.deepEqual(race.map(Number).sort((a, b) => a - b), [0, 1]);
  const jobId = psql(bootstrap, `SELECT id FROM public."CompliancePackJob" WHERE "triggerType"='SCHEDULED' ORDER BY "createdAt" DESC LIMIT 1`);
  assert(jobId);
  assert.equal(psql(scheduled, `SELECT (app_rls.scheduled_get_compliance_pack_job('${capability}','${schedule}','${request(3)}','${jobId}')->'job'->>'id')`), jobId);

  const result = JSON.stringify({ fileName: "scheduled.zip", storageKey: "private/scheduled.zip", integrityHash: "a".repeat(64), signatureAlgorithm: "hmac-sha256" }).replaceAll("'", "''");
  const terminalRace = await concurrent(scheduled, `SELECT app_rls.scheduled_complete_compliance_pack_job('${capability}','${schedule}','${request(4)}','${jobId}','${result}'::jsonb)->>'status'`);
  assert.equal(terminalRace.filter((entry) => entry === "COMPLETED").length, 1, JSON.stringify(terminalRace));
  assert(terminalRace.some((entry) => /SCHEDULED_COMPLIANCE_TRANSITION_DENIED/.test(entry)));
  assert.equal(psql(bootstrap, `SELECT "storageKey" FROM public."CompliancePackJob" WHERE id='${jobId}'`), "private/scheduled.zip");

  assert.equal(psql(operator, `SELECT app_rls.provision_scheduled_job_credential('${ids.rotated}','${schedule}','${rotatedHash}',transaction_timestamp()+interval '1 day','${ids.credential}','${request(5)}')`), ids.rotated);
  assert.match(psql(scheduled, `SELECT * FROM app_rls.claim_compliance_pack_slice('${capability}','${schedule}',transaction_timestamp()::timestamp,1)`, true), /SCHEDULED_JOB_IDENTITY_DENIED/i);
  assert.equal(psql(operator, `SELECT app_rls.revoke_scheduled_job_credential('${ids.rotated}','OPERATOR_REVOKED','${request(6)}')`), "t");
  assert.match(psql(scheduled, `SELECT * FROM app_rls.claim_compliance_pack_slice('${rotatedCapability}','${schedule}',transaction_timestamp()::timestamp,1)`, true), /SCHEDULED_JOB_IDENTITY_DENIED/i);

  psql(bootstrap, `INSERT INTO public."ScheduledJobCredential" (id,"identityName","jobFamily","scheduleId","capabilityHash","capabilityHashVersion","expiresAt","revokedAt","revokedReason","updatedAt") VALUES ('${ids.expired}','identity-scheduled-job','compliance-pack','expired-cert','${"e".repeat(64)}','sha256-v1',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp())`);
  const expiredCapability = crypto.randomBytes(32).toString("base64url");
  psql(bootstrap, `UPDATE public."ScheduledJobCredential" SET "capabilityHash"='${crypto.createHash("sha256").update(expiredCapability).digest("hex")}' WHERE id='${ids.expired}'`);
  assert.match(psql(scheduled, `SELECT * FROM app_rls.claim_compliance_pack_slice('${expiredCapability}','expired-cert',transaction_timestamp()::timestamp,1)`, true), /SCHEDULED_JOB_IDENTITY_DENIED/i);

  assert.equal(psql(scheduled, `BEGIN; SELECT set_config('app.scheduled_verified','forged',true); ROLLBACK; SELECT 'after:'||coalesce(current_setting('app.scheduled_verified',true),'')`), "after:");
  console.log("scheduled-job identity application-path proof passed");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
