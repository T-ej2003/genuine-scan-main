const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_C03_AUTHENTICATED_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_C03_AUTHENTICATED_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_C03_AUTHENTICATED_POSTGRES18_TEST";

const ids = {
  orgA: "00000000-0000-4000-8000-000000000101",
  licenseeA: "00000000-0000-4000-8000-000000000201",
  adminA: "00000000-0000-4000-8000-000000000301",
  refresh: "00000000-0000-4000-8000-000000001501",
  evidenceA: "00000000-0000-4000-8000-000000001601",
  evidenceB: "00000000-0000-4000-8000-000000001602",
  incidentA: "00000000-0000-4000-8000-000000000701",
  incidentB: "00000000-0000-4000-8000-000000000702",
};

const runPsql = (url, sql, expectFailure = false) => {
  const parsed = new URL(url);
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  const result = spawnSync("psql", [parsed.toString(), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8",
    env: { ...process.env, PGPASSWORD: password || process.env.PGPASSWORD || "" },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) {
    assert.notEqual(result.status, 0, "denial probe unexpectedly succeeded");
    return output;
  }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};

async function main() {
  if (!enabled) return console.log("C03 authenticated PostgreSQL 18 proof skipped");
  assert(confirmed, "C03 authenticated PostgreSQL 18 proof confirmation is required");
  const appUrl = process.env.DATABASE_URL;
  const bootstrapUrl = process.env.MSCQR_C03_BOOTSTRAP_URL;
  const preauthUrl = process.env.MSCQR_C03_PREAUTH_URL;
  for (const url of [appUrl, bootstrapUrl, preauthUrl]) {
    const parsed = new URL(String(url || ""));
    assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
    assert(!/(staging|prod|amazonaws|rds)/i.test(url));
  }
  assert.equal(Number(runPsql(bootstrapUrl, "select current_setting('server_version_num')::int / 10000")), 18);

  const capability = crypto.randomBytes(32).toString("base64url");
  const refreshHash = crypto.createHash("sha256").update("c03-authenticated-cert-refresh").digest("hex");
  runPsql(bootstrapUrl, `
    INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt")
    VALUES ('${ids.refresh}','${ids.orgA}','${ids.adminA}','${refreshHash}',transaction_timestamp()+interval '1 day',transaction_timestamp(),transaction_timestamp());
    INSERT INTO public."IncidentEvidence" (id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy") VALUES
      ('${ids.evidenceA}','${ids.incidentA}','s3://private/a','c03-private-a','application/pdf','${ids.adminA}','ADMIN'),
      ('${ids.evidenceB}','${ids.incidentB}','s3://private/b','c03-private-b','application/pdf',NULL,'ADMIN');
  `);
  runPsql(preauthUrl, `SELECT * FROM app_auth.issue_authenticated_session_capability('${ids.refresh}','${refreshHash}','${capability}','ADMIN_MFA',(transaction_timestamp()+interval '12 hours')::timestamp)`);

  process.env.NODE_ENV = "test";
  const prismaModule = require("../../../dist/config/database");
  const prisma = prismaModule.default || prismaModule;
  const { withC03ActorTransaction, withC03ResourceTransaction } = require("../../../dist/rls-waves/session-c/c03/c03ActorBoundary");
  const repository = require("../../../dist/rls-waves/session-c/c03/c03CompliancePackRepository");
  const { loadIncidentEvidenceFileInTransaction } = require("../../../dist/rls-waves/session-c/c03/c03IncidentRepository");
  let requestSequence = 0;
  const requestId = (label) => `c03-cert-${label}-${++requestSequence}`;
  const actorBoundary = (purpose, request = requestId(purpose)) => ({
    databaseSessionCapability: capability,
    requestId: request,
    purpose,
    licenseeId: ids.licenseeA,
    allowedRoles: ["LICENSEE_ADMIN", "PLATFORM_SUPER_ADMIN"],
    requiredAssurance: "mfa-verified",
  });
  const resourceBoundary = (purpose, resourceId, resourceType = "compliancePackJob") => ({
    databaseSessionCapability: capability,
    requestId: requestId(purpose),
    purpose,
    resourceId,
    resourceType,
    allowedRoles: ["LICENSEE_ADMIN", "PLATFORM_SUPER_ADMIN"],
    requiredAssurance: "mfa-verified",
  });
  const result = (suffix) => ({
    fileName: `pack-${suffix}.zip`, storageKey: `private/${suffix}.zip`, integrityHash: crypto.createHash("sha256").update(suffix).digest("hex"),
    signatureAlgorithm: "hmac-sha256", controls: 4, generatedAt: new Date().toISOString(), storageMode: "object-storage",
  });
  const start = (request = requestId("start")) => withC03ActorTransaction(actorBoundary("compliance-pack-start", request),
    (tx, authority) => repository.startCompliancePackJobInTransaction(tx, authority, { triggerType: "MANUAL", from: null, to: null }));

  await assert.rejects(prisma.$queryRawUnsafe('SELECT id FROM public."CompliancePackJob" LIMIT 1'), /permission denied/i);
  await assert.rejects(prisma.$executeRawUnsafe('UPDATE public."CompliancePackJob" SET status=status'), /permission denied/i);
  assert.match(runPsql(appUrl, "SELECT app_rls.install_actor_context('00000000-0000-4000-8000-000000000301','LICENSEE_ADMIN','00000000-0000-4000-8000-000000000101','00000000-0000-4000-8000-000000000201','','mfa-verified','forged','compliance-pack-start')", true), /permission denied/i);
  assert.match(runPsql(appUrl, "BEGIN; SELECT set_config('app.user_id','00000000-0000-4000-8000-000000000301',true),set_config('app.role','PLATFORM_SUPER_ADMIN',true),set_config('app.c03_operation','compliance-pack-start',true); SELECT count(*) FROM public.\"CompliancePackJob\"; ROLLBACK", true), /permission denied/i);

  const idempotencyRequest = requestId("idempotent");
  const started = await start(idempotencyRequest);
  const replay = await start(idempotencyRequest);
  assert.equal(replay.job.id, started.job.id);
  const loaded = await withC03ResourceTransaction(resourceBoundary("compliance-pack-download", started.job.id),
    (tx, authority) => repository.loadCompliancePackJobInTransaction(tx, authority, started.job.id));
  assert.equal(loaded.job.id, started.job.id);
  const completed = await withC03ResourceTransaction(resourceBoundary("compliance-pack-complete", started.job.id),
    (tx, authority) => repository.completeCompliancePackJobInTransaction(tx, authority, started.job.id, result("complete")));
  assert.equal(completed.status, "COMPLETED");
  await assert.rejects(withC03ResourceTransaction(resourceBoundary("compliance-pack-fail", started.job.id),
    (tx, authority) => repository.failCompliancePackJobInTransaction(tx, authority, started.job.id, "LATE_FAILURE")), /C03_COMPLIANCE_TRANSITION_DENIED/);
  const rebuilt = await withC03ResourceTransaction(resourceBoundary("compliance-pack-rebuild-complete", started.job.id),
    (tx, authority) => repository.completeCompliancePackRebuildInTransaction(tx, authority, started.job.id, result("rebuild")));
  assert.equal(rebuilt.storageKey, "private/rebuild.zip");

  const failedJob = await start();
  const failed = await withC03ResourceTransaction(resourceBoundary("compliance-pack-fail", failedJob.job.id),
    (tx, authority) => repository.failCompliancePackJobInTransaction(tx, authority, failedJob.job.id, "BUILD_FAILED"));
  assert.equal(failed.status, "FAILED");
  await assert.rejects(withC03ResourceTransaction(resourceBoundary("compliance-pack-complete", failedJob.job.id),
    (tx, authority) => repository.completeCompliancePackJobInTransaction(tx, authority, failedJob.job.id, result("late"))), /C03_COMPLIANCE_TRANSITION_DENIED/);

  const evidence = await withC03ResourceTransaction(resourceBoundary("incident-evidence-file-read", "c03-private-a", "incidentEvidenceStorage"),
    (tx, authority) => loadIncidentEvidenceFileInTransaction(tx, authority, "c03-private-a"));
  assert.equal(evidence.incidentId, ids.incidentA);
  await assert.rejects(withC03ResourceTransaction(resourceBoundary("incident-evidence-file-read", "c03-private-b", "incidentEvidenceStorage"),
    (tx, authority) => loadIncidentEvidenceFileInTransaction(tx, authority, "c03-private-b")), /C03_SCOPE_DENIED|C03_INCIDENT_EVIDENCE_DENIED/);

  const raceJob = await start();
  const [completeRace, failRace] = await Promise.allSettled([
    withC03ResourceTransaction(resourceBoundary("compliance-pack-complete", raceJob.job.id),
      (tx, authority) => repository.completeCompliancePackJobInTransaction(tx, authority, raceJob.job.id, result("race"))),
    withC03ResourceTransaction(resourceBoundary("compliance-pack-fail", raceJob.job.id),
      (tx, authority) => repository.failCompliancePackJobInTransaction(tx, authority, raceJob.job.id, "RACE_FAILED")),
  ]);
  assert.equal([completeRace, failRace].filter((entry) => entry.status === "fulfilled").length, 1);

  const beforeRollback = Number(runPsql(bootstrapUrl, 'SELECT count(*) FROM public."CompliancePackJob"'));
  await assert.rejects(prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw`SELECT * FROM app_auth.require_authenticated_session(${capability},'compliance-pack-start',${requestId("rollback")})`;
    const authority = { databaseSessionCapability: capability, requestId: requestId("rollback-inner"), purpose: "compliance-pack-start", licenseeId: ids.licenseeA };
    await repository.startCompliancePackJobInTransaction(tx, authority, { triggerType: "MANUAL", from: null, to: null });
    assert.equal(rows.length, 1);
    throw new Error("C03_INJECTED_ROLLBACK");
  }), /C03_INJECTED_ROLLBACK/);
  assert.equal(Number(runPsql(bootstrapUrl, 'SELECT count(*) FROM public."CompliancePackJob"')), beforeRollback);

  const ownerChecks = JSON.parse(runPsql(bootstrapUrl, `SELECT json_build_object(
    'force',(SELECT relforcerowsecurity FROM pg_class WHERE oid='public."CompliancePackJob"'::regclass),
    'ownerBypass',(SELECT rolbypassrls FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerLogin',(SELECT rolcanlogin FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname='mscqr_rls_cert_auth_owner' AND c.relkind IN ('r','p'))
  )`));
  assert.deepEqual(ownerChecks, { force: true, ownerBypass: false, ownerLogin: false, ownerTables: 0 });
  await prisma.$disconnect();
  console.log("C03 authenticated boundaries application-path proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
