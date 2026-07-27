const assert = require("node:assert/strict");

const {
  withB03AuditWorkerContext,
  withB03ScheduledContext,
  withB03SiemWorkerContext,
} = require("../../../dist/rls-waves/session-b/b03/systemContext");

const REQUEST_ID = "174d1fe7-f82e-42a7-829a-ddb8ecf329cb";

const runnerFor = (databaseRole, calls) => ({
  $transaction: async (callback) => callback({
    $queryRaw: async (query) => {
      calls.push({ sql: query.sql, values: query.values });
      if (query.sql.includes("current_user")) return [{ databaseRole }];
      return [];
    },
  }),
});

const main = async () => {
  process.env.MSCQR_WORKER_DATABASE_ROLE = "mscqr_test_worker";
  process.env.MSCQR_SCHEDULED_DATABASE_ROLE = "mscqr_test_scheduled";

  const calls = [];
  const result = await withB03AuditWorkerContext(
    { jobId: "audit-job-1", requestId: REQUEST_ID, licenseeId: "licensee-a" },
    async () => {
      calls.push({ sql: "callback", values: [] });
      return "ok";
    },
    runnerFor("mscqr_test_worker", calls)
  );
  assert.equal(result, "ok");
  assert.match(calls[0].sql, /current_user/);
  assert.match(calls[1].sql, /set_config\('app\.system_identity'/);
  assert.equal(calls[2].sql, "callback", "protected query callback must run after context installation");
  assert.deepEqual(
    calls[1].values.slice(0, 8),
    [
      "identity-worker",
      "audit-job-1",
      "AUDIT_LOG_RECOVERY",
      "",
      "licensee-a",
      "",
      "",
      REQUEST_ID,
    ]
  );
  assert.match(calls[1].sql, /set_config\('app\.role', '', true\)/);
  assert.match(calls[1].sql, /set_config\('app\.is_platform_admin', 'false', true\)/);

  await assert.rejects(
    withB03AuditWorkerContext(
      { jobId: "audit-job-2", requestId: REQUEST_ID },
      async () => undefined,
      runnerFor("database_owner", [])
    ),
    /database role mismatch/
  );

  await assert.rejects(
    withB03SiemWorkerContext(
      { jobId: "siem-job-1", requestId: REQUEST_ID, jobType: "SCHEDULED_COMPLIANCE_PACK" },
      async () => undefined,
      runnerFor("mscqr_test_worker", [])
    ),
    /rejects job type/
  );

  await assert.rejects(
    withB03AuditWorkerContext(
      { jobId: "audit-job-3", requestId: "not-a-uuid" },
      async () => undefined,
      runnerFor("mscqr_test_worker", [])
    ),
    /UUID request ID/
  );

  const scheduledCalls = [];
  await withB03ScheduledContext(
    { jobId: "schedule-job-1", requestId: REQUEST_ID },
    async () => undefined,
    runnerFor("mscqr_test_scheduled", scheduledCalls)
  );
  assert.equal(scheduledCalls[1].values[0], "identity-scheduled-job");
  assert.equal(scheduledCalls[1].values[2], "SCHEDULED_COMPLIANCE_PACK");

  const previousRole = process.env.MSCQR_WORKER_DATABASE_ROLE;
  delete process.env.MSCQR_WORKER_DATABASE_ROLE;
  await assert.rejects(
    withB03AuditWorkerContext(
      { jobId: "audit-job-4", requestId: REQUEST_ID },
      async () => undefined,
      runnerFor("mscqr_test_worker", [])
    ),
    /MSCQR_WORKER_DATABASE_ROLE/
  );
  process.env.MSCQR_WORKER_DATABASE_ROLE = previousRole;

  console.log("B03 system context unit tests passed");
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

