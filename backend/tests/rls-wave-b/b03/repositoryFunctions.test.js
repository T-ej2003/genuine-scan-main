const assert = require("node:assert/strict");

const {
  b03PayloadDigest, claimAuditLogOutboxSlice,
  claimCompliancePackSlice,
  consumeAuditLogOutbox,
  createRoleNotifications,
  getPrimarySuperadminEmail,
  getSuperadminAlertEmails,
  readAttentionQueueProjection,
  resolveIncidentNotificationScope,
} = require("../../../dist/rls-waves/session-b/b03/repositoryFunctions");

const client = (rows, captured) => ({
  $queryRaw: async (query) => {
    captured.push({ sql: query.sql, values: query.values });
    return rows;
  },
});

const main = async () => {
  const auditCalls = [];
  const auditResult = await consumeAuditLogOutbox(client([
    { auditLogId: "audit-1", replayed: false },
  ], auditCalls), {
    jobId: "job-1",
    payloadDigest: "a".repeat(64),
    attemptedAt: new Date("2026-07-20T10:00:00.000Z"),
  });
  assert.equal(auditResult.auditLogId, "audit-1");
  assert.match(auditCalls[0].sql, /app_rls\.consume_audit_log_outbox\(/);
  assert.equal(auditCalls[0].values[0], "job-1");
  assert.equal(auditCalls[0].values[1], "a".repeat(64));

  await assert.rejects(
    consumeAuditLogOutbox(client([], []), {
      jobId: "job-2",
      payloadDigest: "b".repeat(64),
      attemptedAt: new Date(),
    }),
    /exactly one row/
  );

  await assert.rejects(
    claimAuditLogOutboxSlice(client([{
      id: "job-3",
      jobType: "AUDIT_LOG_RECOVERY",
      requestId: "174d1fe7-f82e-42a7-829a-ddb8ecf329cb",
      payloadDigest: "payload-only-is-not-authority",
      idempotencyKey: "idempotency-1",
      organizationId: null,
      licenseeId: null,
      manufacturerId: null,
      initiatingUserId: null,
      expiresAt: new Date("2026-07-20T12:00:00.000Z"),
      attempt: 1,
    }], []), { attemptedAt: new Date("2026-07-20T10:00:00.000Z"), batchSize: 1 }),
    /SHA-256 payloadDigest/
  );

  const digest = b03PayloadDigest({ action: "AUDIT", details: { b: 2, a: 1 } });
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(
    digest,
    b03PayloadDigest({ details: { a: 1, b: 2 }, action: "AUDIT" }),
    "Payload digest must canonicalize object-key order for deterministic replay checks"
  );
  assert.notEqual(digest, JSON.stringify({ action: "AUDIT", details: { b: 2, a: 1 } }));

  await assert.rejects(
    claimAuditLogOutboxSlice(client([], []), {
      attemptedAt: new Date("2026-07-20T10:00:00.000Z"),
      batchSize: 251,
    }),
    /batchSize between 1 and 250/
  );

  const complianceCalls = [];
  await claimCompliancePackSlice(client([], complianceCalls), {
    capability: "A".repeat(43),
    scheduleId: "daily-utc",
    dueAt: new Date("2026-07-20T11:00:00.000Z"),
    batchSize: 100,
  });
  assert.match(complianceCalls[0].sql, /app_rls\.claim_compliance_pack_slice\(/);
  assert.deepEqual(complianceCalls[0].values.slice(0, 4), [
    "A".repeat(43),
    "daily-utc",
    new Date("2026-07-20T11:00:00.000Z"),
    100,
  ]);

  const primaryCalls = [];
  assert.deepEqual(
    await getPrimarySuperadminEmail(client([{ email: "security@example.test" }], primaryCalls)),
    { email: "security@example.test" }
  );
  assert.match(primaryCalls[0].sql, /app_rls\.b03_primary_superadmin_email\(\)/);

  await assert.rejects(
    getSuperadminAlertEmails(client(
      Array.from({ length: 101 }, (_, index) => ({ email: `admin${index}@example.test` })),
      []
    )),
    /unbounded result/
  );

  const roleCalls = [];
  await createRoleNotifications(client([], roleCalls), {
    audience: "LICENSEE_ADMIN",
    title: "Incident",
    body: "Incident requires review",
    notificationType: "INCIDENT_CREATED",
    channels: ["WEB"],
    requestId: "174d1fe7-f82e-42a7-829a-ddb8ecf329cb",
  });
  assert.match(roleCalls[0].sql, /app_rls\.b03_create_role_notifications\(/);
  assert.equal(roleCalls[0].values[0], "LICENSEE_ADMIN");
  assert.equal(roleCalls[0].values[8][0], "WEB");

  assert.throws(
    () => createRoleNotifications(client([], []), {
      audience: "LICENSEE_ADMIN",
      title: "Incident",
      body: "Incident requires review",
      notificationType: "INCIDENT_CREATED",
      channels: ["WEB", "WEB"],
      requestId: "174d1fe7-f82e-42a7-829a-ddb8ecf329cb",
    }),
    /unique notification channels/
  );

  const scopeCalls = [];
  await resolveIncidentNotificationScope(client([{
    incidentId: "incident-1",
    licenseeId: "licensee-1",
    manufacturerOrganizationId: null,
  }], scopeCalls), "incident-1");
  assert.match(scopeCalls[0].sql, /app_rls\.b03_resolve_incident_notification_scope\(/);

  const attentionCalls = [];
  const attention = await readAttentionQueueProjection(client([{
    result: {
      incidents: { count: 1, latest: null },
      policyAlerts: { count: 0, latest: null },
      supportTickets: { count: 0, latest: null },
      auditEvents: { count: 2, latest: null },
    },
  }], attentionCalls), {
    licenseeId: "11111111-1111-4111-8111-111111111111",
    since: new Date("2026-07-25T00:00:00.000Z"),
    requestId: "174d1fe7-f82e-42a7-829a-ddb8ecf329cb",
  });
  assert.equal(attention.auditEvents.count, 2);
  assert.match(attentionCalls[0].sql, /app_rls\.b03_attention_queue_projection\(/);

  console.log("B03 repository function unit tests passed");
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
