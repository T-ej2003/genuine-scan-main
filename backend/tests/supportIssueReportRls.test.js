const assert = require("node:assert/strict");
const { withP2TestApp, P2TestDbSkip } = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");
const { randomUUID } = require("node:crypto");

const authHeader = (token) => ({
  authorization: `Bearer ${token.accessToken}`,
  "x-database-session-capability": token.databaseCapability,
});

(async () => {
  await withP2TestApp(async ({ request, prisma, preauthPrisma, runtimePrisma }) => {
    await seedP2Fixtures(prisma);
    const tokens = await issueBearerTokens(preauthPrisma);
    const body = { title: "Synthetic printer support issue", description: "Isolated RLS integration test" };

    const missingAuth = await request("POST", "/api/support/reports", body);
    assert.equal(missingAuth.status, 401);
    const expired = await request("POST", "/api/support/reports", body, {
      headers: { authorization: "Bearer synthetic-expired" },
    });
    assert.equal(expired.status, 401);
    const malformed = await request("POST", "/api/support/reports", { title: "bad" }, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.equal(malformed.status, 400, malformed.text);
    const foreign = await request("POST", "/api/support/reports", {
      ...body, licenseeId: ids.licenseeB,
    }, { headers: authHeader(tokens.manufacturerA) });
    assert([400, 403].includes(foreign.status), foreign.text);

    const { verifyAccessToken } = require("../dist/services/auth/tokenService");
    const { openCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
    const { createB03AuthenticatedFunctionBoundary } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
    const { createAuthenticatedSupportIssueReport } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
    const boundary = createB03AuthenticatedFunctionBoundary({
      claims: verifyAccessToken(tokens.manufacturerA.accessToken),
      capability: openCookieToken(tokens.manufacturerA.databaseCapability, "auth.database-session"),
      requestId: randomUUID(),
      purpose: "support-report-create",
    });
    await assert.rejects(
      boundary.run((db) => createAuthenticatedSupportIssueReport(db, {
        licenseeId: ids.licenseeB,
        organizationId: ids.orgB,
        ...body,
        autoDetected: false,
        requestId: boundary.requestId,
      })),
      /B03_SUPPORT_REPORT_DENIED|42501/i
    );

    const valid = await request("POST", "/api/support/reports", body, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.equal(valid.status, 201, valid.text);
    const report = await prisma.supportIssueReport.findUnique({ where: { id: valid.payload.data.id } });
    assert.equal(report.reporterUserId, ids.manufacturerA);
    assert.equal(report.licenseeId, ids.licenseeA);
    const queuedAudit = await prisma.auditLogOutbox.findFirst({
      where: { payload: { path: ["entityId"], equals: report.id } },
    });
    assert.equal(queuedAudit.status, "QUEUED");
    assert.equal(queuedAudit.initiatingUserId, ids.manufacturerA);
    assert.equal(queuedAudit.licenseeId, ids.licenseeA);
    assert.equal(queuedAudit.payload.action, "SUPPORT_ISSUE_REPORTED");
    assert.equal(queuedAudit.payload.entityId, report.id);
    assert.match(queuedAudit.payload.ipHash, /^[0-9a-f]{12}:[0-9a-f]{64}$/);
    const { PrismaClient } = require("@prisma/client");
    const workerUrl = new URL(process.env.DATABASE_URL);
    workerUrl.username = "mscqr_rls_cert_worker";
    workerUrl.password = "";
    const worker = new PrismaClient({ datasources: { db: { url: workerUrl.toString() } } });
    process.env.MSCQR_WORKER_DATABASE_ROLE = "mscqr_rls_cert_worker";
    const { withB03AuditWorkerContext } = require("../dist/rls-waves/session-b/b03/systemContext");
    const { claimAuditLogOutboxSlice, consumeAuditLogOutbox } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
    try {
      const claimRequestId = randomUUID();
      const claims = await withB03AuditWorkerContext({
        jobId: `audit-outbox-claim:${claimRequestId}`, requestId: claimRequestId,
      }, (db) => claimAuditLogOutboxSlice(db, { attemptedAt: new Date(), batchSize: 25 }), worker);
      const claim = claims.find((row) => row.id === queuedAudit.id);
      assert(claim, "Committed support audit was not claimable by the worker");
      await withB03AuditWorkerContext({
        jobId: claim.id, requestId: claim.requestId,
        organizationId: claim.organizationId, licenseeId: claim.licenseeId,
        manufacturerId: claim.manufacturerId, initiatingUserId: claim.initiatingUserId,
      }, (db) => consumeAuditLogOutbox(db, {
        jobId: claim.id, payloadDigest: claim.payloadDigest, attemptedAt: new Date(),
      }), worker);
      const { withB03SiemWorkerContext } = require("../dist/rls-waves/session-b/b03/systemContext");
      const { claimSecurityEventOutboxSlice, completeSecurityEventOutbox } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
      const securityClaims = await withB03SiemWorkerContext({
        jobId: `siem-outbox-claim:${claimRequestId}`, requestId: claimRequestId, jobType: "AUDIT_LOG",
      }, (db) => claimSecurityEventOutboxSlice(db, {
        attemptedAt: new Date(), batchSize: 25, jobType: "AUDIT_LOG",
      }), worker);
      const securityClaim = securityClaims.find((row) => row.requestId === queuedAudit.requestId);
      assert(securityClaim, "Committed support security event was not claimable");
      await withB03SiemWorkerContext({
        jobId: securityClaim.id, requestId: securityClaim.requestId, jobType: "AUDIT_LOG",
        organizationId: securityClaim.organizationId, licenseeId: securityClaim.licenseeId,
        manufacturerId: securityClaim.manufacturerId, initiatingUserId: securityClaim.initiatingUserId,
      }, (db) => completeSecurityEventOutbox(db, {
        jobId: securityClaim.id, payloadDigest: securityClaim.payloadDigest,
        attemptedAt: new Date(), sinkEventId: `projection:${securityClaim.id}`,
      }), worker);
    } finally {
      await worker.$disconnect();
    }
    const audit = await prisma.auditLog.findFirst({
      where: { action: "SUPPORT_ISSUE_REPORTED", entityType: "SupportIssueReport", entityId: report.id },
    });
    assert.equal(audit.userId, ids.manufacturerA);
    assert.equal(audit.licenseeId, ids.licenseeA);
    assert.match(audit.ipHash, /^[0-9a-f]{12}:[0-9a-f]{64}$/);
    const securityEvent = await prisma.securityEventOutbox.findFirst({
      where: { eventType: "AUDIT_LOG", requestId: queuedAudit.requestId },
    });
    assert.equal(securityEvent.payload.action, "SUPPORT_ISSUE_REPORTED");
    assert.equal(securityEvent.payload.entityId, report.id);
    assert.equal(securityEvent.sinkEventId, `projection:${securityEvent.id}`);
    assert.equal(await prisma.supportIssueReport.count({ where: { title: body.title } }), 1);

    const second = await request("POST", "/api/support/reports", {
      title: "Second tenant printer support issue",
    }, { headers: authHeader(tokens.manufacturerB) });
    assert.equal(second.status, 201, second.text);
    const secondReport = await prisma.supportIssueReport.findUnique({ where: { id: second.payload.data.id } });
    assert.equal(secondReport.licenseeId, ids.licenseeB);
    assert.equal(secondReport.reporterUserId, ids.manufacturerB);

    await assert.rejects(
      runtimePrisma.supportIssueReport.create({ data: {
        reporterUserId: ids.manufacturerA, reporterRole: "MANUFACTURER_ADMIN",
        licenseeId: ids.licenseeA, title: "Direct write must fail",
      } }),
      /permission denied|42501/i
    );
    assert.doesNotMatch(valid.text, /passwordHash|sessionCapability|diagnostics/i);
  });
  console.log("support issue report RLS integration passed");
})().catch((error) => {
  if (error instanceof P2TestDbSkip && process.env.P2_TEST_DATABASE_REQUIRED !== "true") {
    console.log(`support issue report RLS integration skipped: ${error.message}`);
    return;
  }
  console.error(error);
  process.exitCode = 1;
});
