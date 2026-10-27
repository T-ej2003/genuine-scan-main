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
    const { createAuthenticatedSupportIssueReport, respondToAuthenticatedSupportIssueReport } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
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
    const responsePath = `/api/support/reports/${report.id}/respond`;
    assert.equal((await request("POST", responsePath, { message: "A support reply" })).status, 401);
    assert.equal((await request("POST", responsePath, { message: "A support reply" }, {
      headers: { authorization: "Bearer synthetic-expired" },
    })).status, 401);
    assert.equal((await request("POST", responsePath, { message: "A support reply" }, {
      headers: authHeader(tokens.manufacturerA),
    })).status, 403);
    const concurrentResponses = await Promise.all([0, 1].map(() => request("POST", responsePath,
      { message: "A support reply" }, { headers: authHeader(tokens.superAdmin) })));
    assert(concurrentResponses.every((response) => response.status === 200), concurrentResponses.map((response) => response.text).join("\n"));
    assert.deepEqual(concurrentResponses.map((response) => response.payload.data.replayed).sort(), [false, true]);
    assert(concurrentResponses.every((response) => response.payload.data.emailDeliveryStatus === "PENDING"));
    assert(concurrentResponses.every((response) => /Z$/.test(response.payload.data.respondedAt)));
    assert.equal(new Date(concurrentResponses[0].payload.data.respondedAt).getTime(),
      (await prisma.supportIssueReport.findUnique({ where: { id: report.id } })).respondedAt.getTime());
    const responseNotifications = await prisma.notification.findMany({ where: { type: "support_issue_response" } });
    assert.equal(responseNotifications.filter((row) => row.channel === "EMAIL").length, 1);
    assert.equal(responseNotifications.filter((row) => row.channel === "WEB").length, 1);
    assert.equal(responseNotifications.find((row) => row.channel === "EMAIL").emailedAt, null);
    assert.equal(responseNotifications.find((row) => row.channel === "EMAIL").data.respondedAt,
      concurrentResponses[0].payload.data.respondedAt);
    const duplicateResponse = await request("POST", responsePath, { message: "A support reply" }, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(duplicateResponse.status, 200, duplicateResponse.text);
    assert.equal(duplicateResponse.payload.data.replayed, true);
    assert.equal(await prisma.notification.count({ where: { type: "support_issue_response" } }), 2);
    assert.equal(await prisma.auditLogOutbox.count({ where: { payload: { path: ["action"], equals: "SUPPORT_ISSUE_RESPONDED" } } }), 1);
    const queuedAudit = await prisma.auditLogOutbox.findFirst({
      where: { payload: { path: ["entityId"], equals: report.id } },
    });
    assert.equal(queuedAudit.status, "QUEUED");
    assert.equal(queuedAudit.initiatingUserId, ids.manufacturerA);
    assert.equal(queuedAudit.licenseeId, ids.licenseeA);
    assert.equal(queuedAudit.payload.action, "SUPPORT_ISSUE_REPORTED");
    assert.equal(queuedAudit.payload.entityId, report.id);
    assert.match(queuedAudit.payload.ipHash, /^[0-9a-f]{12}:[0-9a-f]{64}$/);
    const responseAuditRow = await prisma.auditLogOutbox.findFirst({
      where: { payload: { path: ["action"], equals: "SUPPORT_ISSUE_RESPONDED" } },
    });
    assert.equal(responseAuditRow.payload.entityId, report.id);
    assert.match(responseAuditRow.payload.ipHash, /^[0-9a-f]{12}:[0-9a-f]{64}$/);
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
      const responseAudit = claims.find((row) => row.id === responseAuditRow.id);
      assert(responseAudit, "Committed support response audit was not claimable by the worker");
      for (const item of [claim, responseAudit]) {
        await withB03AuditWorkerContext({
          jobId: item.id, requestId: item.requestId,
          organizationId: item.organizationId, licenseeId: item.licenseeId,
          manufacturerId: item.manufacturerId, initiatingUserId: item.initiatingUserId,
        }, (db) => consumeAuditLogOutbox(db, {
          jobId: item.id, payloadDigest: item.payloadDigest, attemptedAt: new Date(),
        }), worker);
      }
      assert.equal((await prisma.auditLog.findFirst({ where: {
        action: "SUPPORT_ISSUE_RESPONDED", entityId: report.id,
      } })).userId, ids.superAdmin);
      const { withB03SupportEmailWorkerContext } = require("../dist/rls-waves/session-b/b03/systemContext");
      const { claimSupportResponseEmails, completeSupportResponseEmail } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
      const firstClaimToken = randomUUID();
      const emailClaims = await withB03SupportEmailWorkerContext({
        jobId: `support-email-claim:${firstClaimToken}`, requestId: firstClaimToken,
      }, (db) => claimSupportResponseEmails(db, { attemptedAt: new Date(), batchSize: 10 }), worker);
      assert.equal(emailClaims.length, 1);
      assert.equal(emailClaims[0].data.claimToken, firstClaimToken);
      assert.equal(emailClaims[0].data.recipient, "p2-manufacturer-a@mscqr.test");
      await withB03SupportEmailWorkerContext({
        jobId: emailClaims[0].id, requestId: randomUUID(),
        organizationId: emailClaims[0].organizationId, licenseeId: emailClaims[0].licenseeId,
      }, (db) => completeSupportResponseEmail(db, {
        notificationId: emailClaims[0].id, claimToken: firstClaimToken,
        status: "FAILED", errorCode: "SMTP_CONFIG_MISSING",
      }), worker);
      assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: report.id } })).emailDeliveryStatus, "FAILED");
      await prisma.notification.update({ where: { id: emailClaims[0].id }, data: {
        updatedAt: new Date(Date.now() - 6 * 60_000),
      } });
      const retryToken = randomUUID();
      const retryClaims = await withB03SupportEmailWorkerContext({
        jobId: `support-email-claim:${retryToken}`, requestId: retryToken,
      }, (db) => claimSupportResponseEmails(db, { attemptedAt: new Date(), batchSize: 10 }), worker);
      assert.equal(retryClaims.length, 1);
      assert.equal(retryClaims[0].id, emailClaims[0].id);
      await withB03SupportEmailWorkerContext({
        jobId: retryClaims[0].id, requestId: randomUUID(),
        organizationId: retryClaims[0].organizationId, licenseeId: retryClaims[0].licenseeId,
      }, (db) => completeSupportResponseEmail(db, {
        notificationId: retryClaims[0].id, claimToken: retryToken,
        status: "SENT", providerMessageId: "synthetic-message",
      }), worker);
      assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: report.id } })).emailDeliveryStatus, "SENT");
      assert((await prisma.notification.findUnique({ where: { id: retryClaims[0].id } })).emailedAt);
      const noDuplicate = await withB03SupportEmailWorkerContext({
        jobId: `support-email-claim:${randomUUID()}`, requestId: randomUUID(),
      }, (db) => claimSupportResponseEmails(db, { attemptedAt: new Date(), batchSize: 10 }), worker);
      assert.equal(noDuplicate.length, 0);
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
    const secondResponsePath = `/api/support/reports/${secondReport.id}/respond`;
    assert.equal((await request("POST", secondResponsePath, { message: "Not permitted" }, {
      headers: authHeader(tokens.manufacturerA),
    })).status, 403);
    assert.equal((await request("POST", secondResponsePath, { message: "x" }, {
      headers: authHeader(tokens.superAdmin),
    })).status, 400);
    const responseBoundary = createB03AuthenticatedFunctionBoundary({
      claims: verifyAccessToken(tokens.superAdmin.accessToken),
      capability: openCookieToken(tokens.superAdmin.databaseCapability, "auth.database-session"),
      requestId: randomUUID(), purpose: "support-report-response",
    });
    await assert.rejects(responseBoundary.run((db) => respondToAuthenticatedSupportIssueReport(db, {
      reportId: secondReport.id, message: "Rejected raw address", status: "RESPONDED",
      ipHash: "127.0.0.1", requestId: responseBoundary.requestId,
    })), /B03_SUPPORT_RESPONSE_DENIED|42501/i);
    await assert.rejects(responseBoundary.run(async (db) => {
      await respondToAuthenticatedSupportIssueReport(db, {
        reportId: secondReport.id, message: "Rolled back response", status: "RESPONDED",
        requestId: responseBoundary.requestId,
      });
      throw new Error("synthetic rollback");
    }), /synthetic rollback/);
    assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: secondReport.id } })).responseMessage, null);
    assert.equal(await prisma.notification.count({ where: {
      type: "support_issue_response", licenseeId: ids.licenseeB,
    } }), 0);
    const secondResponse = await request("POST", secondResponsePath, {
      message: "A response for the other tenant",
    }, { headers: authHeader(tokens.superAdmin) });
    assert.equal(secondResponse.status, 200, secondResponse.text);
    const additionalReport = await prisma.supportIssueReport.create({ data: {
      reporterUserId: ids.manufacturerB, reporterRole: "MANUFACTURER_ADMIN",
      licenseeId: ids.licenseeB, title: "Another synthetic response",
    } });
    assert.equal((await request("POST", `/api/support/reports/${additionalReport.id}/respond`, {
      message: "Another response for the other tenant",
    }, { headers: authHeader(tokens.superAdmin) })).status, 200);
    const { withB03SupportEmailWorkerContext: withRecoveryWorkerContext } = require("../dist/rls-waves/session-b/b03/systemContext");
    const { claimSupportResponseEmails: claimRecoveryEmails } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
    const recoveryWorker = new PrismaClient({ datasources: { db: { url: workerUrl.toString() } } });
    try {
      const staleToken = randomUUID();
      const staleClaims = await withRecoveryWorkerContext({
        jobId: `support-email-claim:${staleToken}`, requestId: staleToken,
      }, (db) => claimRecoveryEmails(db, { attemptedAt: new Date(), batchSize: 2 }), recoveryWorker);
      assert.equal(staleClaims.length, 2);
      assert(staleClaims.every((claim) => claim.licenseeId === ids.licenseeB));
      for (const claim of staleClaims) {
        await prisma.notification.update({ where: { id: claim.id }, data: {
          updatedAt: new Date(Date.now() - 16 * 60_000),
        } });
      }
      const recoveryToken = randomUUID();
      const recovered = await withRecoveryWorkerContext({
        jobId: `support-email-claim:${recoveryToken}`, requestId: recoveryToken,
      }, (db) => claimRecoveryEmails(db, { attemptedAt: new Date(), batchSize: 1 }), recoveryWorker);
      assert.equal(recovered.length, 0, "ambiguous delivery must not be retried automatically");
      assert.equal((await prisma.notification.findMany({ where: { id: { in: staleClaims.map((claim) => claim.id) } } }))
        .filter((row) => row.data.emailState === "UNKNOWN").length, 1);
      await withRecoveryWorkerContext({
        jobId: `support-email-claim:${randomUUID()}`, requestId: randomUUID(),
      }, (db) => claimRecoveryEmails(db, { attemptedAt: new Date(), batchSize: 1 }), recoveryWorker);
      assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: secondReport.id } })).emailDeliveryStatus, "UNKNOWN");
      assert((await prisma.notification.findMany({ where: { id: { in: staleClaims.map((claim) => claim.id) } } }))
        .every((row) => row.data.emailState === "UNKNOWN"));
    } finally {
      await recoveryWorker.$disconnect();
    }
    const terminalNotifications = await prisma.notification.count({ where: {
      type: "support_issue_response", licenseeId: ids.licenseeB,
    } });
    const unknownReplay = await request("POST", secondResponsePath, {
      message: "A response for the other tenant",
    }, { headers: authHeader(tokens.superAdmin) });
    assert.equal(unknownReplay.status, 200, unknownReplay.text);
    assert.equal(unknownReplay.payload.data.replayed, true);
    assert.equal(unknownReplay.payload.data.emailDeliveryStatus, "UNKNOWN");
    assert.equal(await prisma.notification.count({ where: {
      type: "support_issue_response", licenseeId: ids.licenseeB,
    } }), terminalNotifications, "ambiguous delivery replay must not enqueue a duplicate email");
    const changedResponse = await request("POST", responsePath, { message: "A changed support reply" }, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(changedResponse.status, 200, changedResponse.text);
    assert.equal(changedResponse.payload.data.replayed, false);
    const restoredResponse = await request("POST", responsePath, { message: "A support reply" }, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(restoredResponse.status, 200, restoredResponse.text);
    assert.equal(restoredResponse.payload.data.replayed, false);
    assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: report.id } })).responseMessage, "A support reply");
    assert.equal(await prisma.notification.count({ where: {
      type: "support_issue_response", channel: "EMAIL",
      data: { path: ["supportReportId"], equals: report.id },
    } }), 3);
    const restoredReplay = await request("POST", responsePath, { message: "A support reply" }, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(restoredReplay.payload.data.replayed, true);
    assert.equal(restoredReplay.payload.data.respondedAt, restoredResponse.payload.data.respondedAt);
    assert.equal(await prisma.auditLogOutbox.count({ where: {
      payload: { path: ["action"], equals: "SUPPORT_ISSUE_RESPONDED" },
    } }), 5);

    await prisma.refreshToken.updateMany({ where: { userId: ids.superAdmin, revokedAt: null }, data: {
      mfaVerifiedAt: new Date(Date.now() - 31 * 60_000),
    } });
    const staleMfaBoundary = createB03AuthenticatedFunctionBoundary({
      claims: verifyAccessToken(tokens.superAdmin.accessToken),
      capability: openCookieToken(tokens.superAdmin.databaseCapability, "auth.database-session"),
      requestId: randomUUID(), purpose: "support-report-response",
    });
    const [mfaState] = await staleMfaBoundary.run((db) => db.$queryRaw`
      SELECT count(*)::integer AS "count" FROM app_rls.require_recent_mfa_session(
        current_setting('app.auth_session_id',true),clock_timestamp()::timestamp,30)
    `);
    assert.equal(mfaState.count, 0, "the authenticated actor must have no recent-MFA result");
    await assert.rejects(staleMfaBoundary.run((db) => respondToAuthenticatedSupportIssueReport(db, {
      reportId: report.id, message: "This response must not persist", status: "RESPONDED",
      requestId: staleMfaBoundary.requestId,
    })), /B03_SUPPORT_RESPONSE_DENIED|RECENT_MFA_DENIED|42501/i);
    assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: report.id } })).responseMessage, "A support reply");
    assert.equal(await prisma.auditLogOutbox.count({ where: {
      payload: { path: ["action"], equals: "SUPPORT_ISSUE_RESPONDED" },
    } }), 5);

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
