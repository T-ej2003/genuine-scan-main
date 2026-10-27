const assert = require("node:assert/strict");
const { withP2TestApp, P2TestDbSkip } = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");
const { randomUUID } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

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

    const { supportDiagnosticsStorageBytesUpperBound, SUPPORT_DIAGNOSTICS_MAX_BYTES } = require("../dist/utils/supportDiagnosticsSize");
    const asciiBase = supportDiagnosticsStorageBytesUpperBound({ message: "" });
    const asciiDiagnostics = { message: "a".repeat(SUPPORT_DIAGNOSTICS_MAX_BYTES - asciiBase) };
    assert.equal(supportDiagnosticsStorageBytesUpperBound(asciiDiagnostics), SUPPORT_DIAGNOSTICS_MAX_BYTES);
    const asciiPgSize = await prisma.$queryRawUnsafe(
      "SELECT octet_length($1::jsonb::text) AS bytes", JSON.stringify(asciiDiagnostics)
    );
    assert.equal(asciiPgSize[0].bytes, SUPPORT_DIAGNOSTICS_MAX_BYTES);
    const asciiValid = await request("POST", "/api/support/reports", {
      title: "ASCII diagnostics at boundary", diagnostics: JSON.stringify(asciiDiagnostics),
    }, { headers: authHeader(tokens.manufacturerA) });
    assert.equal(asciiValid.status, 201, asciiValid.text.slice(0, 500));
    assert.equal((await prisma.supportIssueReport.findUnique({ where: { id: asciiValid.payload.data.id } })).diagnostics.message.length,
      asciiDiagnostics.message.length);

    const unicodeCount = Math.floor((SUPPORT_DIAGNOSTICS_MAX_BYTES - asciiBase) / Buffer.byteLength("🎯", "utf8"));
    const unicodeDiagnostics = { message: "🎯".repeat(unicodeCount) };
    const unicodePgSize = await prisma.$queryRawUnsafe(
      "SELECT octet_length($1::jsonb::text) AS bytes", JSON.stringify(unicodeDiagnostics)
    );
    assert.equal(unicodePgSize[0].bytes, supportDiagnosticsStorageBytesUpperBound(unicodeDiagnostics));
    for (const sample of [{ nested: [1e21, 1e-7, 1e308, "line\nbreak"] }, { accent: "é", emoji: "🎯" }]) {
      const pgSize = await prisma.$queryRawUnsafe(
        "SELECT octet_length($1::jsonb::text) AS bytes", JSON.stringify(sample)
      );
      assert(supportDiagnosticsStorageBytesUpperBound(sample) >= pgSize[0].bytes);
    }
    const unicodeValid = await request("POST", "/api/support/reports", {
      title: "Unicode diagnostics within boundary", diagnostics: JSON.stringify(unicodeDiagnostics),
    }, { headers: authHeader(tokens.manufacturerA) });
    assert.equal(unicodeValid.status, 201, unicodeValid.text.slice(0, 500));
    const oversized = await request("POST", "/api/support/reports", {
      title: "Unicode diagnostics over boundary",
      diagnostics: JSON.stringify({ message: unicodeDiagnostics.message + "🎯" }),
    }, { headers: authHeader(tokens.manufacturerA) });
    assert.equal(oversized.status, 400, oversized.text.slice(0, 500));
    assert.equal(await prisma.supportIssueReport.count({ where: { title: "Unicode diagnostics over boundary" } }), 0);
    const oversizedAscii = await request("POST", "/api/support/reports", {
      title: "ASCII diagnostics over boundary",
      diagnostics: JSON.stringify({ message: asciiDiagnostics.message + "a" }),
    }, { headers: authHeader(tokens.manufacturerA) });
    assert.equal(oversizedAscii.status, 400, oversizedAscii.text.slice(0, 500));
    await assert.rejects(
      boundary.run((db) => db.$queryRawUnsafe(
        `SELECT app_rls.b03_create_support_issue_report(
          $1::text,$2::text,'SQL boundary oversized diagnostics',NULL::text,NULL::text,NULL::text,
          false,NULL::text,NULL::text,NULL::integer,$3::jsonb,NULL::text,$4::text)`,
        ids.licenseeA, ids.orgA, JSON.stringify({ message: asciiDiagnostics.message + "a" }), boundary.requestId
      )),
      /B03_SUPPORT_REPORT_DENIED|42501/i
    );

    const second = await request("POST", "/api/support/reports", {
      title: "Second tenant printer support issue",
    }, { headers: authHeader(tokens.manufacturerB) });
    assert.equal(second.status, 201, second.text);
    const secondReport = await prisma.supportIssueReport.findUnique({ where: { id: second.payload.data.id } });
    assert.equal(secondReport.licenseeId, ids.licenseeB);
    assert.equal(secondReport.reporterUserId, ids.manufacturerB);

    const ownList = await request("GET", "/api/support/reports", undefined, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.equal(ownList.status, 200, ownList.text);
    assert(ownList.payload.data.reports.some((row) => row.id === report.id));
    assert(ownList.payload.data.reports.every((row) => row.reporterUserId === ids.manufacturerA));
    assert(!ownList.payload.data.reports.some((row) => row.id === secondReport.id));
    const platformList = await request("GET", "/api/support/reports", undefined, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(platformList.status, 200, platformList.text);
    assert(platformList.payload.data.reports.some((row) => row.id === report.id));
    assert(platformList.payload.data.reports.some((row) => row.id === secondReport.id));
    const tenantBList = await request("GET", `/api/support/reports?licenseeId=${ids.licenseeB}`, undefined, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(tenantBList.status, 200, tenantBList.text);
    assert(tenantBList.payload.data.reports.every((row) => row.licenseeId === ids.licenseeB));
    const foreignFilter = await request("GET", `/api/support/reports?licenseeId=${ids.licenseeB}`, undefined, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.equal(foreignFilter.status, 403, foreignFilter.text);
    const malformedList = await request("GET", "/api/support/reports?limit=201", undefined, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.equal(malformedList.status, 400, malformedList.text);
    const missingListAuth = await request("GET", "/api/support/reports");
    assert.equal(missingListAuth.status, 401, missingListAuth.text);

    const fileName = `p2-support-${randomUUID()}.png`;
    const { supportIssueUploadsDirectory } = require("../dist/middleware/supportIssueUpload");
    const filePath = path.join(supportIssueUploadsDirectory, fileName);
    fs.mkdirSync(supportIssueUploadsDirectory, { recursive: true });
    fs.writeFileSync(filePath, Buffer.from("synthetic-png-test-file"));
    try {
      await prisma.supportIssueReport.update({ where: { id: report.id }, data: {
        screenshotPath: fileName, screenshotMime: "image/png",
      } });
      const ownScreenshot = await request("GET", `/api/support/reports/files/${fileName}`, undefined, {
        headers: authHeader(tokens.manufacturerA),
      });
      assert.equal(ownScreenshot.status, 200, ownScreenshot.text);
      const foreignScreenshot = await request("GET", `/api/support/reports/files/${fileName}`, undefined, {
        headers: authHeader(tokens.manufacturerB),
      });
      assert.equal(foreignScreenshot.status, 404, foreignScreenshot.text);
      const sameTenantNonOwner = await request("GET", `/api/support/reports/files/${fileName}`, undefined, {
        headers: authHeader(tokens.licenseeAdminA),
      });
      assert.equal(sameTenantNonOwner.status, 404, sameTenantNonOwner.text);
      const platformScreenshot = await request("GET", `/api/support/reports/files/${fileName}`, undefined, {
        headers: authHeader(tokens.superAdmin),
      });
      assert.equal(platformScreenshot.status, 200, platformScreenshot.text);
    } finally {
      fs.rmSync(filePath, { force: true });
    }

    await prisma.manufacturerLicenseeLink.create({ data: {
      manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB, isPrimary: false,
    } });
    const selectedTenantReportId = randomUUID();
    await prisma.supportIssueReport.create({ data: {
      id: selectedTenantReportId, reporterUserId: ids.manufacturerA,
      reporterRole: "MANUFACTURER_ADMIN", licenseeId: ids.licenseeB,
      title: "Selected tenant B report", screenshotPath: "selected-tenant-b.png",
      screenshotMime: "image/png",
    } });
    await prisma.user.update({ where: { id: ids.manufacturerA }, data: {
      licenseeId: null, orgId: null,
    } });
    const selectedClaims = {
      ...verifyAccessToken(tokens.manufacturerA.accessToken),
      licenseeId: ids.licenseeB, orgId: ids.orgB,
    };
    const selectedListBoundary = createB03AuthenticatedFunctionBoundary({
      claims: selectedClaims,
      capability: openCookieToken(tokens.manufacturerA.databaseCapability, "auth.database-session"),
      requestId: randomUUID(), purpose: "support-report-list",
    });
    const { listAuthenticatedSupportIssueReports, getAuthenticatedSupportIssueScreenshot } = require("../dist/rls-waves/session-b/b03/repositoryFunctions");
    const selectedList = await selectedListBoundary.run((db) => listAuthenticatedSupportIssueReports(db, {
      limit: 50, offset: 0, actorLicenseeId: ids.licenseeB,
      actorOrganizationId: ids.orgB, requestId: selectedListBoundary.requestId,
    }));
    assert(selectedList.reports.some((row) => row.id === selectedTenantReportId));
    assert(!selectedList.reports.some((row) => row.id === report.id));
    const selectedScreenshotBoundary = createB03AuthenticatedFunctionBoundary({
      claims: selectedClaims,
      capability: openCookieToken(tokens.manufacturerA.databaseCapability, "auth.database-session"),
      requestId: randomUUID(), purpose: "support-report-screenshot",
    });
    const selectedScreenshot = await selectedScreenshotBoundary.run((db) => getAuthenticatedSupportIssueScreenshot(db, {
      fileName: "selected-tenant-b.png", actorLicenseeId: ids.licenseeB,
      actorOrganizationId: ids.orgB, requestId: selectedScreenshotBoundary.requestId,
    }));
    assert.equal(selectedScreenshot.id, selectedTenantReportId);

    await assert.rejects(
      runtimePrisma.supportIssueReport.create({ data: {
        reporterUserId: ids.manufacturerA, reporterRole: "MANUFACTURER_ADMIN",
        licenseeId: ids.licenseeA, title: "Direct write must fail",
      } }),
      /permission denied|42501/i
    );
    await assert.rejects(
      runtimePrisma.supportIssueReport.findMany(),
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
