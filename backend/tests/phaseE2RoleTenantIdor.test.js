const assert = require("assert");
const { P2TestDbSkip, withP2TestApp } = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const authHeader = (token) => ({
  authorization: `Bearer ${token.accessToken}`,
  "x-database-session-capability": token.databaseCapability,
});
const deniedStatuses = new Set([401, 403, 404, 410, 428]);

const assertSafeResponse = (response, label) => {
  const text = response.text || "";
  assert.doesNotMatch(
    text,
    /DATABASE_URL|JWT_SECRET|QR_SIGN_HMAC_SECRET|AUTH_COOKIE_SECRET_CURRENT|SMTP_PASS|passwordHash|tokenHash|printLockToken|renderToken|Bearer\s+[A-Za-z0-9._-]+|PrismaClientKnownRequestError|at\s+\S+\s+\(/i,
    `${label}: leaked backend internals`
  );
};

const assertDenied = (response, label) => {
  assert(deniedStatuses.has(response.status), `${label}: expected safe denial, got ${response.status} ${response.text}`);
  assertSafeResponse(response, label);
};

const assertNoLeak = (response, marker, label) => {
  assert.doesNotMatch(response.text || "", new RegExp(marker, "i"), `${label}: leaked ${marker}`);
};

const parseCsv = (text) => {
  const lines = String(text || "").trim().split(/\r?\n/).filter(Boolean);
  const headers = (lines.shift() || "").split(",").map((value) => value.replace(/^"|"$/g, ""));
  return lines.map((line) => {
    const cells = line.match(/("([^"]|"")*"|[^,]*)/g)?.filter((_, index, values) => index < values.length - 1) || [];
    return Object.fromEntries(headers.map((header, index) => [header, (cells[index] || "").replace(/^"|"$/g, "").replace(/""/g, "\"")]));
  });
};

(async () => {
  await withP2TestApp(async ({ request, prisma, preauthPrisma }) => {
    await seedP2Fixtures(prisma);
    const tokens = await issueBearerTokens(preauthPrisma);

    await prisma.supportIssueReport.update({
      where: { id: ids.supportReportA },
      data: {
        internalNote: "support-internal-note-a",
        emailErrorCode: "smtp-internal-error-a",
        acknowledgementEmailErrorCode: "smtp-ack-internal-error-a",
      },
    });
    await prisma.supportIssueReport.update({
      where: { id: ids.supportReportB },
      data: {
        internalNote: "support-internal-note-b",
        publicEmail: "public-b@mscqr.test",
      },
    });

    await prisma.requestAccess.createMany({
      data: [
        {
          id: "00000000-0000-4202-9400-000000000001",
          referenceCode: "P2RA-A",
          fullName: "P2 Request A",
          workEmail: "request-a@tenant-a.test",
          companyName: "Tenant A Apparel",
          roleTitle: "Operations",
          country: "ZA",
          monthlyGarmentVolume: "1000",
          message: "Tenant A launch request",
          sourcePage: "/request-access",
          internalNote: "request-access-internal-a",
        },
        {
          id: "00000000-0000-4202-9400-000000000002",
          referenceCode: "P2RA-B",
          fullName: "P2 Request B",
          workEmail: "request-b@tenant-b.test",
          companyName: "Tenant B Apparel",
          roleTitle: "Operations",
          country: "IN",
          monthlyGarmentVolume: "2000",
          message: "Tenant B launch request",
          sourcePage: "/request-access",
          internalNote: "request-access-internal-b",
        },
      ],
    });

    await prisma.auditLog.createMany({
      data: [
        {
          userId: ids.licenseeAdminA,
          orgId: ids.orgA,
          licenseeId: ids.licenseeA,
          action: "PHASE_E2_AUDIT_A",
          entityType: "Batch",
          entityId: ids.batchA,
          details: { marker: "audit-tenant-a-marker", batchName: "P2 Batch A" },
        },
        {
          userId: ids.licenseeAdminB,
          orgId: ids.orgB,
          licenseeId: ids.licenseeB,
          action: "PHASE_E2_AUDIT_B",
          entityType: "Batch",
          entityId: ids.batchB,
          details: { marker: "audit-tenant-b-marker", batchName: "P2 Batch B" },
        },
      ],
    });

    const anonymousRequestAccess = await request("GET", "/api/support/request-access", null);
    assertDenied(anonymousRequestAccess, "anonymous request-access queue");

    const invalidRequestAccess = await request("GET", "/api/support/request-access", null, {
      headers: authHeader("invalid-token"),
    });
    assertDenied(invalidRequestAccess, "invalid token request-access queue");

    for (const [label, token] of [
      ["licensee A", tokens.licenseeAdminA],
      ["manufacturer A", tokens.manufacturerA],
    ]) {
      const deniedQueue = await request("GET", "/api/support/request-access", null, { headers: authHeader(token) });
      assertDenied(deniedQueue, `${label} request-access queue`);
      assertNoLeak(deniedQueue, "request-a@tenant-a.test", `${label} request-access queue`);
      assertNoLeak(deniedQueue, "request-b@tenant-b.test", `${label} request-access queue`);
      assertNoLeak(deniedQueue, "request-access-internal", `${label} request-access queue`);
    }

    const platformRequestAccess = await request("GET", "/api/support/request-access", null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(platformRequestAccess.status, 200, platformRequestAccess.text);
    assert.match(platformRequestAccess.text, /request-a@tenant-a\.test/);
    assert.match(platformRequestAccess.text, /request-b@tenant-b\.test/);
    assertSafeResponse(platformRequestAccess, "platform request-access queue");

    const platformPatchRequestAccess = await request(
      "PATCH",
      "/api/support/request-access/00000000-0000-4202-9400-000000000001",
      { status: "CONTACTED", internalNote: "Phase E2 reviewed" },
      { headers: authHeader(tokens.superAdmin) }
    );
    assert.strictEqual(platformPatchRequestAccess.status, 200, platformPatchRequestAccess.text);
    const requestAccessAudit = await prisma.auditLog.findFirst({
      where: {
        userId: ids.superAdmin,
        entityType: "RequestAccess",
        entityId: "00000000-0000-4202-9400-000000000001",
        action: "REQUEST_ACCESS_UPDATED",
      },
    });
    assert(requestAccessAudit, "platform request-access mutation was not audited");

    const manufacturerReports = await request("GET", "/api/support/reports", null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.strictEqual(manufacturerReports.status, 200, manufacturerReports.text);
    assert.match(manufacturerReports.text, /P2 Report A/);
    assertNoLeak(manufacturerReports, "P2 Report B", "manufacturer A support reports");
    assertNoLeak(manufacturerReports, "support-internal-note-a", "manufacturer A support reports");
    assertNoLeak(manufacturerReports, "smtp-internal-error-a", "manufacturer A support reports");
    assertNoLeak(manufacturerReports, "public-b@mscqr.test", "manufacturer A support reports");
    assertSafeResponse(manufacturerReports, "manufacturer A support reports");

    const platformScopedReports = await request("GET", `/api/support/reports?licenseeId=${ids.licenseeA}`, null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(platformScopedReports.status, 200, platformScopedReports.text);
    assert.match(platformScopedReports.text, /P2 Report A/);
    assert.match(platformScopedReports.text, /support-internal-note-a/);
    assertNoLeak(platformScopedReports, "P2 Report B", "platform scoped support reports");
    assertSafeResponse(platformScopedReports, "platform scoped support reports");

    const manufacturerRespondReport = await request(
      "POST",
      `/api/support/reports/${ids.supportReportB}/respond`,
      { message: "A lower role must not respond to another tenant report." },
      { headers: authHeader(tokens.manufacturerA) }
    );
    assertDenied(manufacturerRespondReport, "manufacturer responds to support report B");
    assertNoLeak(manufacturerRespondReport, "support-internal-note-b", "manufacturer responds to support report B");

    const platformRespondReport = await request(
      "POST",
      `/api/support/reports/${ids.supportReportA}/respond`,
      { message: "Phase E2 platform support response.", status: "RESPONDED" },
      { headers: authHeader(tokens.superAdmin) }
    );
    assert.strictEqual(platformRespondReport.status, 200, platformRespondReport.text);
    assert.match(platformRespondReport.text, /Phase E2 platform support response/);
    assertSafeResponse(platformRespondReport, "platform support report response");

    const licenseeIncidentPatchB = await request(
      "PATCH",
      `/api/incidents/${ids.incidentB}`,
      { status: "TRIAGED" },
      { headers: authHeader(tokens.licenseeAdminA) }
    );
    assertDenied(licenseeIncidentPatchB, "licensee A incident B patch");
    assertNoLeak(licenseeIncidentPatchB, "P2 Tenant B suspicious scan", "licensee A incident B patch");

    const licenseeIncidentExportB = await request("GET", `/api/incidents/${ids.incidentB}/export-pdf`, null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(licenseeIncidentExportB, "licensee A incident B export");
    assertNoLeak(licenseeIncidentExportB, "P2B000001", "licensee A incident B export");

    const licenseeAuditExport = await request("GET", "/api/audit/logs/export?limit=50", null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assert.strictEqual(licenseeAuditExport.status, 200, licenseeAuditExport.text);
    assert.match(licenseeAuditExport.headers.get("content-type") || "", /text\/csv/i);
    assertNoLeak({ text: licenseeAuditExport.headers.get("content-disposition") || "" }, "tenant-b", "audit export filename");
    const licenseeAuditRows = parseCsv(licenseeAuditExport.text);
    assert(licenseeAuditRows.some((row) => JSON.stringify(row).includes("audit-tenant-a-marker")), "licensee A audit export omitted tenant A row");
    assertNoLeak(licenseeAuditExport, "audit-tenant-b-marker", "licensee A audit export");
    assertNoLeak(licenseeAuditExport, "p2-licensee-b@mscqr.test", "licensee A audit export");
    assertSafeResponse(licenseeAuditExport, "licensee A audit export");

    const platformAuditExportA = await request("GET", `/api/audit/logs/export?licenseeId=${ids.licenseeA}&limit=50`, null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(platformAuditExportA.status, 200, platformAuditExportA.text);
    assert.match(platformAuditExportA.text, /audit-tenant-a-marker/);
    assertNoLeak(platformAuditExportA, "audit-tenant-b-marker", "platform scoped audit export");
    assertNoLeak(platformAuditExportA, "P2 Batch B", "platform scoped audit export");

    const printJobsA = await request("GET", "/api/manufacturer/print-jobs", null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.strictEqual(printJobsA.status, 200, printJobsA.text);
    assert.match(printJobsA.text, /P2-PRINT-A/);
    assertNoLeak(printJobsA, "P2-PRINT-B", "manufacturer A print jobs");
    assertNoLeak(printJobsA, "P2B000001", "manufacturer A print jobs");

    const printJobBTamper = await request("GET", `/api/manufacturer/print-jobs/${ids.printJobB}`, null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assertDenied(printJobBTamper, "manufacturer A print job B");
    assertNoLeak(printJobBTamper, "P2-PRINT-B", "manufacturer A print job B");
    assertNoLeak(printJobBTamper, "p2-pack-b-hash", "manufacturer A print job B");

    const directPrintOwnDisabled = await request(
      "POST",
      `/api/manufacturer/print-jobs/${ids.printJobA}/direct-print/tokens`,
      { printLockToken: "phase-e2-lock-token", count: 1 },
      { headers: authHeader(tokens.manufacturerA) }
    );
    assert.strictEqual(directPrintOwnDisabled.status, 410, directPrintOwnDisabled.text);
    assert.match(directPrintOwnDisabled.text, /Browser-mediated direct printing has been disabled/i);
    assertNoLeak(directPrintOwnDisabled, "renderToken", "manufacturer A direct-print disabled");
    assertSafeResponse(directPrintOwnDisabled, "manufacturer A direct-print disabled");

    const licenseeDirectPrintDenied = await request(
      "POST",
      `/api/manufacturer/print-jobs/${ids.printJobA}/direct-print/tokens`,
      { printLockToken: "phase-e2-lock-token", count: 1 },
      { headers: authHeader(tokens.licenseeAdminA) }
    );
    assertDenied(licenseeDirectPrintDenied, "licensee direct-print token route");
    assertNoLeak(licenseeDirectPrintDenied, "P2A000001", "licensee direct-print token route");

    const localAgentClaimMissingAuth = await request("POST", "/api/printer-agent/local/claim", { max: 1 });
    assert(
      [400, 401].includes(localAgentClaimMissingAuth.status),
      `local printer-agent claim without signature: expected malformed/auth denial, got ${localAgentClaimMissingAuth.status} ${localAgentClaimMissingAuth.text}`
    );
    assertSafeResponse(localAgentClaimMissingAuth, "local printer-agent claim without signature");
    assertNoLeak(localAgentClaimMissingAuth, "P2-PRINT-A", "local printer-agent claim without signature");
    assertNoLeak(localAgentClaimMissingAuth, "P2-PRINT-B", "local printer-agent claim without signature");

    await prisma.user.update({
      where: { id: ids.manufacturerA },
      data: { isActive: false, status: "DISABLED", disabledAt: new Date() },
    });
    const inactiveManufacturer = await request("GET", "/api/qr/batches", null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.strictEqual(inactiveManufacturer.status, 401, inactiveManufacturer.text);
    assertSafeResponse(inactiveManufacturer, "inactive manufacturer token");

    await prisma.user.update({
      where: { id: ids.manufacturerA },
      data: { isActive: true, status: "ACTIVE", disabledAt: null },
    });
    await prisma.user.update({
      where: { id: ids.licenseeAdminA },
      data: { role: "MANUFACTURER" },
    });
    const downgradedRole = await request("GET", `/api/users?licenseeId=${ids.licenseeA}`, null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(downgradedRole, "role downgrade takes effect");
    assertNoLeak(downgradedRole, "p2-licensee-b", "role downgrade takes effect");
  });

  console.log("phase E2 role, tenant, IDOR, export, printer, and support tests passed");
})().catch((error) => {
  if (error instanceof P2TestDbSkip) {
    const message = `phase E2 DB-backed authorization tests skipped: ${error.message}`;
    if (String(process.env.P2_TEST_DATABASE_REQUIRED || "").trim().toLowerCase() === "true") {
      console.error(`${message} P2_TEST_DATABASE_REQUIRED=true forbids skipping.`);
      process.exit(1);
    }
    console.log(message);
    process.exit(0);
  }
  console.error(error);
  process.exit(1);
});
