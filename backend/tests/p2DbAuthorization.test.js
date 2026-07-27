const assert = require("assert");
const fs = require("fs");
const path = require("path");
const JSZip = require("jszip");
const { P2TestDbSkip, withP2TestApp } = require("./helpers/p2TestDb");
const { emails, ids, issueBearerTokens, passwords, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const authHeader = (token) => ({
  authorization: `Bearer ${token.accessToken}`,
  "x-database-session-capability": token.databaseCapability,
});
const deniedStatuses = new Set([401, 403, 404, 410, 428]);

const assertDenied = (response, label) => {
  assert(deniedStatuses.has(response.status), `${label}: expected safe denial, got ${response.status} ${response.text}`);
  assertSafeResponse(response, label);
};

const assertSafeResponse = (response, label) => {
  const text = response.text || "";
  assert.doesNotMatch(
    text,
    /DATABASE_URL|JWT_SECRET|QR_SIGN_HMAC_SECRET|AUTH_COOKIE_SECRET_CURRENT|passwordHash|tokenHash|Bearer\s+[A-Za-z0-9._-]+|PrismaClientKnownRequestError|at\s+\S+\s+\(/i,
    `${label}: leaked backend internals`
  );
};

const assertNoCrossTenantLeak = (response, forbiddenMarker, label) => {
  assert.doesNotMatch(response.text || "", new RegExp(forbiddenMarker, "i"), `${label}: leaked ${forbiddenMarker}`);
};

(async () => {
  await withP2TestApp(async ({ baseUrl, request, prisma, preauthPrisma }) => {
    const fixtures = await seedP2Fixtures(prisma);
    const tokens = await issueBearerTokens(preauthPrisma);

    const loginOk = await request("POST", "/api/auth/login", {
      email: emails.manufacturerA,
      password: passwords.manufacturerA,
    });
    assert.strictEqual(loginOk.status, 200, loginOk.text);
    assert.match(loginOk.text, /MANUFACTURER/i);
    assertSafeResponse(loginOk, "manufacturer login");

    const loginBad = await request("POST", "/api/auth/login", {
      email: emails.manufacturerA,
      password: "wrong-password",
    });
    assert.strictEqual(loginBad.status, 401, loginBad.text);
    assert.match(loginBad.text, /Invalid email or password/i);
    assertSafeResponse(loginBad, "invalid login");

    const anonymousMe = await request("GET", "/api/auth/me", null);
    assert.strictEqual(anonymousMe.status, 401, anonymousMe.text);
    assertSafeResponse(anonymousMe, "anonymous /auth/me");

    const invalidToken = await request("GET", "/api/auth/me", null, { headers: authHeader("not-a-real-token") });
    assert.strictEqual(invalidToken.status, 401, invalidToken.text);
    assertSafeResponse(invalidToken, "invalid token /auth/me");

    const me = await request("GET", "/api/auth/me", null, { headers: authHeader(tokens.licenseeAdminA) });
    assert.strictEqual(me.status, 200, me.text);
    assert.match(me.text, /p2-licensee-a@mscqr\.test/i);
    assertNoCrossTenantLeak(me, "p2-licensee-b", "licensee A /auth/me");

    const batchesA = await request("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminA) });
    assert.strictEqual(batchesA.status, 200, batchesA.text);
    assert.match(batchesA.text, /P2 Batch A/);
    assertNoCrossTenantLeak(batchesA, "P2 Batch B", "licensee A batch list");

    const manufacturerBatchesA = await request("GET", "/api/qr/batches", null, { headers: authHeader(tokens.manufacturerA) });
    assert.strictEqual(manufacturerBatchesA.status, 200, manufacturerBatchesA.text);
    assert.match(manufacturerBatchesA.text, /P2 Batch A/);
    assertNoCrossTenantLeak(manufacturerBatchesA, "P2 Batch B", "manufacturer A batch list");

    const tamperedBatchQuery = await request("GET", `/api/qr/batches?licenseeId=${ids.licenseeB}`, null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(tamperedBatchQuery, "licensee A tampered batch query");
    assertNoCrossTenantLeak(tamperedBatchQuery, "P2 Batch B", "licensee A tampered batch query");

    const renameOtherTenantBatch = await request("PATCH", `/api/qr/batches/${ids.batchB}/rename`, { name: "P2 Leaked Rename" }, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(renameOtherTenantBatch, "licensee A rename tenant B batch");
    const untouchedBatchB = await prisma.batch.findUnique({ where: { id: ids.batchB }, select: { name: true } });
    assert.strictEqual(untouchedBatchB.name, "P2 Batch B", "cross-tenant batch mutation changed tenant B data");

    const manufacturerExportDenied = await request("GET", "/api/qr/codes/export", null, { headers: authHeader(tokens.manufacturerA) });
    assertDenied(manufacturerExportDenied, "manufacturer QR export");
    assertNoCrossTenantLeak(manufacturerExportDenied, "P2B000001", "manufacturer QR export denial");

    const licenseeExportDenied = await request("GET", "/api/qr/codes/export", null, { headers: authHeader(tokens.licenseeAdminA) });
    assertDenied(licenseeExportDenied, "licensee QR export");
    assertNoCrossTenantLeak(licenseeExportDenied, "P2B000001", "licensee QR export denial");

    const scopedQrExport = await request("GET", `/api/qr/codes/export?licenseeId=${ids.licenseeA}`, null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(scopedQrExport.status, 200, scopedQrExport.text);
    assert.match(scopedQrExport.text, /P2A000001/);
    assertNoCrossTenantLeak(scopedQrExport, "P2B000001", "super admin scoped QR export");
    assertNoCrossTenantLeak(scopedQrExport, "P2 Brand B", "super admin scoped QR export");

    const signedScan = await request("GET", `/api/scan?t=${encodeURIComponent(fixtures.signedScanTokenA)}`, null);
    assert.strictEqual(signedScan.status, 200, signedScan.text);
    assert.match(signedScan.text, /P2A000001|SIGNED_LABEL|authentic|verified/i);
    assertNoCrossTenantLeak(signedScan, "P2B000001", "signed scan token");
    assertSafeResponse(signedScan, "signed scan token");

    const supportAsManufacturer = await request("GET", "/api/support/tickets", null, { headers: authHeader(tokens.manufacturerA) });
    assertDenied(supportAsManufacturer, "manufacturer support tickets");
    assertNoCrossTenantLeak(supportAsManufacturer, "P2 Support B", "manufacturer support tickets");

    const unscopedSupportAsAdmin = await request("GET", "/api/support/tickets", null, {
      headers: authHeader(tokens.superAdmin),
    });
    assertDenied(unscopedSupportAsAdmin, "platform support tickets without a licensee selector");

    const supportAsAdmin = await request("GET", `/api/support/tickets?licenseeId=${ids.licenseeA}`, null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(supportAsAdmin.status, 200, supportAsAdmin.text);
    assert.match(supportAsAdmin.text, /P2 Support A/);
    assertNoCrossTenantLeak(supportAsAdmin, "P2 Support B", "platform scoped support ticket denial");
    assertSafeResponse(supportAsAdmin, "platform support tickets");

    const incidentsA = await request("GET", "/api/incidents", null, { headers: authHeader(tokens.licenseeAdminA) });
    assert.strictEqual(incidentsA.status, 200, incidentsA.text);
    assert.match(incidentsA.text, /P2 Tenant A suspicious scan/);
    assertNoCrossTenantLeak(incidentsA, "P2 Tenant B suspicious scan", "licensee A incidents");

    const incidentTamper = await request("GET", `/api/incidents/${ids.incidentB}`, null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(incidentTamper, "licensee A incident B IDOR");
    assertNoCrossTenantLeak(incidentTamper, "P2 Tenant B suspicious scan", "licensee A incident B IDOR");

    const featureFlagsDenied = await request("GET", "/api/governance/feature-flags", null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assertDenied(featureFlagsDenied, "manufacturer governance feature flags");
    assertNoCrossTenantLeak(featureFlagsDenied, "p2-governance-b", "manufacturer governance feature flags");

    const featureFlagsAdmin = await request("GET", `/api/governance/feature-flags?licenseeId=${ids.licenseeA}`, null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(featureFlagsAdmin.status, 200, featureFlagsAdmin.text);
    assert.match(featureFlagsAdmin.text, /p2-governance-a/i);
    assertNoCrossTenantLeak(featureFlagsAdmin, "p2-governance-b", "licensee A governance feature flags");

    const complianceDownloadTamper = await request("GET", `/api/governance/compliance/pack/jobs/${ids.complianceJobB}/download`, null, {
      headers: authHeader(tokens.licenseeAdminA),
    });
    assertDenied(complianceDownloadTamper, "licensee A compliance pack B download");
    assertNoCrossTenantLeak(complianceDownloadTamper, "p2-b-pack", "licensee A compliance pack B download");

    const ownComplianceDownload = await fetch(`${baseUrl}/api/governance/compliance/pack/jobs/${ids.complianceJobA}/download`, {
      headers: authHeader(tokens.superAdmin),
    });
    const ownComplianceBytes = Buffer.from(await ownComplianceDownload.arrayBuffer());
    assert.strictEqual(ownComplianceDownload.status, 200, ownComplianceBytes.toString("utf8"));
    assert.match(ownComplianceDownload.headers.get("content-type") || "", /application\/zip/i);
    const ownComplianceZip = await JSZip.loadAsync(ownComplianceBytes);
    const integrity = JSON.parse(await ownComplianceZip.file("integrity.json").async("string"));
    assert.strictEqual(integrity.licenseeId, ids.licenseeA, "platform admin compliance pack integrity licensee scope");
    assert.notStrictEqual(integrity.licenseeId, ids.licenseeB, "platform admin compliance pack leaked tenant B scope");
    assert(ownComplianceZip.file("compliance-report.json"), "platform admin compliance pack missing compliance-report.json");
    assert(ownComplianceZip.file("controls-map.json"), "platform admin compliance pack missing controls-map.json");
    assert(ownComplianceZip.file("evidence-map.json"), "platform admin compliance pack missing evidence-map.json");
    assertSafeResponse({ text: ownComplianceBytes.toString("latin1") }, "platform admin compliance pack download");
    for (const fileName of ["p2-a-pack.zip", "p2-b-pack.zip"]) {
      const localPackPath = path.resolve(__dirname, "../uploads/compliance-packs", path.basename(fileName));
      if (fs.existsSync(localPackPath)) fs.rmSync(localPackPath, { force: true });
    }

    const ownPrintPack = await request("GET", `/api/manufacturer/print-jobs/${ids.printJobA}/pack`, null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert.strictEqual(ownPrintPack.status, 410, ownPrintPack.text);
    assert.match(ownPrintPack.text, /Print-pack download is disabled/i);
    assertNoCrossTenantLeak(ownPrintPack, "P2B000001", "manufacturer A own disabled print pack");
    assertSafeResponse(ownPrintPack, "manufacturer A own disabled print pack");

    const crossTenantPrintPack = await request("GET", `/api/manufacturer/print-jobs/${ids.printJobB}/pack`, null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assertDenied(crossTenantPrintPack, "manufacturer A print pack B");
    assertNoCrossTenantLeak(crossTenantPrintPack, "P2B000001", "manufacturer A print pack B");
    assertNoCrossTenantLeak(crossTenantPrintPack, "p2-pack-b-hash", "manufacturer A print pack B");
  });

  console.log("p2 DB-backed authorization and content tests passed");
})().catch((error) => {
  if (error instanceof P2TestDbSkip) {
    const message = `p2 DB-backed authorization tests skipped: ${error.message}`;
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
