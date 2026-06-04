const assert = require("assert");
const { QRStatus } = require("@prisma/client");
const { request, state, withServer } = require("./helpers/p1TestApp");
const { hashToken, signQrPayload } = require("../dist/services/qrTokenService");

const qr = state.qrCodes.find((entry) => entry.id === "p1-qr-a");
assert(qr, "P1 signed scan QR fixture missing");

const buildToken = (overrides = {}) => {
  const token = signQrPayload({
    qr_id: qr.id,
    batch_id: qr.batchId,
    licensee_id: qr.licenseeId,
    manufacturer_id: qr.batch?.manufacturer?.id || null,
    epoch: Number(qr.replayEpoch || 1),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: qr.tokenNonce || "p1-scan-nonce",
    ...overrides,
  });
  return token;
};

const prepareQr = (overrides = {}) => {
  Object.assign(qr, {
    status: QRStatus.PRINTED,
    tokenNonce: "p1-scan-nonce",
    replayEpoch: 1,
    tokenHash: null,
    issuanceMode: "GOVERNED_PRINT",
    customerVerifiableAt: new Date(),
    signedFirstSeenAt: null,
    lastSignedVerificationAt: null,
    lastSignedVerificationIpHash: null,
    lastSignedVerificationDeviceHash: null,
    underInvestigationAt: null,
    underInvestigationReason: null,
    printJobId: null,
    printJob: null,
    ...overrides,
  });
  const token = buildToken();
  qr.tokenHash = hashToken(token);
  return token;
};

const assertSafePublicPayload = ({ text }) => {
  assert.doesNotMatch(text, /tokenHash|passwordHash|JWT|Bearer|p1-licensee-b|P1 Brand B|stack|Prisma|DATABASE_URL|secret/i);
};

(async () => {
  await withServer(async (baseUrl) => {
    const validToken = prepareQr();
    const valid = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(validToken)}`, null);
    assert.strictEqual(valid.status, 200, valid.text);
    assert.strictEqual(valid.payload.success, true);
    assertSafePublicPayload(valid);
    assert.match(valid.text, /SIGNED_LABEL|P1A000001|authentic|active|verified/i);

    const expiredToken = prepareQr({
      tokenNonce: "p1-expired-nonce",
    });
    const expiredPayload = signQrPayload({
      qr_id: qr.id,
      batch_id: qr.batchId,
      licensee_id: qr.licenseeId,
      manufacturer_id: qr.batch?.manufacturer?.id || null,
      epoch: 1,
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600,
      nonce: qr.tokenNonce,
    });
    qr.tokenHash = hashToken(expiredPayload);
    const expired = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(expiredPayload)}`, null);
    assert.strictEqual(expired.status, 400, expired.text);
    assert.match(expired.text, /expired/i);
    assertSafePublicPayload(expired);

    const tampered = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(`${expiredToken.slice(0, -2)}xx`)}`, null);
    assert.strictEqual(tampered.status, 400, tampered.text);
    assert.match(tampered.text, /Invalid|tampered|signature/i);
    assertSafePublicPayload(tampered);

    const missing = await request(baseUrl, "GET", "/api/scan", null);
    assert.strictEqual(missing.status, 400, missing.text);
    assertSafePublicPayload(missing);

    const revokedToken = prepareQr({ tokenNonce: "p1-revoked-nonce" });
    qr.tokenHash = hashToken("different-issued-token");
    const revoked = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(revokedToken)}`, null);
    assert.strictEqual(revoked.status, 400, revoked.text);
    assert.match(revoked.text, /revoked|mismatch|invalid/i);
    assertSafePublicPayload(revoked);

    const missingQrToken = buildToken({ qr_id: "p1-missing-qr", nonce: "p1-missing-nonce" });
    const notFound = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(missingQrToken)}`, null);
    assert.strictEqual(notFound.status, 404, notFound.text);
    assert.match(notFound.text, /not found|registry/i);
    assertSafePublicPayload(notFound);

    state.scan.deviceFingerprint = "p1-device-b";
    state.scan.insight = {
      firstScanAt: "2026-06-01T10:00:00.000Z",
      firstScanLocation: "London",
      latestScanAt: "2026-06-01T10:03:00.000Z",
      latestScanLocation: "Paris",
      previousScanAt: "2026-06-01T10:01:00.000Z",
      previousScanLocation: "London",
      signals: {
        scanCount24h: 3,
        distinctDeviceCount24h: 2,
        recentScanCount10m: 3,
        distinctCountryCount24h: 2,
        seenOnCurrentDeviceBefore: false,
        previousScanSameDevice: false,
        currentActorTrustedOwnerContext: false,
        seenByCurrentTrustedActorBefore: false,
        previousScanSameTrustedActor: null,
        trustedOwnerScanCount24h: 0,
        trustedOwnerScanCount10m: 0,
        untrustedScanCount24h: 3,
        untrustedScanCount10m: 3,
        distinctTrustedActorCount24h: 0,
        distinctUntrustedDeviceCount24h: 2,
        distinctUntrustedCountryCount24h: 2,
        ipVelocityCount10m: 3,
        ipReputationScore: 0,
        deviceGraphOverlap24h: 1,
        crossCodeCorrelation24h: 1,
      },
    };
    state.scan.duplicateRisk = {
      classification: "SUSPICIOUS_DUPLICATE",
      reasons: ["The label was scanned from a different scan context unusually quickly."],
      riskScore: 82,
      threshold: 65,
      signals: state.scan.insight.signals,
      activitySummary: null,
    };
    const suspiciousToken = prepareQr({
      status: QRStatus.REDEEMED,
      scanCount: 2,
      scannedAt: new Date("2026-06-01T10:01:00.000Z"),
      redeemedAt: new Date("2026-06-01T10:01:00.000Z"),
    });
    const suspicious = await request(baseUrl, "GET", `/api/scan?t=${encodeURIComponent(suspiciousToken)}`, null);
    assert.strictEqual(suspicious.status, 200, suspicious.text);
    assert.match(suspicious.text, /SUSPICIOUS_DUPLICATE|REVIEW_REQUIRED|different scan context/i);
    assertSafePublicPayload(suspicious);
  });

  console.log("p1 signed scan-token integration test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
