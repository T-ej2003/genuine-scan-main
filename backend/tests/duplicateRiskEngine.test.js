const { assessDuplicateRisk } = require("../dist/services/duplicateRiskService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const repeatOnly = assessDuplicateRisk({
    scanCount: 4,
    scanSignals: {
      distinctDeviceCount24h: 1,
      recentScanCount10m: 2,
      distinctCountryCount24h: 1,
      seenOnCurrentDeviceBefore: true,
      previousScanSameDevice: true,
    },
    customerUserId: "cust_123",
    ownershipStatus: {
      isClaimed: true,
      isOwnedByRequester: true,
      isClaimedByAnother: false,
      matchMethod: "user",
    },
    latestScanAt: "2026-02-28T10:15:00.000Z",
    previousScanAt: "2026-02-28T09:50:00.000Z",
  });
  assert(
    repeatOnly.classification === "LEGIT_REPEAT",
    "Expected normal 4x repeat scans on same trusted context to remain LEGIT_REPEAT"
  );

  const countOnly = assessDuplicateRisk({
    scanCount: 12,
    scanSignals: {
      distinctDeviceCount24h: 1,
      recentScanCount10m: 1,
      distinctCountryCount24h: 1,
      seenOnCurrentDeviceBefore: true,
      previousScanSameDevice: true,
    },
  });
  assert(countOnly.classification === "LEGIT_REPEAT", "High scan count alone must not force suspicious classification");

  const suspiciousComposite = assessDuplicateRisk({
    scanCount: 5,
    scanSignals: {
      distinctDeviceCount24h: 3,
      recentScanCount10m: 6,
      distinctCountryCount24h: 2,
      seenOnCurrentDeviceBefore: false,
      previousScanSameDevice: false,
    },
    policy: {
      triggered: {
        multiScan: true,
        geoDrift: true,
        velocitySpike: true,
      },
      alerts: [{ message: "Policy engine flagged rapid multi-device activity." }],
    },
    latestScanAt: "2026-02-28T10:15:00.000Z",
    previousScanAt: "2026-02-28T10:00:00.000Z",
  });
  assert(
    suspiciousComposite.classification === "SUSPICIOUS_DUPLICATE",
    "Expected composite anomaly pattern to be classified as suspicious"
  );
  assert(suspiciousComposite.riskScore >= 60, "Suspicious composite should have elevated risk score");

  const ownershipConflict = assessDuplicateRisk({
    scanCount: 2,
    scanSignals: {
      distinctDeviceCount24h: 1,
      recentScanCount10m: 1,
      distinctCountryCount24h: 1,
    },
    ownershipStatus: {
      isClaimed: true,
      isOwnedByRequester: false,
      isClaimedByAnother: true,
    },
    customerUserId: "cust_new",
  });
  assert(ownershipConflict.classification === "SUSPICIOUS_DUPLICATE", "Ownership conflict should be suspicious");

  console.log("duplicate risk engine tests passed");
};

run();
