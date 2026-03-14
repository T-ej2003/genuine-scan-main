const assert = require("assert");
const path = require("path");
const { QRStatus } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const baseTimeMs = Date.parse("2026-03-14T12:00:00.000Z");
let nowMs = baseTimeMs;
const realDateNow = Date.now;
Date.now = () => nowMs;

const licensee = {
  id: "lic-1",
  name: "MSCQR Demo",
  prefix: "MSC",
};

const batch = {
  id: "batch-1",
  name: "Batch 1",
  printedAt: new Date("2026-03-14T11:30:00.000Z"),
  manufacturer: {
    id: "manufacturer-1",
    name: "Demo Manufacturer",
    email: "ops@example.com",
    location: "London",
    website: "https://example.com",
  },
};

const qrState = {
  id: "qr-1",
  code: "MSC0001",
  status: QRStatus.PRINTED,
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: null,
  redeemedAt: null,
  scanCount: 0,
  lastScanIp: null,
  lastScanUserAgent: null,
  lastScanDevice: null,
  licensee,
  batch,
};

const scanLogs = [];

const fakePrisma = {
  qRCode: {
    findUnique: async ({ where }) => {
      if (where.code !== qrState.code) return null;
      return {
        ...qrState,
      };
    },
  },
  $transaction: async (callback) =>
    callback({
      qRCode: {
        update: async ({ data }) => {
          qrState.status = data.status || qrState.status;
          qrState.scannedAt = data.scannedAt || qrState.scannedAt;
          qrState.redeemedAt = data.redeemedAt || qrState.redeemedAt;
          qrState.lastScanIp = data.lastScanIp ?? qrState.lastScanIp;
          qrState.lastScanUserAgent = data.lastScanUserAgent ?? qrState.lastScanUserAgent;
          qrState.lastScanDevice = data.lastScanDevice ?? qrState.lastScanDevice;
          qrState.scanCount += Number(data.scanCount?.increment || 0);
          return {
            ...qrState,
          };
        },
      },
      qrScanLog: {
        findFirst: async () => {
          const latest = scanLogs[scanLogs.length - 1];
          return latest ? { ...latest } : null;
        },
        create: async ({ data }) => {
          scanLogs.push({
            ...data,
            id: `log-${scanLogs.length + 1}`,
            scannedAt: new Date(Date.now()),
          });
          return scanLogs[scanLogs.length - 1];
        },
      },
    }),
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("utils/prismaStorageGuard.js", {
  warnStorageUnavailableOnce: () => {},
});

const { recordScan } = require("../dist/services/qrService");

(async () => {
  const first = await recordScan("MSC0001", {
    ipAddress: "198.51.100.14",
    userAgent: "Chrome on Android",
    device: "device-1",
  });

  assert.strictEqual(first.isFirstScan, true, "first scan should still count as a first scan");
  assert.strictEqual(first.scanRecorded, true, "first scan should be recorded");
  assert.strictEqual(first.qrCode.scanCount, 1, "first scan should increment scan count");
  assert.strictEqual(scanLogs.length, 1, "first scan should create one scan log");

  nowMs = baseTimeMs + 30_000;
  const refresh = await recordScan("MSC0001", {
    ipAddress: "198.51.100.14",
    userAgent: "Chrome on Android",
    device: "device-1",
  });

  assert.strictEqual(refresh.isFirstScan, true, "same-device refresh should preserve the first-scan result");
  assert.strictEqual(refresh.scanRecorded, false, "same-device refresh should not create a new scan event");
  assert.strictEqual(refresh.qrCode.scanCount, 1, "same-device refresh should not increment scan count");
  assert.strictEqual(scanLogs.length, 1, "same-device refresh should not create a second scan log");

  nowMs = baseTimeMs + 45_000;
  const trustedOwnerScan = await recordScan("MSC0001", {
    ipAddress: "198.51.100.14",
    userAgent: "Chrome on Android",
    device: "device-1",
    customerUserId: "cust-123",
    ownershipId: "ownership-1",
    ownershipMatchMethod: "device_token",
    isTrustedOwnerContext: true,
  });

  assert.strictEqual(trustedOwnerScan.isFirstScan, false, "a later owner-linked scan should be treated as a repeat");
  assert.strictEqual(trustedOwnerScan.scanRecorded, true, "changing to a trusted owner context should create a new scan event");
  assert.strictEqual(trustedOwnerScan.qrCode.scanCount, 2, "trusted owner scan should increment scan count");
  assert.strictEqual(scanLogs.length, 2, "trusted owner scan should create a second scan log");

  console.log("qr scan refresh dedupe tests passed");
})()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    Date.now = realDateNow;
  });
