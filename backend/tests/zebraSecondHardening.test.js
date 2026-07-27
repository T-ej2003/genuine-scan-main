const {
  canRotateLegacyQrCode,
  explainLegacyQrRotationBlock,
  isLegacyPublicCode,
  serializeLegacyQrReportCsv,
} = require("../dist/services/legacyQrRotationService");
const {
  calculateRequiredSampleScans,
  evaluateSampleScanPolicy,
  normalizeSampleScanPolicy,
} = require("../dist/services/sampleScanPolicyService");
const {
  extractPublicCodeFromSampleScan,
  sampleScanBelongsToPrintJob,
} = require("../dist/services/printSampleScanService");
const {
  canConfigurePrinterNetworkEndpoint,
} = require("../dist/controllers/printerController");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const safeLegacyQr = {
  id: "qr-safe",
  code: "MSCQR-WIFI-DEMO-001-000001",
  displayCode: null,
  status: "ALLOCATED",
  batchId: "batch-1",
  printJobId: null,
  scannedAt: null,
  scanCount: 0,
  printedAt: null,
  redeemedAt: null,
  tokenIssuedAt: null,
  customerVerifiableAt: null,
  signedFirstSeenAt: null,
  lastSignedVerificationAt: null,
  batch: {
    printedAt: null,
    printPackDownloadedAt: null,
  },
};

const run = async () => {
  assert(isLegacyPublicCode("MSCQR-WIFI-DEMO-001-000001"), "predictable public codes should be detected as legacy");
  assert(!isLegacyPublicCode("c_secureOpaqueCode"), "c_ public codes should not be reported as legacy");

  assert(canRotateLegacyQrCode(safeLegacyQr), "unprinted, unscanned, unexposed legacy QR should be rotatable");

  const printedReasons = explainLegacyQrRotationBlock({
    ...safeLegacyQr,
    id: "qr-printed",
    printedAt: new Date(),
  });
  assert(printedReasons.includes("printed_at_present"), "printed legacy QR must not rotate");

  const scannedReasons = explainLegacyQrRotationBlock({
    ...safeLegacyQr,
    id: "qr-scanned",
    scannedAt: new Date(),
    scanCount: 1,
  });
  assert(scannedReasons.includes("scanned_at_present"), "scanned legacy QR must not rotate");
  assert(scannedReasons.includes("scan_count_present"), "legacy QR with scan count must not rotate");

  const releasedReasons = explainLegacyQrRotationBlock({
    ...safeLegacyQr,
    id: "qr-released",
    batch: {
      ...safeLegacyQr.batch,
      lifecycleState: "RELEASED",
      releasedAt: new Date(),
    },
  });
  assert(releasedReasons.includes("batch_released"), "released batch legacy QR must not rotate");

  const exposedReasons = explainLegacyQrRotationBlock(safeLegacyQr, {
    scanLogs: 0,
    verificationDecisions: 1,
    auditEvents: 0,
    printAuditEvents: 0,
  });
  assert(exposedReasons.includes("verification_decision_exists"), "externally verified QR must not rotate");

  assert(
    sampleScanBelongsToPrintJob({ printJobId: "job-1", qrPrintJobId: "job-1" }),
    "sample scan should pass when QR is linked to the print job"
  );
  assert(
    sampleScanBelongsToPrintJob({ printJobId: "job-1", printItemSessionJobId: "job-1" }),
    "sample scan should pass when print item session is linked to the print job"
  );
  assert(
    !sampleScanBelongsToPrintJob({ printJobId: "job-1", qrPrintJobId: "job-2", printItemSessionJobId: "job-2" }),
    "wrong sample scan must be rejected"
  );
  assert(
    extractPublicCodeFromSampleScan("https://app.mscqr.test/verify/c_exactCode?utm=x") === "c_exactCode",
    "sample scan should extract exact public code from verify URL"
  );
  assert(
    extractPublicCodeFromSampleScan(" c_rawExactCode ") === "c_rawExactCode",
    "sample scan should accept raw public code with trim only"
  );

  assert(
    calculateRequiredSampleScans(normalizeSampleScanPolicy({ type: "ONE_PER_N_LABELS", n: 50 }), 101) === 3,
    "one-per-N sample policy should require ceiling(quantity / n)"
  );
  assert(
    calculateRequiredSampleScans(normalizeSampleScanPolicy({ type: "PERCENTAGE", percentage: 2, min: 2 }), 120) === 3,
    "percentage sample policy should honor percentage and minimum quorum"
  );
  const duplicateScanPolicy = await evaluateSampleScanPolicy({
    batchId: "batch-1",
    printJobId: "job-1",
    policy: { type: "ONE_PER_N_LABELS", n: 1 },
    quantity: 2,
    tx: {
      qRCode: { count: async () => 2 },
      printAuditEvent: {
        findMany: async () => [
          { batchId: "batch-1", printJobId: "job-1", eventType: "sample_scan_verified", qrCodeId: "qr-1" },
          { batchId: "batch-1", printJobId: "job-1", eventType: "sample_scan_verified", qrCodeId: "qr-1" },
          { batchId: "batch-2", printJobId: "job-1", eventType: "sample_scan_verified", qrCodeId: "qr-2" },
          { batchId: "batch-1", printJobId: "job-2", eventType: "sample_scan_verified", qrCodeId: "qr-3" },
          { batchId: "batch-1", printJobId: "job-1", eventType: "sample_scan_rejected", qrCodeId: "qr-4" },
        ],
      },
    },
  });
  assert(duplicateScanPolicy.passed === 1, "duplicate sample scans for the same QR must not double count");
  assert(!duplicateScanPolicy.satisfied, "a duplicate scan must not satisfy a two-sample quorum");

  const csv = serializeLegacyQrReportCsv({
    groups: [
      {
        brandId: "brand-1",
        brandName: "Brand One",
        brandPrefix: "B1",
        batchId: "batch-1",
        batchName: "Batch One",
        batchLifecycleState: "RELEASED",
        batchReleasedAt: "2026-06-09T00:00:00.000Z",
        status: "ALLOCATED",
        count: 4,
        knownUnsafeCount: 3,
        potentiallyRotatableCount: 1,
        batchPrintedAt: null,
        batchPrintPackDownloadedAt: null,
      },
    ],
  });
  assert(csv.includes("knownUnsafeCount"), "legacy CSV should expose protected counts");
  assert(csv.includes("potentiallyRotatableCount"), "legacy CSV should expose potentially rotatable counts");

  assert(canConfigurePrinterNetworkEndpoint("SUPER_ADMIN"), "super admin may configure printer host/port");
  assert(canConfigurePrinterNetworkEndpoint("PLATFORM_SUPER_ADMIN"), "platform admin may configure printer host/port");
  assert(canConfigurePrinterNetworkEndpoint("LICENSEE_ADMIN"), "licensee admin may configure printer host/port");
  assert(!canConfigurePrinterNetworkEndpoint("ORG_ADMIN"), "deprecated org admin must not configure printer host/port");
  assert(!canConfigurePrinterNetworkEndpoint("MANUFACTURER"), "manufacturer must not configure printer host/port");
  assert(!canConfigurePrinterNetworkEndpoint("MANUFACTURER_ADMIN"), "manufacturer admin must not configure printer host/port");
  assert(!canConfigurePrinterNetworkEndpoint("MANUFACTURER_USER"), "manufacturer user must not configure printer host/port");

  console.log("zebra second hardening tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
