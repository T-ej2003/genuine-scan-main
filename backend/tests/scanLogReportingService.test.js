const assert = require("assert");
const path = require("path");

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

const captured = {
  listSql: "",
  countSql: "",
  params: [],
};

mockModule("config/database.js", {
  __esModule: true,
  default: {
    $queryRaw: async (sql, ...params) => {
      const statement = String(sql?.sql || sql?.raw?.join(" ") || sql || "");
      const values = Array.isArray(sql?.values) ? sql.values : params;
      if (statement.includes("to_regclass")) {
        return [{ oid: null }];
      }
      if (statement.includes('COUNT(*)::bigint')) {
        captured.countSql = statement;
        return [{ total: 1n }];
      }

      captured.listSql = statement;
      captured.params = values;
      return [
        {
          id: "scan-1",
          code: "MSC0001",
          qrCodeId: "qr-1",
          licenseeId: "lic-1",
          batchId: "batch-1",
          status: "SCANNED",
          scannedAt: new Date("2026-03-28T08:00:00.000Z"),
          isFirstScan: true,
          scanCount: 1,
          customerUserId: null,
          ownershipId: null,
          ownershipMatchMethod: null,
          isTrustedOwnerContext: false,
          ipAddress: "198.51.100.10",
          userAgent: "Mozilla/5.0",
          device: "iPhone",
          latitude: null,
          longitude: null,
          accuracy: null,
          locationName: "London",
          locationCountry: "UK",
          locationRegion: "London",
          locationCity: "London",
          archived: false,
          licensee_ref_id: "lic-1",
          licensee_ref_name: "MSCQR Demo",
          licensee_ref_prefix: "MSC",
          qr_ref_id: "qr-1",
          qr_ref_code: "MSC0001",
          qr_ref_status: "SCANNED",
        },
      ];
    },
  },
});

const { listScanLogsForReporting } = require("../dist/services/scanLogReportingService");

(async () => {
  const result = await listScanLogsForReporting({
    licenseeId: "lic-1",
    manufacturerId: "man-1",
    batchId: "batch-1",
    code: "MSC",
    firstScan: true,
    limit: 10,
    offset: 20,
  });

  assert.strictEqual(result.total, 1, "should surface the counted total");
  assert.strictEqual(result.logs.length, 1, "should map one scan log row");
  assert.strictEqual(result.logs[0].licensee.name, "MSCQR Demo", "should map joined licensee details");
  assert.strictEqual(result.logs[0].qrCode.code, "MSC0001", "should map joined QR details");
  assert.strictEqual(result.logs[0].archived, false, "live-table fallback should mark rows as non-archived");
  assert(
    captured.listSql.includes('FROM "QrScanLog" s'),
    "list query should fall back to the live scan-log table when the reporting view is absent"
  );
  assert(
    captured.countSql.includes('FROM "QrScanLog" s'),
    "count query should use the same live scan-log fallback"
  );
  assert(
    captured.params.includes("lic-1") && captured.params.includes("man-1") && captured.params.includes("batch-1"),
    "list query should bind the requested filters as parameters"
  );

  console.log("scan log reporting service tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
