const { ScanRiskClassification } = require("@prisma/client");
const { classifyScan } = require("../dist/services/scanRiskService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const now = new Date("2026-02-15T12:00:00.000Z");

const run = () => {
  const first = classifyScan(
    {
      scannedAt: now,
      customerUserId: "cust-1",
      anonVisitorId: "anon-1",
      ownerCustomerUserId: null,
      locationCountry: "US",
      latitude: 37.77,
      longitude: -122.41,
    },
    []
  );
  assert(first.classification === ScanRiskClassification.FIRST_SCAN, "Expected FIRST_SCAN for empty history");

  const legitRepeat = classifyScan(
    {
      scannedAt: now,
      customerUserId: "cust-1",
      anonVisitorId: "anon-2",
      ownerCustomerUserId: null,
      locationCountry: "US",
      latitude: 37.78,
      longitude: -122.4,
    },
    [
      {
        scannedAt: new Date("2026-02-15T11:50:00.000Z"),
        customerUserId: "cust-1",
        anonVisitorId: "anon-1",
        locationCountry: "US",
        latitude: 37.77,
        longitude: -122.41,
      },
    ]
  );
  assert(
    legitRepeat.classification === ScanRiskClassification.LEGIT_REPEAT,
    "Expected LEGIT_REPEAT for same customer account"
  );

  const suspiciousDifferentAccount = classifyScan(
    {
      scannedAt: now,
      customerUserId: "cust-2",
      anonVisitorId: "anon-9",
      ownerCustomerUserId: "cust-1",
      locationCountry: "US",
      latitude: 37.77,
      longitude: -122.41,
    },
    [
      {
        scannedAt: new Date("2026-02-15T11:50:00.000Z"),
        customerUserId: "cust-1",
        anonVisitorId: "anon-1",
        locationCountry: "US",
        latitude: 37.77,
        longitude: -122.41,
      },
    ]
  );
  assert(
    suspiciousDifferentAccount.classification === ScanRiskClassification.SUSPICIOUS_DUPLICATE,
    "Expected SUSPICIOUS_DUPLICATE for different account from owner"
  );

  const suspiciousBursty = classifyScan(
    {
      scannedAt: now,
      customerUserId: null,
      anonVisitorId: "anon-9",
      ownerCustomerUserId: null,
      locationCountry: "US",
      latitude: 40.71,
      longitude: -74.0,
    },
    [
      { scannedAt: new Date("2026-02-15T11:59:00.000Z"), customerUserId: null, anonVisitorId: "anon-1", locationCountry: "US", latitude: 40.71, longitude: -74.0 },
      { scannedAt: new Date("2026-02-15T11:58:00.000Z"), customerUserId: null, anonVisitorId: "anon-2", locationCountry: "US", latitude: 40.71, longitude: -74.0 },
      { scannedAt: new Date("2026-02-15T11:57:00.000Z"), customerUserId: null, anonVisitorId: "anon-3", locationCountry: "US", latitude: 40.71, longitude: -74.0 },
      { scannedAt: new Date("2026-02-15T11:56:00.000Z"), customerUserId: null, anonVisitorId: "anon-4", locationCountry: "US", latitude: 40.71, longitude: -74.0 },
    ]
  );
  assert(
    suspiciousBursty.classification === ScanRiskClassification.SUSPICIOUS_DUPLICATE,
    "Expected SUSPICIOUS_DUPLICATE for bursty multi-device activity"
  );

  console.log("scan risk service tests passed");
};

run();
