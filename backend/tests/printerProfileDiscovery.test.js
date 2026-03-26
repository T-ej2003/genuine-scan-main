const prisma = require("../dist/config/database").default;
const profileService = require("../dist/printing/registry/printerProfileService");
const networkPrinterSocketService = require("../dist/services/networkPrinterSocketService");
const ippClient = require("../dist/printing/ippClient");
const {
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterDeliveryMode,
  PrinterProfileStatus,
  PrinterTransportKind,
} = require("@prisma/client");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const makePrinter = (overrides = {}) => ({
  id: "printer-1",
  name: "Zebra ZT411 Line 1",
  vendor: "Zebra",
  model: "ZT411",
  connectionType: PrinterConnectionType.NETWORK_DIRECT,
  commandLanguage: PrinterCommandLanguage.ZPL,
  capabilitySummary: { languages: ["ZPL"], dpi: 300 },
  metadata: {},
  deliveryMode: PrinterDeliveryMode.DIRECT,
  host: null,
  ipAddress: "192.168.10.10",
  port: 9100,
  tlsEnabled: false,
  resourcePath: null,
  printerUri: null,
  ...overrides,
});

const run = async () => {
  const backupUpsert = prisma.printerProfile.upsert;
  const backupSnapshotCreate = prisma.printerProfileSnapshot.create;
  const backupProfileUpdate = prisma.printerProfile.update;
  const backupFindUnique = prisma.printerProfile.findUnique;
  const backupSocketProbe = networkPrinterSocketService.testNetworkPrinterConnectivity;
  const backupIppInspect = ippClient.inspectIppPrinter;

  let currentProfile = null;
  const snapshots = [];

  prisma.printerProfile.upsert = async (args) => {
    const payload = currentProfile ? args.update : args.create;
    currentProfile = {
      id: currentProfile?.id || "profile-1",
      onboardingSnapshotId: currentProfile?.onboardingSnapshotId || null,
      ...currentProfile,
      ...payload,
    };
    return currentProfile;
  };

  prisma.printerProfileSnapshot.create = async (args) => {
    const snapshot = {
      id: `snapshot-${snapshots.length + 1}`,
      capturedAt: new Date("2026-03-26T12:00:00.000Z"),
      ...args.data,
    };
    snapshots.unshift(snapshot);
    return snapshot;
  };

  prisma.printerProfile.update = async (args) => {
    currentProfile = {
      ...currentProfile,
      ...args.data,
    };
    return currentProfile;
  };

  prisma.printerProfile.findUnique = async () => ({
    ...currentProfile,
    onboardingSnapshot: snapshots.find((snapshot) => snapshot.id === currentProfile?.onboardingSnapshotId) || null,
    snapshots: snapshots.slice(0, 10),
  });

  try {
    networkPrinterSocketService.testNetworkPrinterConnectivity = async () => ({ ok: true, latencyMs: 12 });
    ippClient.inspectIppPrinter = async () => ({
      endpointUrl: "ipps://ipp-printer.local:631/ipp/print",
      printerUri: "ipps://ipp-printer.local:631/ipp/print",
      pdfSupported: true,
      documentFormats: ["application/pdf"],
      uriSecurity: "tls",
      ippVersions: ["2.0"],
      printerState: "idle",
      printerName: "SATO CL4NX Plus",
    });

    const certifiedDiscovery = await profileService.discoverPrinterCapabilities(makePrinter());
    assert(
      certifiedDiscovery.status === PrinterProfileStatus.CERTIFIED,
      "Supported raw TCP printer should certify successfully"
    );
    assert(certifiedDiscovery.mismatches.length === 0, "Certified discovery should not report mismatches");

    const certifiedPreflight = await profileService.resolvePrinterPreflight(makePrinter(), {
      quantity: 1,
      labelWidthMm: 40,
      labelHeightMm: 40,
    });
    assert(certifiedPreflight.ok, "Certified raw TCP printer should pass preflight");
    assert(
      certifiedPreflight.resolvedTransport === PrinterTransportKind.RAW_TCP,
      "Raw TCP printer should resolve the RAW_TCP transport kind"
    );

    const reviewDiscovery = await profileService.discoverPrinterCapabilities(
      makePrinter({
        id: "printer-2",
        name: "Unknown line printer",
        vendor: "Unknown",
        model: "Mystery",
        commandLanguage: PrinterCommandLanguage.AUTO,
        capabilitySummary: {},
      })
    );
    assert(
      reviewDiscovery.status === PrinterProfileStatus.NEEDS_REVIEW,
      "AUTO language printers should remain in needs-review state"
    );
    assert(
      reviewDiscovery.mismatches.some((message) => /active language/i.test(message)),
      "AUTO language discovery should flag the unresolved active language"
    );

    ippClient.inspectIppPrinter = async () => ({
      endpointUrl: "ipps://ipp-printer.local:631/ipp/print",
      printerUri: "ipps://ipp-printer.local:631/ipp/print",
      pdfSupported: false,
      documentFormats: ["application/postscript"],
      uriSecurity: "tls",
      ippVersions: ["2.0"],
      printerState: "idle",
      printerName: "Office IPP printer",
    });

    const ippReviewDiscovery = await profileService.discoverPrinterCapabilities(
      makePrinter({
        id: "printer-3",
        name: "Legacy office printer",
        vendor: "Unknown",
        model: "LegacyPDFless",
        connectionType: PrinterConnectionType.NETWORK_IPP,
        commandLanguage: PrinterCommandLanguage.AUTO,
        capabilitySummary: {},
        metadata: {},
        host: "ipp-printer.local",
        port: 631,
        tlsEnabled: true,
        printerUri: "ipps://ipp-printer.local:631/ipp/print",
      })
    );
    assert(
      ippReviewDiscovery.status === PrinterProfileStatus.NEEDS_REVIEW,
      "IPP discovery should stay in review when PDF support is missing"
    );
    assert(
      ippReviewDiscovery.mismatches.some((message) => /PDF support/i.test(message)),
      "IPP discovery should report missing PDF support as a certification mismatch"
    );

    const blockedPreflight = await profileService.resolvePrinterPreflight(
      makePrinter({
        id: "printer-4",
        metadata: {
          mediaWidthMaxMm: 40,
          mediaLengthMaxMm: 45,
          cutter: false,
        },
      }),
      {
        quantity: 1,
        labelWidthMm: 55,
        labelHeightMm: 50,
        requiredOptions: ["cutter"],
      }
    );
    assert(!blockedPreflight.ok, "Preflight should fail when media limits or required options are invalid");
    assert(
      blockedPreflight.issues.some((message) => /label width/i.test(message)),
      "Preflight should report media-width violations"
    );
    assert(
      blockedPreflight.issues.some((message) => /Required printer option missing: cutter/i.test(message)),
      "Preflight should report missing required printer options"
    );

    console.log("printer profile discovery tests passed");
  } finally {
    prisma.printerProfile.upsert = backupUpsert;
    prisma.printerProfileSnapshot.create = backupSnapshotCreate;
    prisma.printerProfile.update = backupProfileUpdate;
    prisma.printerProfile.findUnique = backupFindUnique;
    networkPrinterSocketService.testNetworkPrinterConnectivity = backupSocketProbe;
    ippClient.inspectIppPrinter = backupIppInspect;
  }
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
