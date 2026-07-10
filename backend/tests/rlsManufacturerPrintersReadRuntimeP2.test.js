const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const {
  PrismaClient,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterDeliveryMode,
  PrinterLanguageKind,
  PrinterProfileSnapshotType,
  PrinterProfileStatus,
  PrinterTransportKind,
  PrinterTrustStatus,
  UserRole,
} = require("@prisma/client");

const {
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
  withP2TestApp,
} = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");
const {
  applyCandidateRls,
  buildRoleUrl: buildRestrictedRoleUrl,
  createRestrictedRlsReadRole,
  dropRestrictedRlsReadRole,
  rollbackCandidateRls,
} = require("./helpers/rlsReadRuntimeRole");

const command =
  "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_TEST=true npm --prefix backend run test:rls:manufacturer-printers-read-runtime";
const flagName = "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_TEST)) {
  console.log(`RLS manufacturer printer read runtime P2 test skipped. Run with: ${command}`);
  process.exit(0);
}

const noLinkedManufacturerId = "00000000-0000-4202-8200-000000000099";

const printerIds = {
  printerA: "00000000-0000-4202-9400-000000000001",
  printerB: "00000000-0000-4202-9400-000000000002",
  localAssignedA: "00000000-0000-4202-9400-000000000003",
  localRegisteredA: "00000000-0000-4202-9400-000000000004",
  registrationA: "00000000-0000-4202-9410-000000000001",
  attestationA: "00000000-0000-4202-9420-000000000001",
  sessionA: "00000000-0000-4202-9430-000000000001",
  profileAssignedA: "00000000-0000-4202-9440-000000000001",
  profileRegisteredA: "00000000-0000-4202-9440-000000000002",
  snapshotAssignedA: "00000000-0000-4202-9450-000000000001",
  snapshotRegisteredA: "00000000-0000-4202-9450-000000000002",
};

const authHeader = (token) => ({ authorization: `Bearer ${token}` });
const backendRoot = path.resolve(__dirname, "..");
const distRoot = path.join(backendRoot, "dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const clearDistRequireCache = () => {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(distRoot)) delete require.cache[key];
  }
};

const request = async (baseUrl, method, route, body, options = {}) => {
  const headers = { ...(options.headers || {}) };
  const hasBody = body !== undefined && body !== null;
  if (hasBody && !headers["content-type"] && !headers["Content-Type"]) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: hasBody ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  return { status: response.status, headers: response.headers, text, payload };
};

const listen = async (app) => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
};

const readContext = async (client) => {
  const rows = await client.$queryRaw`
    SELECT
      current_setting('app.user_id', true) AS user_id,
      current_setting('app.role', true) AS role,
      current_setting('app.licensee_id', true) AS licensee_id,
      current_setting('app.manufacturer_id', true) AS manufacturer_id,
      current_setting('app.organization_id', true) AS organization_id,
      current_setting('app.is_platform_admin', true) AS is_platform_admin
  `;
  return rows[0] || {};
};

const readContextFromRunner = (runner) => runner.$transaction((tx) => readContext(tx));

const createPrinterFixtures = async (prisma) => {
  const now = new Date();
  const future = new Date(Date.now() + 10 * 60_000);
  await prisma.printerProfileSnapshot.deleteMany({
    where: { id: { in: [printerIds.snapshotAssignedA, printerIds.snapshotRegisteredA] } },
  });
  await prisma.printerProfile.deleteMany({
    where: { id: { in: [printerIds.profileAssignedA, printerIds.profileRegisteredA] } },
  });
  await prisma.printer.deleteMany({ where: { id: { in: Object.values(printerIds) } } });
  await prisma.printerAgentSession.deleteMany({ where: { id: printerIds.sessionA } });
  await prisma.printerAttestation.deleteMany({ where: { id: printerIds.attestationA } });
  await prisma.printerRegistration.deleteMany({ where: { id: printerIds.registrationA } });

  await prisma.printerRegistration.create({
    data: {
      id: printerIds.registrationA,
      userId: ids.manufacturerA,
      orgId: ids.orgA,
      licenseeId: ids.licenseeA,
      deviceFingerprint: "p2-local-device-a",
      agentId: "p2-local-agent-a",
      publicKeyPem: "compat:p2-local-agent-public-key",
      trustStatus: PrinterTrustStatus.TRUSTED,
      approvedAt: now,
      lastSeenAt: now,
    },
  });
  await prisma.printerAttestation.create({
    data: {
      id: printerIds.attestationA,
      printerRegistrationId: printerIds.registrationA,
      signedPayloadHash: "p2-local-attestation-hash",
      heartbeatNonce: "p2-local-attestation-nonce",
      attestedAt: now,
      expiresAt: future,
      signatureValid: true,
      trustValid: true,
      metadata: {
        connected: true,
        printerName: "P2 Local Registered A",
        printerId: "p2-native-registered-a",
        selectedPrinterId: "p2-native-registered-a",
        selectedPrinterName: "P2 Local Registered A",
        deviceName: "P2 Workstation A",
        agentVersion: "9999.1.1",
        protocolVersion: "local-agent-direct-v2",
        buildVersion: "9999.1.1",
        transportDiagnosticsVersion: "transport-diagnostics-v1",
        capabilities: {
          supportsPrinterQueueSnapshot: true,
          supportsWindowsTcpPortInspection: true,
          supportsRawTcpConnectTest: true,
          supportsRawTcpZplSend: true,
          supportsUsbRawSpooler: true,
          supportsSpoolJobCancel: true,
          supportsSpoolJobStatus: true,
          supportsTransportDiagnostics: true,
          supportsTestLabel: true,
          supportsPersistentPrintSession: true,
          supportsOfficialMscqrZplWordmark: true,
        },
        printers: [
          {
            printerId: "p2-native-registered-a",
            printerName: "P2 Local Registered A",
            online: true,
            languages: ["ZPL"],
            mediaSizes: ["4x6"],
            dpi: 203,
          },
        ],
        capabilitySummary: {
          languages: ["ZPL"],
          mediaSizes: ["4x6"],
          dpi: 203,
        },
      },
    },
  });
  await prisma.printerAgentSession.create({
    data: {
      id: printerIds.sessionA,
      connectionId: "p2-local-session-a",
      registrationId: printerIds.registrationA,
      agentId: "p2-local-agent-a",
      deviceFingerprint: "p2-local-device-a",
      publicKeyFingerprint: "p2-local-public-key-fingerprint",
      selectedPrinterId: "p2-native-registered-a",
      selectedPrinterName: "P2 Local Registered A",
      connectionState: "CONNECTED",
      trustMode: "SIGNED_ATTESTATION",
      connectorVersion: "9999.1.1",
      printerHealth: {
        connected: true,
        printerId: "p2-native-registered-a",
        printerName: "P2 Local Registered A",
        selectedPrinterId: "p2-native-registered-a",
        selectedPrinterName: "P2 Local Registered A",
        buildVersion: "9999.1.1",
        languages: ["ZPL"],
      },
      lastSeenAt: now,
      lastSignedHeartbeatAt: now,
      expiresAt: future,
    },
  });
  await prisma.printer.createMany({
    data: [
      {
        id: printerIds.printerA,
        name: "P2 Printer A",
        vendor: "Zebra",
        model: "ZT410",
        connectionType: PrinterConnectionType.NETWORK_DIRECT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        ipAddress: "10.10.10.10",
        port: 9100,
        deliveryMode: PrinterDeliveryMode.DIRECT,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        createdByUserId: ids.licenseeAdminA,
        isActive: true,
        isDefault: true,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 printer A ready",
      },
      {
        id: printerIds.printerB,
        name: "P2 Printer B",
        vendor: "Zebra",
        model: "ZT410",
        connectionType: PrinterConnectionType.NETWORK_DIRECT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        ipAddress: "10.20.20.20",
        port: 9100,
        deliveryMode: PrinterDeliveryMode.DIRECT,
        orgId: ids.orgB,
        licenseeId: ids.licenseeB,
        createdByUserId: ids.licenseeAdminB,
        isActive: true,
        isDefault: true,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 printer B ready",
      },
      {
        id: printerIds.localAssignedA,
        name: "P2 Local Assigned A",
        vendor: "Zebra",
        model: "ZD621",
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        nativePrinterId: "p2-native-assigned-a",
        agentId: "p2-local-agent-a",
        deviceFingerprint: "p2-local-device-a",
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        assignedUserId: ids.manufacturerA,
        createdByUserId: ids.manufacturerA,
        isActive: true,
        isDefault: false,
        lastSeenAt: now,
        lastValidatedAt: now,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 local assigned printer ready",
      },
      {
        id: printerIds.localRegisteredA,
        name: "P2 Local Registered A",
        vendor: "Zebra",
        model: "ZD621",
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        nativePrinterId: "p2-native-registered-a",
        agentId: "p2-local-agent-a",
        deviceFingerprint: "p2-local-device-a",
        printerRegistrationId: printerIds.registrationA,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        isActive: true,
        isDefault: true,
        lastSeenAt: now,
        lastValidatedAt: now,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 local registered printer ready",
      },
    ],
  });
  await prisma.printerProfile.createMany({
    data: [
      {
        id: printerIds.profileAssignedA,
        printerId: printerIds.localAssignedA,
        status: PrinterProfileStatus.NEEDS_REVIEW,
        transportKind: PrinterTransportKind.DRIVER_QUEUE,
        activeLanguage: PrinterLanguageKind.ZPL,
        nativeLanguage: "ZPL",
        supportedLanguages: ["ZPL"],
        jobMode: "driver_queue",
        spoolFormat: "zpl",
        preferredTransport: "USB",
        connectionTypes: ["USB"],
        brand: "Zebra",
        modelName: "ZD621",
        dpi: 203,
        latestSeenCapabilities: { languages: ["ZPL"], mediaSizes: ["4x6"] },
      },
      {
        id: printerIds.profileRegisteredA,
        printerId: printerIds.localRegisteredA,
        status: PrinterProfileStatus.NEEDS_REVIEW,
        transportKind: PrinterTransportKind.DRIVER_QUEUE,
        activeLanguage: PrinterLanguageKind.ZPL,
        nativeLanguage: "ZPL",
        supportedLanguages: ["ZPL"],
        jobMode: "driver_queue",
        spoolFormat: "zpl",
        preferredTransport: "USB",
        connectionTypes: ["USB"],
        brand: "Zebra",
        modelName: "ZD621",
        dpi: 203,
        latestSeenCapabilities: { languages: ["ZPL"], mediaSizes: ["4x6"] },
      },
    ],
  });
  await prisma.printerProfileSnapshot.createMany({
    data: [
      {
        id: printerIds.snapshotAssignedA,
        printerProfileId: printerIds.profileAssignedA,
        snapshotType: PrinterProfileSnapshotType.LIVE_DISCOVERY,
        summary: "P2 assigned local profile snapshot",
        warnings: [],
        data: { source: "p2-assigned-local" },
        capturedAt: now,
      },
      {
        id: printerIds.snapshotRegisteredA,
        printerProfileId: printerIds.profileRegisteredA,
        snapshotType: PrinterProfileSnapshotType.LIVE_DISCOVERY,
        summary: "P2 registered local profile snapshot",
        warnings: [],
        data: { source: "p2-registered-local" },
        capturedAt: now,
      },
    ],
  });
};

const withConsoleCapture = async (callback) => {
  const logs = [];
  const originalInfo = console.info;
  const originalWarn = console.warn;
  console.info = (...args) => logs.push({ level: "info", args });
  console.warn = (...args) => logs.push({ level: "warn", args });
  try {
    await callback(logs);
  } finally {
    console.info = originalInfo;
    console.warn = originalWarn;
  }
  return logs;
};

const getProofLogs = (logs) =>
  logs
    .filter((entry) => entry.args[0] === "staging_rls_manufacturer_printers_read_proof")
    .map((entry) => ({ level: entry.level, event: entry.args[1] }));

const safeProofEventKeys = [
  "contextClass",
  "durationMs",
  "failureCategory",
  "flagEnabled",
  "metric",
  "route",
  "rowCount",
  "success",
];

const assertPrinterList = (response, expectedName, forbiddenName, label) => {
  assert.equal(response.status, 200, `${label}: ${response.text}`);
  assert.equal(response.payload?.success, true, `${label}: expected success payload`);
  assert(Array.isArray(response.payload?.data), `${label}: expected data array`);
  assert.match(response.text, new RegExp(expectedName, "i"), `${label}: expected ${expectedName}`);
  assert.doesNotMatch(response.text, new RegExp(forbiddenName, "i"), `${label}: leaked ${forbiddenName}`);
};

const namesFor = (rows) => rows.map((row) => row.name).sort();

const assertManufacturerAPrinterRows = (rows, label) => {
  assert.deepEqual(
    namesFor(rows),
    ["P2 Local Assigned A", "P2 Local Registered A", "P2 Printer A"],
    `${label}: expected network, assigned local-agent, and registered local-agent printers`
  );

  const assignedLocal = rows.find((row) => row.name === "P2 Local Assigned A");
  assert(assignedLocal, `${label}: assigned local-agent printer missing`);
  assert.equal(assignedLocal.connectionType, PrinterConnectionType.LOCAL_AGENT, `${label}: assigned local connection type`);
  assert.equal(assignedLocal.assignedUserId, ids.manufacturerA, `${label}: assigned local current-user scope`);
  assert.equal(assignedLocal.printerRegistrationId, null, `${label}: assigned local should not depend on registration`);
  assert.equal(assignedLocal.printerProfile?.id, printerIds.profileAssignedA, `${label}: assigned local profile visible`);
  assert.equal(
    assignedLocal.latestDiscoverySnapshot?.id,
    printerIds.snapshotAssignedA,
    `${label}: assigned local profile snapshot visible`
  );

  const registeredLocal = rows.find((row) => row.name === "P2 Local Registered A");
  assert(registeredLocal, `${label}: registered local-agent printer missing`);
  assert.equal(registeredLocal.connectionType, PrinterConnectionType.LOCAL_AGENT, `${label}: registered local connection type`);
  assert.equal(
    registeredLocal.printerRegistration?.userId,
    ids.manufacturerA,
    `${label}: registered local current-user registration scope`
  );
  assert.equal(registeredLocal.registryStatus?.state, "READY", `${label}: registered local status should be ready`);
  assert.equal(
    registeredLocal.registryStatus?.connectionStatus?.registrationId,
    printerIds.registrationA,
    `${label}: local status registration should be loaded`
  );
  assert.equal(
    registeredLocal.registryStatus?.connectionStatus?.signedAttestation?.signatureValid,
    true,
    `${label}: latest attestation should be loaded`
  );
  assert.equal(
    registeredLocal.registryStatus?.connectionStatus?.persistentSessionDisconnected,
    false,
    `${label}: connected PrinterAgentSession should be loaded`
  );
  assert.equal(registeredLocal.printerProfile?.id, printerIds.profileRegisteredA, `${label}: registered local profile visible`);
  assert.equal(
    registeredLocal.latestDiscoverySnapshot?.id,
    printerIds.snapshotRegisteredA,
    `${label}: registered local profile snapshot visible`
  );
};

const assertSafeProofEvent = (event) => {
  assert.deepEqual(Object.keys(event).sort(), safeProofEventKeys, "proof event must contain only safe telemetry fields");
  assert.strictEqual(event.metric, "staging_rls_manufacturer_printers_read");
  assert.strictEqual(event.route, "GET /api/manufacturer/printers");
  assert.strictEqual(event.flagEnabled, true);
  assert(["platform_admin", "manufacturer", "tenant_user"].includes(event.contextClass), "safe context class expected");
  assert.strictEqual(typeof event.durationMs, "number");
  assert(event.durationMs >= 0, "duration must be non-negative");
  assert(Number.isInteger(event.rowCount), "row count must be an integer");
  assert(event.rowCount >= 0, "row count must be non-negative");

  const serialized = JSON.stringify(event);
  for (const forbidden of [
    ids.licenseeAdminA,
    ids.licenseeAdminB,
    ids.manufacturerA,
    ids.manufacturerB,
    ids.superAdmin,
    ids.licenseeA,
    ids.licenseeB,
    ids.orgA,
    ids.orgB,
    printerIds.printerA,
    printerIds.printerB,
    printerIds.localAssignedA,
    printerIds.localRegisteredA,
    printerIds.registrationA,
    "P2 Printer A",
    "P2 Printer B",
    "P2 Local Assigned A",
    "P2 Local Registered A",
    "10.10.10.10",
    "10.20.20.20",
    "p2-licensee-a@mscqr.test",
    "p2-manufacturer-a@mscqr.test",
  ]) {
    assert(!serialized.includes(forbidden), `proof event leaked raw identifier: ${forbidden}`);
  }

  for (const forbiddenKey of [
    "printerId",
    "printerName",
    "deviceName",
    "userId",
    "actorUserId",
    "licenseeId",
    "manufacturerId",
    "organizationId",
    "orgId",
    "ipAddress",
    "token",
    "secret",
    "email",
  ]) {
    assert(!Object.prototype.hasOwnProperty.call(event, forbiddenKey), `proof event includes ${forbiddenKey}`);
  }
};

const runFlagOffRouteAssertions = async () => {
  process.env[flagName] = "false";
  delete process.env.RLS_READ_DATABASE_URL;
  const logs = await withConsoleCapture(async () => {
    await withP2TestApp(async ({ request, prisma }) => {
      await seedP2Fixtures(prisma);
      await createPrinterFixtures(prisma);
      const tokens = await issueBearerTokens();

      const manufacturer = await request("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(manufacturer, "P2 Printer A", "P2 Printer B", "flag off manufacturer printer list");
      assertManufacturerAPrinterRows(manufacturer.payload.data, "flag off manufacturer printer list");

      const wrongManufacturer = await request("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerB),
      });
      assertPrinterList(wrongManufacturer, "P2 Printer B", "P2 Printer A", "flag off wrong manufacturer filtered list");
      assert.doesNotMatch(
        wrongManufacturer.text,
        /P2 Local (Assigned|Registered) A/i,
        "flag off wrong manufacturer must not see tenant A local-agent printers"
      );

      const { listScopedManufacturerPrintersReadPayload } = require("../dist/services/stagingRlsManufacturerPrintersReadService");
      const noLinkedRows = await listScopedManufacturerPrintersReadPayload({
        user: {
          userId: noLinkedManufacturerId,
          email: "p2-no-linked-manufacturer@mscqr.test",
          role: UserRole.MANUFACTURER,
          licenseeId: null,
          linkedLicenseeIds: [],
          orgId: null,
          sessionStage: "ACTIVE",
          authAssurance: "ADMIN_MFA",
        },
        userId: noLinkedManufacturerId,
        orgId: null,
        licenseeId: null,
        licenseeIds: null,
        includeInactive: false,
      });
      assert.deepEqual(
        noLinkedRows,
        [],
        "flag off no-linked manufacturer must not fall through to all active network printers"
      );
    });
  });
  assert.deepEqual(getProofLogs(logs), [], "flag-off path must not emit manufacturer printer RLS proof events");
};

const runFlagOnRouteAssertions = async () => {
  process.env[flagName] = "true";
  let databaseInfo = null;
  let adminPrisma = null;
  let appPrisma = null;
  let server = null;
  let appRoleName = null;

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);

    adminPrisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });
    await seedP2Fixtures(adminPrisma);
    await createPrinterFixtures(adminPrisma);

    appRoleName = createRestrictedRlsReadRole(databaseInfo.databaseUrl, "mscqr_printers_rls_read");
    applyCandidateRls(databaseInfo.databaseUrl, appRoleName);

    process.env.RLS_READ_DATABASE_URL = buildRestrictedRoleUrl(databaseInfo.databaseUrl, appRoleName);
    clearDistRequireCache();

    const proofLogs = [];
    const requestLogs = [];
    const captureLogger = (level, message, meta) => {
      if (message === "staging_rls_manufacturer_printers_read_proof") proofLogs.push({ level, event: meta });
      if (message === "HTTP request completed") requestLogs.push({ level, event: meta });
    };
    mockModule("utils/logger.js", {
      logger: {
        info: (message, meta) => captureLogger("info", message, meta),
        warn: (message, meta) => captureLogger("warn", message, meta),
        error: (message, meta) => captureLogger("error", message, meta),
        debug: (message, meta) => captureLogger("debug", message, meta),
      },
    });

    appPrisma = require("../dist/config/database").default;
    const { createBackendApp } = require("../dist/app");
    const app = createBackendApp();
    const listener = await listen(app);
    server = listener.server;
    const routeRequest = (method, route, body, options) => request(listener.baseUrl, method, route, body, options);
    const tokens = await issueBearerTokens();

    try {
      const { getRlsReadPrisma } = require("../dist/config/rlsReadDatabase");
      const rlsReadPrisma = getRlsReadPrisma();
      const plainRows = await rlsReadPrisma.$transaction((tx) =>
        tx.printer.findMany({ where: { id: { in: Object.values(printerIds) } }, orderBy: [{ id: "asc" }] })
      );
      assert.deepEqual(plainRows, [], "Printer RLS must fail closed without transaction-local app context");
      const plainRegistrations = await rlsReadPrisma.$transaction((tx) =>
        tx.printerRegistration.findMany({ where: { id: printerIds.registrationA } })
      );
      assert.deepEqual(
        plainRegistrations,
        [],
        "PrinterRegistration RLS must fail closed without transaction-local app context"
      );

      const manufacturer = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(manufacturer, "P2 Printer A", "P2 Printer B", "flag on manufacturer printer list");
      assertManufacturerAPrinterRows(manufacturer.payload.data, "flag on manufacturer printer list");

      const manufacturerTrailingSlash = await routeRequest("GET", "/api/manufacturer/printers/", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(
        manufacturerTrailingSlash,
        "P2 Printer A",
        "P2 Printer B",
        "flag on trailing-slash manufacturer printer list"
      );
      assertManufacturerAPrinterRows(manufacturerTrailingSlash.payload.data, "flag on trailing-slash manufacturer printer list");

      const wrongManufacturer = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerB),
      });
      assertPrinterList(wrongManufacturer, "P2 Printer B", "P2 Printer A", "flag on wrong manufacturer filtered list");
      assert.doesNotMatch(
        wrongManufacturer.text,
        /P2 Local (Assigned|Registered) A/i,
        "flag on wrong manufacturer must not see tenant A local-agent printers"
      );

      const platformAdmin = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.superAdmin),
      });
      assert.equal(platformAdmin.status, 200, `platform admin printer list: ${platformAdmin.text}`);
      assert.match(platformAdmin.text, /P2 Printer A/i, "platform admin should explicitly retain printer A visibility");
      assert.match(platformAdmin.text, /P2 Printer B/i, "platform admin should explicitly retain printer B visibility");

      const { listScopedManufacturerPrintersReadPayload } = require("../dist/services/stagingRlsManufacturerPrintersReadService");
      const noClaimRows = await listScopedManufacturerPrintersReadPayload({
        user: {
          userId: ids.manufacturerA,
          email: "manufacturer-a-no-link-claims@mscqr.test",
          role: UserRole.MANUFACTURER,
          licenseeId: null,
          linkedLicenseeIds: [],
          orgId: null,
          sessionStage: "ACTIVE",
          authAssurance: "ADMIN_MFA",
        },
        userId: ids.manufacturerA,
        orgId: null,
        licenseeId: null,
        licenseeIds: null,
        includeInactive: false,
      });
      assertManufacturerAPrinterRows(noClaimRows, "flag on manufacturer service without linked-licensee claims");

      await assert.rejects(
        () => listScopedManufacturerPrintersReadPayload({
          user: {
            userId: ids.licenseeAdminA,
            email: "org-admin-a@mscqr.test",
            role: UserRole.ORG_ADMIN,
            licenseeId: ids.licenseeA,
            orgId: ids.orgA,
            sessionStage: "ACTIVE",
            authAssurance: "ADMIN_MFA",
          },
          licenseeId: ids.licenseeA,
          includeInactive: false,
        }),
        /phase-one access is not enabled/,
        "dormant organization admin must not gain phase-one printer-read access"
      );

      const siblingRoutePath = `/api/manufacturer/printers/${printerIds.printerA}/test`;
      const siblingRoute = await routeRequest("POST", siblingRoutePath, {}, {
        headers: authHeader(tokens.licenseeAdminA),
      });
      assert.notEqual(siblingRoute.status, 401, `sibling printer test route should pass auth before telemetry assertion: ${siblingRoute.text}`);

      const successProofs = proofLogs.filter((entry) => entry.event.success);
      assert.equal(successProofs.length, 5, "only active phase-one printer reads may emit success proofs");
      assert.deepEqual(
        successProofs.map((entry) => entry.event.contextClass).sort(),
        ["manufacturer", "manufacturer", "manufacturer", "manufacturer", "platform_admin"],
        "proof events must expose context class only"
      );
      assert.deepEqual(
        successProofs.map((entry) => entry.event.rowCount).sort((a, b) => a - b),
        [1, 2, 3, 3, 3],
        "proof row counts should be coarse and scoped"
      );
      for (const entry of successProofs) {
        assert.strictEqual(entry.level, "info");
        assertSafeProofEvent(entry.event);
        assert.strictEqual(entry.event.failureCategory, null);
      }

      const printerRequestLogs = requestLogs.filter((entry) =>
        entry.event.path === "/api/manufacturer/printers"
      );
      assert.equal(printerRequestLogs.length, 4, "flag-on printer request telemetry should be emitted");
      assert.deepEqual(
        printerRequestLogs.map((entry) => entry.event.actorContextClass).sort(),
        ["manufacturer", "manufacturer", "manufacturer", "platform_admin"],
        "request telemetry must expose context class only under the printer-read flag"
      );
      for (const entry of printerRequestLogs) {
        assert.strictEqual(entry.event.actorUserId, null, "flag-on request telemetry must redact actor user id");
        assert.strictEqual(entry.event.actorRole, null, "flag-on request telemetry must redact actor role");
        assert.strictEqual(entry.event.actorLicenseeId, null, "flag-on request telemetry must redact licensee id");
        assert.strictEqual(entry.event.actorOrgId, null, "flag-on request telemetry must redact organization id");
        const serialized = JSON.stringify(entry.event);
        assert(!serialized.includes(ids.manufacturerA), "request telemetry leaked manufacturer id");
        assert(!serialized.includes(ids.licenseeA), "request telemetry leaked licensee id");
        assert(!serialized.includes(ids.orgA), "request telemetry leaked organization id");
        assert(!serialized.includes(printerIds.printerA), "request telemetry leaked printer id");
        assert(!serialized.includes("P2 Printer A"), "request telemetry leaked printer name");
      }

      const siblingRouteLog = requestLogs.find((entry) => entry.event.path === siblingRoutePath);
      assert(siblingRouteLog, "sibling printer route should emit request telemetry");
      assert.strictEqual(siblingRouteLog.event.actorContextClass, null, "sibling printer route must not be classified as printer-read RLS telemetry");
      assert.strictEqual(siblingRouteLog.event.actorUserId, ids.licenseeAdminA, "sibling route must not redact actor user id");
      assert.strictEqual(siblingRouteLog.event.actorRole, UserRole.LICENSEE_ADMIN, "sibling route must not redact actor role");
      assert.strictEqual(siblingRouteLog.event.actorLicenseeId, ids.licenseeA, "sibling route must not redact licensee id");
      assert.strictEqual(siblingRouteLog.event.actorOrgId, ids.orgA, "sibling route must not redact organization id");

      const context = await readContextFromRunner(rlsReadPrisma);
      assert.equal(context.user_id || "", "", "app.user_id leaked after route transaction");
      assert.equal(context.role || "", "", "app.role leaked after route transaction");
      assert.equal(context.licensee_id || "", "", "app.licensee_id leaked after route transaction");
      assert.equal(context.manufacturer_id || "", "", "app.manufacturer_id leaked after route transaction");
      assert.equal(context.organization_id || "", "", "app.organization_id leaked after route transaction");
      assert.equal(context.is_platform_admin || "", "", "app.is_platform_admin leaked after route transaction");

      await assert.rejects(
        () =>
          listScopedManufacturerPrintersReadPayload({
            user: {
              userId: ids.licenseeAdminA,
              email: "missing-tenant@mscqr.test",
              role: UserRole.LICENSEE_ADMIN,
              licenseeId: null,
              orgId: ids.orgA,
              sessionStage: "ACTIVE",
              authAssurance: "ADMIN_MFA",
            },
            userId: ids.licenseeAdminA,
            orgId: ids.orgA,
            licenseeId: null,
            licenseeIds: null,
            includeInactive: false,
          }),
        /requires app\.licensee_id/,
        "staging RLS printer service must fail closed when tenant context is missing"
      );

      const failureProof = proofLogs.find((entry) => !entry.event.success && entry.event.failureCategory === "rls_context_missing");
      assert(failureProof, "flag-on printer read failures must emit a categorized proof event");
      assert.strictEqual(failureProof.level, "warn");
      assertSafeProofEvent(failureProof.event);
      assert.strictEqual(failureProof.event.failureCategory, "rls_context_missing");
      assert(!JSON.stringify(failureProof.event).includes("requires app.licensee_id"), "failure proof must not log error text");
    } finally {
      rollbackCandidateRls(databaseInfo.databaseUrl, appRoleName);
    }
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    const rlsReadModule = require.cache[require.resolve("../dist/config/rlsReadDatabase")]
      ? require("../dist/config/rlsReadDatabase")
      : null;
    if (rlsReadModule) await rlsReadModule.disconnectRlsReadPrisma().catch(() => {});
    if (appPrisma?.$disconnect) await appPrisma.$disconnect().catch(() => {});
    if (adminPrisma?.$disconnect) await adminPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.databaseUrl && appRoleName) dropRestrictedRlsReadRole(databaseInfo.databaseUrl, appRoleName);
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
    delete process.env.RLS_READ_DATABASE_URL;
  }
};

(async () => {
  await runFlagOffRouteAssertions();
  await runFlagOnRouteAssertions();
  console.log("RLS manufacturer printer read runtime P2 tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
