export const fixtureIds = Object.freeze({
  orgA: "rls-harness-org-a",
  orgB: "rls-harness-org-b",
  licenseeA: "rls-harness-licensee-a",
  licenseeB: "rls-harness-licensee-b",
  platformAdmin: "rls-harness-platform-admin",
  licenseeAdminA: "rls-harness-licensee-admin-a",
  licenseeAdminB: "rls-harness-licensee-admin-b",
  manufacturerA: "rls-harness-manufacturer-a",
  manufacturerB: "rls-harness-manufacturer-b",
  orgUserA: "rls-harness-org-user-a",
});

const a = (table) => `rls-harness-${table.toLowerCase()}-a`;
const b = (table) => `rls-harness-${table.toLowerCase()}-b`;

export const tableProofs = Object.freeze([
  { table: "Organization", idSql: '"id"', a: fixtureIds.orgA, b: fixtureIds.orgB },
  { table: "Licensee", idSql: '"id"', a: fixtureIds.licenseeA, b: fixtureIds.licenseeB },
  { table: "User", idSql: '"id"', a: fixtureIds.licenseeAdminA, b: fixtureIds.licenseeAdminB },
  {
    table: "ManufacturerLicenseeLink",
    idSql: `"manufacturerId" || ':' || "licenseeId"`,
    a: `${fixtureIds.manufacturerA}:${fixtureIds.licenseeA}`,
    b: `${fixtureIds.manufacturerB}:${fixtureIds.licenseeB}`,
  },
  { table: "InventoryStatusRollup", idSql: '"batchId"', a: a("Batch"), b: b("Batch") },
  ...[
    "Batch",
    "QRCode",
    "PrintJob",
    "PrintSession",
    "PrintItem",
    "PrinterRegistration",
    "Printer",
    "PrinterAttestation",
    "PrinterAgentSession",
    "PrinterProfile",
    "PrinterProfileSnapshot",
  ].map((table) => ({ table, idSql: '"id"', a: a(table), b: b(table) })),
]);

const ownTenant = (tenant) =>
  Object.fromEntries(tableProofs.map((proof) => [proof.table, [proof[tenant]].filter(Boolean)]));
const empty = () => Object.fromEntries(tableProofs.map(({ table }) => [table, []]));

const platformVisibility = Object.fromEntries(
  tableProofs.map((proof) => [
    proof.table,
    proof.table === "User"
      ? [
          fixtureIds.licenseeAdminA,
          fixtureIds.licenseeAdminB,
          fixtureIds.manufacturerA,
          fixtureIds.manufacturerB,
          fixtureIds.orgUserA,
          fixtureIds.platformAdmin,
        ].sort()
      : proof.table === "Printer"
        ? [proof.a, proof.b, "rls-harness-printer-null"].sort()
        : [proof.a, proof.b].sort(),
  ]),
);

const licenseeAVisibility = ownTenant("a");
licenseeAVisibility.User = [fixtureIds.licenseeAdminA, fixtureIds.manufacturerA].sort();

const manufacturerAVisibility = ownTenant("a");
manufacturerAVisibility.User = [fixtureIds.manufacturerA];

const licenseeBVisibility = ownTenant("b");
licenseeBVisibility.User = [fixtureIds.licenseeAdminB, fixtureIds.manufacturerB].sort();

export const contextMatrix = Object.freeze([
  {
    name: "platform_admin_explicit",
    settings: {
      userId: fixtureIds.platformAdmin,
      role: "PLATFORM_SUPER_ADMIN",
      isPlatformAdmin: "true",
    },
    expected: platformVisibility,
  },
  {
    name: "licensee_admin_a",
    settings: {
      userId: fixtureIds.licenseeAdminA,
      role: "LICENSEE_ADMIN",
      licenseeId: fixtureIds.licenseeA,
      organizationId: fixtureIds.orgA,
    },
    expected: licenseeAVisibility,
  },
  {
    name: "manufacturer_a",
    settings: {
      userId: fixtureIds.manufacturerA,
      role: "MANUFACTURER",
      licenseeId: fixtureIds.licenseeA,
      manufacturerId: fixtureIds.manufacturerA,
      organizationId: fixtureIds.orgA,
    },
    expected: manufacturerAVisibility,
  },
  {
    name: "dormant_org_admin_a",
    settings: {
      userId: fixtureIds.orgUserA,
      role: "ORG_ADMIN",
      organizationId: fixtureIds.orgA,
    },
    expected: empty(),
  },
  {
    name: "dormant_manufacturer_admin_a",
    settings: {
      userId: fixtureIds.manufacturerA,
      role: "MANUFACTURER_ADMIN",
      licenseeId: fixtureIds.licenseeA,
      manufacturerId: fixtureIds.manufacturerA,
      organizationId: fixtureIds.orgA,
    },
    expected: empty(),
  },
  {
    name: "dormant_manufacturer_user_a",
    settings: {
      userId: fixtureIds.manufacturerA,
      role: "MANUFACTURER_USER",
      licenseeId: fixtureIds.licenseeA,
      manufacturerId: fixtureIds.manufacturerA,
      organizationId: fixtureIds.orgA,
    },
    expected: empty(),
  },
  {
    name: "unrelated_tenant_b",
    settings: {
      userId: fixtureIds.licenseeAdminB,
      role: "LICENSEE_ADMIN",
      licenseeId: fixtureIds.licenseeB,
      organizationId: fixtureIds.orgB,
    },
    expected: licenseeBVisibility,
  },
  { name: "missing_context", settings: {}, expected: empty() },
  {
    name: "malformed_context",
    settings: {
      userId: fixtureIds.licenseeAdminA,
      role: "NOT_A_REAL_APPLICATION_ROLE",
      licenseeId: fixtureIds.licenseeA,
      manufacturerId: fixtureIds.manufacturerA,
      organizationId: fixtureIds.orgA,
      isPlatformAdmin: "definitely-not-boolean",
    },
    expected: empty(),
  },
  {
    name: "empty_string_context",
    settings: {
      userId: "",
      role: "",
      licenseeId: "",
      manufacturerId: "",
      organizationId: "",
      isPlatformAdmin: "",
    },
    expected: empty(),
  },
  {
    name: "tenant_a_attempts_tenant_b",
    settings: {
      userId: fixtureIds.licenseeAdminA,
      role: "LICENSEE_ADMIN",
      licenseeId: fixtureIds.licenseeA,
      organizationId: fixtureIds.orgA,
    },
    expected: licenseeAVisibility,
    forbiddenIds: Object.fromEntries(tableProofs.map((proof) => [proof.table, [proof.b]])),
  },
]);

export const fixtureSql = `
INSERT INTO "Organization" ("id", "name", "updatedAt") VALUES
  ('${fixtureIds.orgA}', 'RLS Harness Org A', now()),
  ('${fixtureIds.orgB}', 'RLS Harness Org B', now());
INSERT INTO "Licensee" ("id", "orgId", "name", "prefix", "updatedAt") VALUES
  ('${fixtureIds.licenseeA}', '${fixtureIds.orgA}', 'RLS Harness Licensee A', 'RLSHA', now()),
  ('${fixtureIds.licenseeB}', '${fixtureIds.orgB}', 'RLS Harness Licensee B', 'RLSHB', now());
INSERT INTO "User" ("id", "email", "name", "role", "orgId", "licenseeId", "updatedAt") VALUES
  ('${fixtureIds.platformAdmin}', 'rls-platform@harness.test', 'Platform Admin', 'PLATFORM_SUPER_ADMIN', NULL, NULL, now()),
  ('${fixtureIds.licenseeAdminA}', 'rls-licensee-a@harness.test', 'Licensee A', 'LICENSEE_ADMIN', '${fixtureIds.orgA}', '${fixtureIds.licenseeA}', now()),
  ('${fixtureIds.licenseeAdminB}', 'rls-licensee-b@harness.test', 'Licensee B', 'LICENSEE_ADMIN', '${fixtureIds.orgB}', '${fixtureIds.licenseeB}', now()),
  ('${fixtureIds.manufacturerA}', 'rls-manufacturer-a@harness.test', 'Manufacturer A', 'MANUFACTURER', '${fixtureIds.orgA}', '${fixtureIds.licenseeA}', now()),
  ('${fixtureIds.manufacturerB}', 'rls-manufacturer-b@harness.test', 'Manufacturer B', 'MANUFACTURER', '${fixtureIds.orgB}', '${fixtureIds.licenseeB}', now()),
  ('${fixtureIds.orgUserA}', 'rls-org-a@harness.test', 'Org A Admin', 'ORG_ADMIN', '${fixtureIds.orgA}', NULL, now());
INSERT INTO "ManufacturerLicenseeLink" ("manufacturerId", "licenseeId", "isPrimary", "updatedAt") VALUES
  ('${fixtureIds.manufacturerA}', '${fixtureIds.licenseeA}', true, now()),
  ('${fixtureIds.manufacturerB}', '${fixtureIds.licenseeB}', true, now());
INSERT INTO "PrinterRegistration" ("id", "userId", "orgId", "licenseeId", "deviceFingerprint", "agentId", "publicKeyPem", "updatedAt") VALUES
  ('${a("PrinterRegistration")}', '${fixtureIds.manufacturerA}', '${fixtureIds.orgA}', '${fixtureIds.licenseeA}', 'rls-device-a', 'rls-agent-a', 'fixture-public-key-a', now()),
  ('${b("PrinterRegistration")}', '${fixtureIds.manufacturerB}', '${fixtureIds.orgB}', '${fixtureIds.licenseeB}', 'rls-device-b', 'rls-agent-b', 'fixture-public-key-b', now());
INSERT INTO "Printer" ("id", "name", "connectionType", "printerRegistrationId", "orgId", "licenseeId", "assignedUserId", "createdByUserId", "updatedAt") VALUES
  ('${a("Printer")}', 'RLS Printer A', 'LOCAL_AGENT', '${a("PrinterRegistration")}', '${fixtureIds.orgA}', '${fixtureIds.licenseeA}', '${fixtureIds.manufacturerA}', '${fixtureIds.manufacturerA}', now()),
  ('${b("Printer")}', 'RLS Printer B', 'LOCAL_AGENT', '${b("PrinterRegistration")}', '${fixtureIds.orgB}', '${fixtureIds.licenseeB}', '${fixtureIds.manufacturerB}', '${fixtureIds.manufacturerB}', now()),
  ('rls-harness-printer-null', 'RLS Nullable Printer', 'NETWORK_DIRECT', NULL, NULL, NULL, NULL, NULL, now());
INSERT INTO "Batch" ("id", "name", "licenseeId", "manufacturerId", "startCode", "endCode", "totalCodes", "updatedAt") VALUES
  ('${a("Batch")}', 'RLS Batch A', '${fixtureIds.licenseeA}', '${fixtureIds.manufacturerA}', 'RLSHA0001', 'RLSHA0001', 1, now()),
  ('${b("Batch")}', 'RLS Batch B', '${fixtureIds.licenseeB}', '${fixtureIds.manufacturerB}', 'RLSHB0001', 'RLSHB0001', 1, now());
INSERT INTO "InventoryStatusRollup" ("batchId", "licenseeId", "manufacturerId", "totalCodes", "updatedAt") VALUES
  ('${a("Batch")}', '${fixtureIds.licenseeA}', '${fixtureIds.manufacturerA}', 1, now()),
  ('${b("Batch")}', '${fixtureIds.licenseeB}', '${fixtureIds.manufacturerB}', 1, now());
INSERT INTO "PrintJob" ("id", "batchId", "manufacturerId", "printerId", "quantity", "updatedAt") VALUES
  ('${a("PrintJob")}', '${a("Batch")}', '${fixtureIds.manufacturerA}', '${a("Printer")}', 1, now()),
  ('${b("PrintJob")}', '${b("Batch")}', '${fixtureIds.manufacturerB}', '${b("Printer")}', 1, now());
INSERT INTO "PrintSession" ("id", "printJobId", "batchId", "manufacturerId", "printerRegistrationId", "printerId", "totalItems", "updatedAt") VALUES
  ('${a("PrintSession")}', '${a("PrintJob")}', '${a("Batch")}', '${fixtureIds.manufacturerA}', '${a("PrinterRegistration")}', '${a("Printer")}', 1, now()),
  ('${b("PrintSession")}', '${b("PrintJob")}', '${b("Batch")}', '${fixtureIds.manufacturerB}', '${b("PrinterRegistration")}', '${b("Printer")}', 1, now());
INSERT INTO "QRCode" ("id", "code", "licenseeId", "batchId", "printJobId", "updatedAt") VALUES
  ('${a("QRCode")}', 'RLSHA0001', '${fixtureIds.licenseeA}', '${a("Batch")}', '${a("PrintJob")}', now()),
  ('${b("QRCode")}', 'RLSHB0001', '${fixtureIds.licenseeB}', '${b("Batch")}', '${b("PrintJob")}', now());
INSERT INTO "PrintItem" ("id", "printSessionId", "qrCodeId", "code", "updatedAt") VALUES
  ('${a("PrintItem")}', '${a("PrintSession")}', '${a("QRCode")}', 'RLSHA0001', now()),
  ('${b("PrintItem")}', '${b("PrintSession")}', '${b("QRCode")}', 'RLSHB0001', now());
INSERT INTO "PrinterAttestation" ("id", "printerRegistrationId", "signedPayloadHash", "heartbeatNonce", "attestedAt", "expiresAt") VALUES
  ('${a("PrinterAttestation")}', '${a("PrinterRegistration")}', 'rls-hash-a', 'rls-nonce-a', now(), now() + interval '1 hour'),
  ('${b("PrinterAttestation")}', '${b("PrinterRegistration")}', 'rls-hash-b', 'rls-nonce-b', now(), now() + interval '1 hour');
INSERT INTO "PrinterAgentSession" ("id", "connectionId", "registrationId", "agentId", "deviceFingerprint", "publicKeyFingerprint", "selectedPrinterId", "updatedAt") VALUES
  ('${a("PrinterAgentSession")}', 'rls-connection-a', '${a("PrinterRegistration")}', 'rls-agent-a', 'rls-device-a', 'rls-key-a', '${a("Printer")}', now()),
  ('${b("PrinterAgentSession")}', 'rls-connection-b', '${b("PrinterRegistration")}', 'rls-agent-b', 'rls-device-b', 'rls-key-b', '${b("Printer")}', now());
INSERT INTO "PrinterProfile" ("id", "printerId", "transportKind", "nativeLanguage", "supportedLanguages", "jobMode", "updatedAt") VALUES
  ('${a("PrinterProfile")}', '${a("Printer")}', 'USB_RAW', 'ZPL', '["ZPL"]'::jsonb, 'RAW', now()),
  ('${b("PrinterProfile")}', '${b("Printer")}', 'USB_RAW', 'ZPL', '["ZPL"]'::jsonb, 'RAW', now());
INSERT INTO "PrinterProfileSnapshot" ("id", "printerProfileId", "snapshotType", "data") VALUES
  ('${a("PrinterProfileSnapshot")}', '${a("PrinterProfile")}', 'LIVE_DISCOVERY', '{}'::jsonb),
  ('${b("PrinterProfileSnapshot")}', '${b("PrinterProfile")}', 'LIVE_DISCOVERY', '{}'::jsonb);
`;

export const truncateFixtureSql = `TRUNCATE TABLE ${tableProofs
  .map(({ table }) => `"${table}"`)
  .join(", ")} CASCADE;`;

export const contextSql = (settings = {}) => {
  const settingNames = {
    userId: "app.user_id",
    role: "app.role",
    licenseeId: "app.licensee_id",
    manufacturerId: "app.manufacturer_id",
    organizationId: "app.organization_id",
    isPlatformAdmin: "app.is_platform_admin",
  };
  return Object.entries(settings)
    .filter(([key]) => Object.hasOwn(settingNames, key))
    .map(([key, value]) => [settingNames[key], value ?? ""])
    .map(([name, value]) => `SET LOCAL ${name} = '${String(value).replaceAll("'", "''")}';`)
    .join("\n");
};

export const visibilitySql = `SELECT jsonb_build_object(
${tableProofs
  .map(
    ({ table, idSql }) =>
      `  '${table}', (SELECT COALESCE(jsonb_agg(scope_id ORDER BY scope_id), '[]'::jsonb) FROM (SELECT ${idSql} AS scope_id FROM "${table}") visible_${table.toLowerCase()})`,
  )
  .join(",\n")}
) AS visibility`;
