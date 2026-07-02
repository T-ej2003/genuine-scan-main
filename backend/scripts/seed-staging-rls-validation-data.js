#!/usr/bin/env node

const {
  BatchLifecycleState,
  PrismaClient,
  QRStatus,
  UserRole,
  UserStatus,
} = require("@prisma/client");

const ENABLED_ENV = "STAGING_RLS_SEED_ENABLED";
const CONFIRM_ENV = "STAGING_RLS_SEED_CONFIRM";
const CONFIRMATION_PHRASE = "MSCQR_CREATE_STAGING_RLS_VALIDATION_DATA";
const NODE_ENV_PRODUCTION_OVERRIDE = "STAGING_RLS_SEED_ALLOW_PRODUCTION_NODE_ENV_FOR_STAGING";
const SEED_ENVIRONMENT_ENV = "STAGING_RLS_SEED_ENVIRONMENT";
const ALLOWED_DB_HOSTS_ENV = "STAGING_RLS_SEED_ALLOWED_DB_HOSTS";

const IDS = Object.freeze({
  org: "00000000-0000-4302-8000-000000000001",
  licensee: "00000000-0000-4302-8100-000000000001",
  licenseeAdmin: "00000000-0000-4302-8200-000000000001",
  manufacturer: "00000000-0000-4302-8200-000000000002",
  qrRange: "00000000-0000-4302-8350-000000000001",
  batch: "00000000-0000-4302-8300-000000000001",
});

const QR_COUNT = 5;
const LABEL = "MSCQR Staging RLS Validation";
const LICENSEE_PREFIX = "SRV";
const QR_CODES = Array.from({ length: QR_COUNT }, (_, index) => `SRV-RLS-${String(index + 1).padStart(4, "0")}`);
const QR_IDS = QR_CODES.map((_, index) => `00000000-0000-4302-8400-${String(index + 1).padStart(12, "0")}`);

const usage = `Usage:
  node scripts/seed-staging-rls-validation-data.js --help
  STAGING_RLS_SEED_ENABLED=true \\
  STAGING_RLS_SEED_CONFIRM=${CONFIRMATION_PHRASE} \\
  STAGING_RLS_SEED_ENVIRONMENT=staging \\
  DATABASE_URL=<staging-postgres-url> \\
  node scripts/seed-staging-rls-validation-data.js

Creates or reuses a small synthetic staging-only data set for the RLS evidence collector.

Safety contract:
  - refuses to run without ${ENABLED_ENV}=true
  - refuses to run unless ${CONFIRM_ENV}=${CONFIRMATION_PHRASE}
  - refuses missing or production-looking DATABASE_URL values
  - refuses non-local DATABASE_URL hosts unless host/database/user clearly contains staging/stg/test/p2/tmp/temporary/local
  - accepts exact reviewed non-local DB hosts only through ${ALLOWED_DB_HOSTS_ENV}
  - refuses NODE_ENV=production unless ${NODE_ENV_PRODUCTION_OVERRIDE}=true and ${SEED_ENVIRONMENT_ENV}=staging
  - does not call external APIs, does not create auth tokens, and does not enable RLS
  - prints safe JSON only and never prints DATABASE_URL, QR codes, raw tokens, or secrets
`;

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const print = (payload) => console.log(JSON.stringify(payload, null, 2));

class StagingRlsSeedRefusalError extends Error {
  constructor(message, code = "STAGING_RLS_VALIDATION_SEED_REFUSED") {
    super(message);
    this.name = "StagingRlsSeedRefusalError";
    this.code = code;
  }
}

const refuse = (message, code) => {
  throw new StagingRlsSeedRefusalError(message, code);
};

const readAllowedDbHosts = (env = process.env) =>
  new Set(
    String(env[ALLOWED_DB_HOSTS_ENV] || "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean)
  );

const parseDatabaseUrl = (raw) => {
  try {
    return new URL(raw);
  } catch {
    refuse("DATABASE_URL must be a valid PostgreSQL URL; the value was not printed.");
  }
};

const assertDatabaseUrlSafe = (databaseUrl, env = process.env) => {
  const raw = String(databaseUrl || "").trim();
  if (!raw) refuse("DATABASE_URL is required; it will not be printed.");

  const parsed = parseDatabaseUrl(raw);
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    refuse("DATABASE_URL must use postgres/postgresql for the staging seed.");
  }

  const lower = raw.toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, "")).toLowerCase();
  const productionMarkers = ["mscqr-prod", "mscqr-prod-db-proxy", "production", "prod"];
  if (productionMarkers.some((marker) => lower.includes(marker))) {
    refuse("Refusing production-looking DATABASE_URL.");
  }

  const isAwsRdsHost = host.endsWith(".rds.amazonaws.com") || host.includes(".rds.amazonaws.com.");
  const rdsLooksStaging = host.includes("staging") || host.includes("stg");
  const safeMarkerSource = `${host} ${databaseName} ${parsed.username}`.toLowerCase();
  const hasStagingOrTestMarker = /(staging|stg|test|p2|tmp|temporary|local)/.test(safeMarkerSource);
  const isLocalHost = ["localhost", "127.0.0.1", "::1", "postgres"].includes(host) || host.endsWith(".local");
  const allowedDbHosts = readAllowedDbHosts(env);
  const isExplicitlyAllowedHost = allowedDbHosts.has(host);

  if (isAwsRdsHost && !rdsLooksStaging && !isExplicitlyAllowedHost) {
    refuse("Refusing AWS RDS DATABASE_URL unless the host clearly names staging/stg or is exactly reviewed in STAGING_RLS_SEED_ALLOWED_DB_HOSTS.");
  }

  if (!isLocalHost && !hasStagingOrTestMarker && !isExplicitlyAllowedHost) {
    refuse("Refusing non-local DATABASE_URL without a staging/test/local marker or exact reviewed DB host allowlist entry.");
  }

  return { host, databaseName, isLocalHost, hasStagingOrTestMarker };
};

const assertNodeEnvironmentSafe = (env, databaseSafety) => {
  const nodeEnv = String(env.NODE_ENV || "").trim().toLowerCase();
  if (nodeEnv !== "production") return;

  const override = isTruthy(env[NODE_ENV_PRODUCTION_OVERRIDE]);
  const seedEnvironment = String(env[SEED_ENVIRONMENT_ENV] || "").trim().toLowerCase();
  if (!override || seedEnvironment !== "staging") {
    throw new Error(
      `Refusing NODE_ENV=production unless ${NODE_ENV_PRODUCTION_OVERRIDE}=true and ${SEED_ENVIRONMENT_ENV}=staging.`
    );
  }
  if (!databaseSafety.isLocalHost && !databaseSafety.hasStagingOrTestMarker) {
    refuse("Refusing NODE_ENV=production override because DATABASE_URL does not clearly name staging/test/local.");
  }
};

const readConfig = (env = process.env) => {
  if (!isTruthy(env[ENABLED_ENV])) {
    refuse(`${ENABLED_ENV}=true is required.`);
  }
  if (String(env[CONFIRM_ENV] || "").trim() !== CONFIRMATION_PHRASE) {
    refuse(`${CONFIRM_ENV} must equal ${CONFIRMATION_PHRASE}.`);
  }
  const databaseSafety = assertDatabaseUrlSafe(env.DATABASE_URL, env);
  assertNodeEnvironmentSafe(env, databaseSafety);

  const seedEnvironment = String(env[SEED_ENVIRONMENT_ENV] || "staging").trim().toLowerCase();
  if (!["staging", "test", "p2", "local"].includes(seedEnvironment)) {
    refuse(`${SEED_ENVIRONMENT_ENV} must be staging, test, p2, or local.`);
  }

  return {
    seedEnvironment,
    nodeEnv: String(env.NODE_ENV || "").trim() || null,
  };
};

const ownedMetadata = (entity) => ({
  purpose: "staging_rls_validation_seed",
  owner: "mscqr-staging-rls-validation",
  entity,
  synthetic: true,
  productionData: false,
});

const assertOwned = (condition, message) => {
  if (!condition) refuse(message);
};

const hasOwnedMetadata = (record) => {
  const metadata = record?.metadata;
  return Boolean(metadata && typeof metadata === "object" && metadata.purpose === "staging_rls_validation_seed");
};

const ensureOrganization = async (tx, result) => {
  const existing = await tx.organization.findUnique({ where: { id: IDS.org } });
  if (existing) {
    assertOwned(existing.name === `${LABEL} Organization`, "Existing staging validation organization ID is not owned by this seed.");
    await tx.organization.update({ where: { id: IDS.org }, data: { name: `${LABEL} Organization`, isActive: true } });
    result.reused.organization = true;
    return existing;
  }
  result.created.organization = true;
  return tx.organization.create({
    data: {
      id: IDS.org,
      name: `${LABEL} Organization`,
      isActive: true,
    },
  });
};

const ensureLicensee = async (tx, result) => {
  const prefixConflict = await tx.licensee.findUnique({ where: { prefix: LICENSEE_PREFIX } });
  assertOwned(!prefixConflict || prefixConflict.id === IDS.licensee, "Licensee prefix SRV is already owned by another tenant.");

  const existing = await tx.licensee.findUnique({ where: { id: IDS.licensee } });
  const data = {
    orgId: IDS.org,
    name: `${LABEL} Licensee`,
    prefix: LICENSEE_PREFIX,
    brandName: `${LABEL} Synthetic Brand`,
    description: "Synthetic non-production tenant for staged RLS collector validation.",
    supportEmail: "staging-rls-validation@example.invalid",
    metadata: ownedMetadata("licensee"),
    isActive: true,
    suspendedAt: null,
    suspendedReason: null,
  };
  if (existing) {
    assertOwned(existing.prefix === LICENSEE_PREFIX && hasOwnedMetadata(existing), "Existing staging validation licensee is not owned by this seed.");
    result.reused.licensee = true;
    return tx.licensee.update({ where: { id: IDS.licensee }, data });
  }
  result.created.licensee = true;
  return tx.licensee.create({ data: { id: IDS.licensee, ...data } });
};

const ensureUser = async (tx, result, key, id, email, role, name) => {
  const emailConflict = await tx.user.findUnique({ where: { email } });
  assertOwned(!emailConflict || emailConflict.id === id, `Synthetic ${key} email is already owned by another user.`);

  const existing = await tx.user.findUnique({ where: { id } });
  const data = {
    email,
    passwordHash: null,
    name,
    role,
    orgId: IDS.org,
    licenseeId: IDS.licensee,
    metadata: ownedMetadata(key),
    status: UserStatus.ACTIVE,
    isActive: true,
    disabledAt: null,
    disabledReason: null,
    deletedAt: null,
    emailVerifiedAt: new Date(),
  };
  if (existing) {
    assertOwned(existing.email === email && hasOwnedMetadata(existing), `Existing staging validation ${key} user is not owned by this seed.`);
    result.reused[key] = true;
    return tx.user.update({ where: { id }, data });
  }
  result.created[key] = true;
  return tx.user.create({ data: { id, ...data } });
};

const ensureManufacturerLink = async (tx, result) => {
  const existing = await tx.manufacturerLicenseeLink.findUnique({
    where: { manufacturerId_licenseeId: { manufacturerId: IDS.manufacturer, licenseeId: IDS.licensee } },
  });
  if (existing) {
    result.reused.manufacturerLicenseeLink = true;
    return tx.manufacturerLicenseeLink.update({
      where: { manufacturerId_licenseeId: { manufacturerId: IDS.manufacturer, licenseeId: IDS.licensee } },
      data: { isPrimary: true },
    });
  }
  result.created.manufacturerLicenseeLink = true;
  return tx.manufacturerLicenseeLink.create({
    data: { manufacturerId: IDS.manufacturer, licenseeId: IDS.licensee, isPrimary: true },
  });
};

const ensureQrRange = async (tx, result) => {
  const existing = await tx.qRRange.findUnique({ where: { id: IDS.qrRange } });
  const data = {
    licenseeId: IDS.licensee,
    startCode: QR_CODES[0],
    endCode: QR_CODES[QR_CODES.length - 1],
    totalCodes: QR_CODES.length,
    usedCodes: QR_CODES.length,
  };
  if (existing) {
    assertOwned(existing.licenseeId === IDS.licensee && existing.startCode === QR_CODES[0], "Existing staging validation QR range is not owned by this seed.");
    result.reused.qrRange = true;
    return tx.qRRange.update({ where: { id: IDS.qrRange }, data });
  }
  result.created.qrRange = true;
  return tx.qRRange.create({ data: { id: IDS.qrRange, ...data } });
};

const ensureBatch = async (tx, result) => {
  const existing = await tx.batch.findUnique({ where: { id: IDS.batch } });
  const data = {
    name: `${LABEL} Batch`,
    licenseeId: IDS.licensee,
    manufacturerId: IDS.manufacturer,
    startCode: QR_CODES[0],
    endCode: QR_CODES[QR_CODES.length - 1],
    totalCodes: QR_CODES.length,
    lifecycleState: BatchLifecycleState.CODES_GENERATED,
    metadata: ownedMetadata("batch"),
    suspendedAt: null,
    suspendedReason: null,
  };
  if (existing) {
    assertOwned(existing.name === `${LABEL} Batch` && hasOwnedMetadata(existing), "Existing staging validation batch is not owned by this seed.");
    result.reused.batch = true;
    return tx.batch.update({ where: { id: IDS.batch }, data });
  }
  result.created.batch = true;
  return tx.batch.create({ data: { id: IDS.batch, ...data } });
};

const ensureQrCodes = async (tx, result) => {
  let created = 0;
  let reused = 0;
  for (const [index, code] of QR_CODES.entries()) {
    const id = QR_IDS[index];
    const codeConflict = await tx.qRCode.findUnique({ where: { code } });
    assertOwned(!codeConflict || codeConflict.id === id, "Synthetic staging QR code is already owned by another row.");

    const existing = await tx.qRCode.findUnique({ where: { id } });
    const data = {
      code,
      displayCode: null,
      licenseeId: IDS.licensee,
      batchId: IDS.batch,
      status: QRStatus.ALLOCATED,
      printJobId: null,
      printedAt: null,
      printedByUserId: null,
      issuanceMode: "STAGING_RLS_VALIDATION",
      customerVerifiableAt: null,
      tokenNonce: null,
      tokenHash: null,
      tokenIssuedAt: null,
      tokenExpiresAt: null,
    };
    if (existing) {
      assertOwned(existing.code === code && existing.licenseeId === IDS.licensee, "Existing staging validation QR code is not owned by this seed.");
      await tx.qRCode.update({ where: { id }, data });
      reused += 1;
    } else {
      await tx.qRCode.create({ data: { id, ...data } });
      created += 1;
    }
  }
  result.created.qrCodes = created;
  result.reused.qrCodes = reused;
};

const seedStagingRlsValidationData = async (config, prisma = new PrismaClient()) => {
  const result = {
    ok: true,
    status: "ready",
    seedEnvironment: config.seedEnvironment,
    mutatesProduction: false,
    enablesRls: false,
    createsAuthTokens: false,
    created: {
      organization: false,
      licensee: false,
      licenseeAdmin: false,
      manufacturer: false,
      manufacturerLicenseeLink: false,
      qrRange: false,
      batch: false,
      qrCodes: 0,
      printers: 0,
    },
    reused: {
      organization: false,
      licensee: false,
      licenseeAdmin: false,
      manufacturer: false,
      manufacturerLicenseeLink: false,
      qrRange: false,
      batch: false,
      qrCodes: 0,
      printers: 0,
    },
    counts: {
      batches: 1,
      qrCodes: QR_COUNT,
      printersCreated: 0,
      externalApiCalls: 0,
    },
    stagingBatchId: IDS.batch,
    operatorOnlyFields: ["stagingBatchId"],
    collectorEnvExample: {
      STAGING_BASE_URL: "<staging-base-url>",
      STAGING_AUTH_TOKEN: "<redacted-bearer-token>",
      STAGING_BATCH_ID: IDS.batch,
      RLS_VALIDATION_SAMPLES: "1",
    },
  };

  await prisma.$transaction(async (tx) => {
    await ensureOrganization(tx, result);
    await ensureLicensee(tx, result);
    await ensureUser(
      tx,
      result,
      "licenseeAdmin",
      IDS.licenseeAdmin,
      "staging-rls-validation-licensee@example.invalid",
      UserRole.LICENSEE_ADMIN,
      `${LABEL} Licensee Operator`,
    );
    await ensureUser(
      tx,
      result,
      "manufacturer",
      IDS.manufacturer,
      "staging-rls-validation-manufacturer@example.invalid",
      UserRole.MANUFACTURER,
      `${LABEL} Manufacturer Operator`,
    );
    await ensureManufacturerLink(tx, result);
    await ensureQrRange(tx, result);
    await ensureBatch(tx, result);
    await ensureQrCodes(tx, result);
  });

  return result;
};

const main = async () => {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(usage);
    return;
  }

  let prisma;
  try {
    const config = readConfig(process.env);
    prisma = new PrismaClient();
    print(await seedStagingRlsValidationData(config, prisma));
  } catch (error) {
    const isSafeRefusal = error instanceof StagingRlsSeedRefusalError;
    print({
      ok: false,
      status: "refused",
      errorCode: isSafeRefusal ? error.code : "STAGING_RLS_VALIDATION_SEED_RUNTIME_ERROR",
      diagnostic: isSafeRefusal
        ? error.message
        : "Staging RLS validation seed failed before completion. Check local logs with secrets redacted.",
      databaseUrlPrinted: false,
      authTokenPrinted: false,
      secretPrinted: false,
      mutatesProduction: false,
      enablesRls: false,
    });
    process.exitCode = 1;
  } finally {
    await prisma?.$disconnect?.().catch(() => undefined);
  }
};

if (require.main === module) {
  main();
}

module.exports = {
  ALLOWED_DB_HOSTS_ENV,
  CONFIRMATION_PHRASE,
  IDS,
  QR_CODES,
  StagingRlsSeedRefusalError,
  assertDatabaseUrlSafe,
  isTruthy,
  readConfig,
  seedStagingRlsValidationData,
};
