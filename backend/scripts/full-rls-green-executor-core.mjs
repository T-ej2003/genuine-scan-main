#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { GetSecretValueCommand, PutSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";

export const GREEN_EXECUTOR_MODES = Object.freeze([
  "full-rls-capability-preflight",
  "full-rls-role-provision",
  "full-rls-role-verify",
  "full-rls-admin-bootstrap",
  "full-rls-admin-ownership",
  "full-rls-runtime-policy",
  "full-rls-verification",
  "full-rls-rollback",
]);

const roleKeys = Object.freeze(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"]);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const packageRoot = path.resolve("scripts/rls/sql/generated");
const generatedRoot = path.resolve("documents/security/rls-program/generated");
const backendRoot = fs.existsSync(path.resolve("backend/prisma")) ? path.resolve("backend") : path.resolve(".");
const fixedModeFiles = Object.freeze({
  "full-rls-admin-bootstrap": "admin-bootstrap.sql",
  "full-rls-admin-ownership": "admin-ownership.sql",
  "full-rls-runtime-policy": "runtime-policy.sql",
  "full-rls-verification": "verification.sql",
  "full-rls-rollback": "clean-room-cleanup.sql",
});
const secretName = (target, key) => `${target.secretPrefix}${key}`;
const roleName = (target, key) => `${target.rolePrefix}${key}`;

export function validateGreenExecutorMode(target, mode, confirmation) {
  if (!GREEN_EXECUTOR_MODES.includes(mode)) throw new Error(`Mode is outside the reviewed ${target.environment} green executor set.`);
  const expected = target.confirmations[mode];
  if (expected ? confirmation !== expected : confirmation) {
    throw new Error("Executor confirmation does not match the fixed mode contract.");
  }
  return mode;
}

export function validateAdministratorUrl(target, raw) {
  const url = new URL(String(raw || ""));
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!["postgres:", "postgresql:"].includes(url.protocol)
      || url.username !== target.administrator
      || database !== target.maintenanceDatabase
      || !target.hostnamePattern.test(url.hostname)
      || target.forbiddenHostnamePattern.test(url.hostname)
      || url.searchParams.get("sslmode") !== "require") {
    throw new Error(`Executor refused an unreviewed ${target.environment} administrator endpoint.`);
  }
  return url;
}

export function verifyBoundPackage(target, {
  expectedSourceContract,
  expectedPackageChecksum,
  expectedReleaseSha,
  sqlRoot = packageRoot,
  evidenceRoot = generatedRoot,
}) {
  if (!/^[a-f0-9]{64}$/.test(expectedSourceContract || "")
      || !/^[a-f0-9]{64}$/.test(expectedPackageChecksum || "")
      || !/^[a-f0-9]{40}$/.test(expectedReleaseSha || "")) {
    throw new Error("Executor release binding is incomplete.");
  }
  const checksumPath = path.join(evidenceRoot, "checksums.json");
  const checksumBytes = fs.readFileSync(checksumPath);
  if (sha256(checksumBytes) !== expectedPackageChecksum) throw new Error("Executor package checksum mismatch.");
  const checksums = JSON.parse(checksumBytes);
  if (checksums.schemaVersion !== 3
      || checksums.deploymentModel !== "clean-room-blue-green"
      || checksums.sourceContractSha256 !== expectedSourceContract) {
    throw new Error("Executor package source contract mismatch.");
  }
  for (const [name, digest] of Object.entries(checksums.files || {})) {
    const root = name.endsWith(".sql") ? sqlRoot : evidenceRoot;
    const file = path.join(root, name);
    if (!fs.existsSync(file) || sha256(fs.readFileSync(file)) !== digest) {
      throw new Error(`Executor package file mismatch: ${name}`);
    }
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(evidenceRoot, "full-rls-implementation-manifest.json")));
  const expectedRoles = Object.fromEntries([
    ["owner", roleName(target, "owner")],
    ["authOwner", roleName(target, "auth_owner")],
    ...roleKeys.map((key) => [key, roleName(target, key)]),
  ]);
  if (manifest.targetEnvironment !== target.environment
      || manifest.deploymentId !== target.deploymentId
      || manifest.sourceContractSha256 !== expectedSourceContract
      || JSON.stringify(manifest.roles) !== JSON.stringify(expectedRoles)) {
    throw new Error("Executor package environment or role inventory mismatch.");
  }
  return { checksums, manifest, packageChecksum: expectedPackageChecksum };
}

const targetUrl = (target, adminUrl, username = target.administrator, password = adminUrl.password) => {
  const url = new URL(adminUrl);
  url.pathname = `/${target.database}`;
  url.username = username;
  url.password = password;
  url.searchParams.set("sslmode", "require");
  return url;
};

const psql = (url, args, label) => {
  const result = spawnSync("psql", [url.toString(), "-X", "-v", "ON_ERROR_STOP=1", ...args], {
    cwd: packageRoot,
    encoding: "utf8",
    env: { ...process.env, PGCONNECT_TIMEOUT: "10" },
  });
  if (result.status !== 0) throw new Error(`Green executor ${label} failed; database detail suppressed.`);
  return String(result.stdout || "").trim();
};

const query = (url, sql, label) => psql(url, ["-Atqc", sql], label);
const runFile = (url, file, label, variables = []) => {
  if (fixedModeFiles[label] !== file && label !== "full-rls-admin-bootstrap") {
    throw new Error("Executor refused an unreviewed package file.");
  }
  return psql(url, [...variables.flatMap(([key, value]) => ["-v", `${key}=${value}`]), "-f", file], label);
};

const databaseExists = (target, adminUrl) =>
  query(adminUrl, `SELECT count(*) FROM pg_database WHERE datname='${target.database}'`, "database-presence") === "1";

const managedRoleCount = (target, adminUrl) =>
  Number(query(adminUrl, `SELECT count(*) FROM pg_roles WHERE rolname LIKE '${target.rolePrefix}%'`, "managed-role-presence"));

const verifyAdministrator = (target, adminUrl) => {
  const result = query(
    adminUrl,
    "SELECT current_database()||'|'||current_user||'|'||(current_setting('server_version_num')::int/10000)::text||'|'||(NOT rolsuper AND NOT rolbypassrls AND rolcreaterole AND rolcreatedb)::text FROM pg_roles WHERE rolname=current_user",
    "administrator-preflight"
  );
  if (result !== `${target.maintenanceDatabase}|${target.administrator}|18|true`) {
    throw new Error(`${target.environment} green administrator identity or PostgreSQL version mismatch.`);
  }
};

const secretUrl = (target, adminUrl, key, password) =>
  targetUrl(target, adminUrl, roleName(target, key), password).toString();

const validateRuntimeUrl = (target, raw, key) => {
  const url = new URL(String(raw || ""));
  if (!["postgres:", "postgresql:"].includes(url.protocol)
      || url.username !== roleName(target, key)
      || decodeURIComponent(url.pathname.slice(1)) !== target.database
      || url.searchParams.get("sslmode") !== "require") {
    throw new Error("Runtime role secret verification failed.");
  }
  return url;
};

async function provisionRuntimeRoles(target, adminUrl, secretsManager) {
  if (!databaseExists(target, adminUrl)) throw new Error("Green database must be bootstrapped before role provisioning.");
  const credentials = Object.fromEntries(roleKeys.map((key) => [key, {
    password: crypto.randomBytes(48).toString("base64url"),
    url: null,
  }]));
  for (const [key, value] of Object.entries(credentials)) value.url = secretUrl(target, adminUrl, key, value.password);
  const statements = roleKeys.map((key) =>
    `ALTER ROLE "${roleName(target, key)}" PASSWORD '${credentials[key].password.replaceAll("'", "''")}'`
  ).join(";");
  query(targetUrl(target, adminUrl), `BEGIN;${statements};COMMIT;`, "runtime-role-passwords");
  for (const key of roleKeys) {
    await secretsManager.send(new PutSecretValueCommand({
      SecretId: secretName(target, key),
      ClientRequestToken: crypto.randomUUID(),
      SecretString: credentials[key].url,
      VersionStages: ["AWSCURRENT"],
    }));
  }
}

async function verifyRuntimeRoles(target, adminUrl, secretsManager) {
  const expected = roleKeys.map((key) => roleName(target, key)).sort().join(",");
  const actual = query(targetUrl(target, adminUrl), `SELECT string_agg(rolname,',' ORDER BY rolname) FROM pg_roles WHERE rolname IN (${roleKeys.map((key) => `'${roleName(target, key)}'`).join(",")}) AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls`, "runtime-role-verification");
  if (actual !== expected) throw new Error("Runtime role catalogue verification failed.");
  for (const key of roleKeys) {
    const value = await secretsManager.send(new GetSecretValueCommand({ SecretId: secretName(target, key), VersionStage: "AWSCURRENT" }));
    validateRuntimeUrl(target, value.SecretString, key);
  }
}

async function applySchemaMigrations(target, secretsManager) {
  const value = await secretsManager.send(new GetSecretValueCommand({
    SecretId: secretName(target, "migration"),
    VersionStage: "AWSCURRENT",
  }));
  const migrationUrl = validateRuntimeUrl(target, value.SecretString, "migration");
  const prisma = path.join(backendRoot, "node_modules", ".bin", "prisma");
  const result = spawnSync(prisma, ["migrate", "deploy"], {
    cwd: backendRoot,
    encoding: "utf8",
    env: { ...process.env, DATABASE_URL: migrationUrl.toString() },
  });
  if (result.status !== 0) throw new Error(`${target.environment} green schema migration failed; detail suppressed.`);
  if (target.environment === "production") {
    const provision = spawnSync(process.execPath, ["scripts/production-green-canary-provision.mjs"], {
      cwd: backendRoot,
      encoding: "utf8",
      env: { ...process.env, DATABASE_URL: migrationUrl.toString() },
    });
    if (provision.status !== 0) throw new Error("Production green canary provisioning failed; detail suppressed.");
  }
}

const catalogueFingerprint = (target, adminUrl) => sha256(JSON.stringify({
  databasePresent: databaseExists(target, adminUrl),
  managedRoleCount: managedRoleCount(target, adminUrl),
}));

const receipt = ({
  target,
  mode,
  releaseSha,
  sourceContract,
  packageChecksum,
  status,
  catalogueSha256,
  approval,
}) => {
  const value = {
    schemaVersion: 1,
    environment: target.environment,
    database: target.database,
    deploymentId: target.deploymentId,
    mode,
    status,
    releaseSha,
    sourceContractSha256: sourceContract,
    packageChecksumSha256: packageChecksum,
    ...(approval ? {
      migrationSetDigest: approval.approval.migrationSetDigest,
      approvalContractSha256: approval.approvalContractSha256,
      approvalId: approval.approval.approvalId,
      ticketId: approval.approval.ticketId,
      administratorIdentity: approval.approval.administratorIdentity,
      independentCheckerIdentity: approval.approval.independentCheckerIdentity,
      approvalExpiresAt: approval.approval.expiresAt,
    } : {}),
    catalogueSha256,
    completedAt: new Date().toISOString(),
    nonce: crypto.randomUUID(),
  };
  return { ...value, receiptSha256: sha256(`${JSON.stringify(value)}\n`) };
};

async function writeReceipt(target, value, bucket, s3) {
  if (!target.receiptBucketPattern.test(bucket || "")) {
    throw new Error(`Executor receipt bucket is outside the reviewed ${target.environment} boundary.`);
  }
  const key = `rls-receipts/${value.releaseSha}/${value.mode}/${value.nonce}.json`;
  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: `${JSON.stringify(value)}\n`,
    ContentType: "application/json",
    ServerSideEncryption: "AES256",
    IfNoneMatch: "*",
  }));
  return { bucket, key, receiptSha256: value.receiptSha256 };
}

export async function executeFullRlsGreenMode(target, {
  env = process.env,
  secretsManager = new SecretsManagerClient({ region: target.region }),
  s3 = new S3Client({ region: target.region }),
  validateApproval = null,
} = {}) {
  const mode = validateGreenExecutorMode(target, env.MSCQR_FULL_RLS_MODE, env.MSCQR_FULL_RLS_CONFIRMATION || "");
  const adminUrl = validateAdministratorUrl(target, env.DATABASE_URL);
  const bound = verifyBoundPackage(target, {
    expectedSourceContract: env.MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256,
    expectedPackageChecksum: env.MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256,
    expectedReleaseSha: env.RELEASE_GIT_SHA,
  });
  const approval = validateApproval
    ? await validateApproval(env.MSCQR_PRODUCTION_RLS_APPROVAL_ARTIFACT, {
      releaseSha: env.RELEASE_GIT_SHA,
      sourceContractSha256: bound.checksums.sourceContractSha256,
      migrationSetDigest: bound.checksums.migrationSetDigest,
      packageChecksumSha256: bound.packageChecksum,
      deploymentId: target.deploymentId,
      greenDatabase: target.database,
      administratorIdentity: target.administrator,
      kmsKeyArn: env.MSCQR_PRODUCTION_RLS_APPROVAL_KMS_KEY_ARN,
    }, { allowExpiredRollback: mode === "full-rls-rollback" })
    : null;
  if (validateApproval && bound.checksums.productionApprovalContractSha256
      && (bound.checksums.productionApprovalContractSha256 !== approval.approvalContractSha256
        || bound.manifest.administrativeExecutor?.approval?.approvalContractSha256 !== approval.approvalContractSha256)) {
    throw new Error("Production approval does not match the generated package.");
  }
  verifyAdministrator(target, adminUrl);
  if (mode === "full-rls-capability-preflight") {
    if (databaseExists(target, adminUrl) || managedRoleCount(target, adminUrl) !== 0) {
      throw new Error(`${target.environment} green preflight requires an absent fresh target and role namespace.`);
    }
  } else if (mode === "full-rls-admin-bootstrap") {
    if (databaseExists(target, adminUrl)) throw new Error(`${target.environment} green bootstrap refuses a pre-existing target database.`);
    query(adminUrl, `CREATE DATABASE "${target.database}" OWNER "${target.administrator}" TEMPLATE template0`, mode);
    runFile(targetUrl(target, adminUrl), "admin-bootstrap.sql", mode);
  } else if (mode === "full-rls-role-provision") {
    await provisionRuntimeRoles(target, adminUrl, secretsManager);
  } else if (mode === "full-rls-role-verify") {
    await verifyRuntimeRoles(target, adminUrl, secretsManager);
  } else if (mode === "full-rls-rollback") {
    if (!databaseExists(target, adminUrl)) throw new Error("Exact rollback requires the reviewed green database.");
    query(adminUrl, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${target.database}' AND pid<>pg_backend_pid();DROP DATABASE "${target.database}"`, mode);
    runFile(adminUrl, "clean-room-cleanup.sql", mode, [["candidate_database", target.database]]);
    if (databaseExists(target, adminUrl) || managedRoleCount(target, adminUrl) !== 0) {
      throw new Error("Exact rollback did not restore the fresh pre-activation catalogue.");
    }
  } else {
    if (!databaseExists(target, adminUrl)) throw new Error("Green database is unavailable for the requested package phase.");
    if (mode === "full-rls-admin-ownership") await applySchemaMigrations(target, secretsManager);
    runFile(targetUrl(target, adminUrl), fixedModeFiles[mode], mode);
  }
  const value = receipt({
    target,
    mode,
    releaseSha: env.RELEASE_GIT_SHA,
    sourceContract: bound.checksums.sourceContractSha256,
    packageChecksum: bound.packageChecksum,
    status: "passed",
    catalogueSha256: catalogueFingerprint(target, adminUrl),
    approval,
  });
  const stored = await writeReceipt(target, value, env.MSCQR_FULL_RLS_RECEIPT_BUCKET, s3);
  process.stdout.write(`${JSON.stringify({ status: "passed", mode, ...stored })}\n`);
  return value;
}
