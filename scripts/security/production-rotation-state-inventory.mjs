import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROLE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

export function buildRotationInventorySql(role) {
  if (!ROLE_PATTERN.test(role)) throw new Error("read-only inventory requires a reviewed RLS role");
  return `BEGIN; SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '2000ms'; SET LOCAL ROLE "${role}"; SELECT json_build_object(
  'refreshSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."RefreshToken" WHERE "revokedAt" IS NULL AND "expiresAt" > now()),
  'adminSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max(r."expiresAt")) FROM public."RefreshToken" r JOIN public."User" u ON u."id" = r."userId" WHERE r."revokedAt" IS NULL AND r."expiresAt" > now() AND u."status"::text = 'ACTIVE' AND u."isActive" = true AND u."deletedAt" IS NULL AND u."role"::text IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN', 'LICENSEE_ADMIN', 'ORG_ADMIN', 'MANUFACTURER_ADMIN')),
  'customerSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."CustomerAuthSession" WHERE "revokedAt" IS NULL AND "expiresAt" > now()),
  'customerVerificationState', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."CustomerVerificationSession" WHERE "expiresAt" IS NULL OR "expiresAt" > now()),
  'activeInvites', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."Invite" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'resetTokens', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."PasswordReset" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'emailVerification', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."EmailVerificationToken" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'qrArtifacts', (SELECT json_build_object('count', coalesce(sum(mode_count), 0)::int, 'maxExpiry', max(max_expiry), 'issuanceModes', coalesce(json_object_agg(mode, mode_count), '{}'::json), 'keyVersions', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'QRCode has no persisted signing-key version column')) FROM (SELECT "issuanceMode" AS mode, count(*)::int AS mode_count, max("tokenExpiresAt") AS max_expiry FROM public."QRCode" WHERE "tokenExpiresAt" > now() GROUP BY "issuanceMode") q),
  'printerTestQrArtifacts', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'printer-test identifiers are synthetic signed payload metadata and are not persisted as QRCode rows'),
  'artifactRecords', (SELECT json_build_object('count', coalesce(sum(algorithm_count), 0)::int, 'maxFinishedAt', max(max_finished_at), 'signatureAlgorithms', coalesce(json_object_agg(algorithm, algorithm_count), '{}'::json)) FROM (SELECT coalesce("signatureAlgorithm", 'unknown') AS algorithm, count(*)::int AS algorithm_count, max("finishedAt") AS max_finished_at FROM public."CompliancePackJob" WHERE "finishedAt" IS NOT NULL GROUP BY coalesce("signatureAlgorithm", 'unknown')) a),
  'legacyComplianceArtifacts', (SELECT json_build_object('count', count(*)::int, 'maxFinishedAt', max("finishedAt")) FROM public."CompliancePackJob" WHERE "finishedAt" IS NOT NULL AND lower(coalesce("signatureAlgorithm", '')) <> 'ed25519'),
  'legacyImmutableAuditArtifacts', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'AuditLog has no legacy-artifact marker or separate immutable-artifact relation'),
  'oauthState', json_build_object('persisted', false, 'maxTtlSeconds', 900), 'oauthExchange', json_build_object('persisted', false, 'maxTtlSeconds', 600), 'printedQrCompatibility', json_build_object('maxConfiguredTtlSeconds', 31536000)) AS inventory; ROLLBACK;`;
}

export function executeProductionRotationInventory({ spawn = spawnSync, env = process.env } = {}) {
  const role = String(env.ROTATION_INVENTORY_RLS_ROLE || "").trim();
  if (env.ROTATION_INVENTORY_APPROVED !== "true" || !ROLE_PATTERN.test(role)) throw new Error("read-only inventory requires ROTATION_INVENTORY_APPROVED=true and a reviewed RLS role");
  if (!env.DATABASE_URL) throw new Error("DATABASE_URL must be provided by the approved read-only runtime");
  const result = spawn("psql", ["--no-psqlrc", "--tuples-only", "--no-align", "--command", buildRotationInventorySql(role)], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...env, PSQL_HISTORY: "/dev/null", PGAPPNAME: "mscqr-production-rotation-read-only-inventory" } });
  if (result.status !== 0) throw new Error("read-only rotation inventory query failed");
  try { return JSON.parse(String(result.stdout || "").trim()); } catch { throw new Error("read-only rotation inventory returned malformed metadata"); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) console.log(JSON.stringify(executeProductionRotationInventory()));
