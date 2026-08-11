import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assertBoundedRotationInventory, ROTATION_INVENTORY_CATEGORIES } from "../security/production-runtime-rotation-inventory.mjs";
import { buildRotationInventorySql, executeProductionRotationInventory } from "../security/production-rotation-state-inventory.mjs";

const fixtureUrl = process.env.MSCQR_ROTATION_INVENTORY_FIXTURE_DATABASE_URL;
const skipOutsideCi = !fixtureUrl && process.env.CI !== "true";
const organizationId = "00000000-0000-4000-8000-000000000001";
const licenseeId = "00000000-0000-4000-8000-000000000002";
const qrIds = ["00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013"];
const artifactIds = ["00000000-0000-4000-8000-000000000021", "00000000-0000-4000-8000-000000000022", "00000000-0000-4000-8000-000000000023"];

const runSql = (sql) => execFileSync("psql", [fixtureUrl, "-v", "ON_ERROR_STOP=1", "-c", sql], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const runInventory = () => {
  try {
    return executeProductionRotationInventory({ env: { ...process.env, DATABASE_URL: fixtureUrl, ROTATION_INVENTORY_APPROVED: "true", ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls" } });
  } catch (error) {
    execFileSync("psql", [fixtureUrl, "-v", "ON_ERROR_STOP=1", "--command", buildRotationInventorySql("mscqr_prod_rls")], { stdio: ["ignore", "inherit", "inherit"] });
    throw error;
  }
};

function assertInventoryShape(inventory) {
  assert.deepEqual(Object.keys(inventory).sort(), [...ROTATION_INVENTORY_CATEGORIES].sort());
  assert.doesNotThrow(() => assertBoundedRotationInventory(inventory));
  const visit = (value) => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (!value || typeof value !== "object") return;
    for (const [key, nested] of Object.entries(value)) {
      assert.doesNotMatch(key, /token|secret|password|credential|databaseurl/i);
      visit(nested);
    }
  };
  visit(inventory);
  assert.doesNotMatch(JSON.stringify(inventory), /postgresql:\/\/|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i);
}

test("production-shaped rotation inventory executes against PostgreSQL for empty and representative data", { skip: skipOutsideCi }, () => {
  assert.ok(fixtureUrl, "MSCQR_ROTATION_INVENTORY_FIXTURE_DATABASE_URL is required in CI");
  runSql(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mscqr_prod_rls') THEN
        CREATE ROLE mscqr_prod_rls NOLOGIN;
      END IF;
    END $$;
    GRANT USAGE ON SCHEMA public TO mscqr_prod_rls;
    GRANT SELECT ON TABLE public."RefreshToken", public."User", public."CustomerAuthSession", public."CustomerVerificationSession", public."Invite", public."PasswordReset", public."EmailVerificationToken", public."QRCode", public."CompliancePackJob" TO mscqr_prod_rls;
  `);

  try {
    runSql(`DELETE FROM public."CompliancePackJob"; DELETE FROM public."QRCode"; DELETE FROM public."Licensee" WHERE id = '${licenseeId}'; DELETE FROM public."Organization" WHERE id = '${organizationId}';`);
    const empty = runInventory();
    assertInventoryShape(empty);
    assert.equal(empty.qrArtifacts.count, 0);
    assert.equal(empty.qrArtifacts.maxExpiry, null);
    assert.deepEqual(empty.qrArtifacts.issuanceModes, {});
    assert.equal(empty.artifactRecords.count, 0);
    assert.equal(empty.artifactRecords.maxFinishedAt, null);
    assert.deepEqual(empty.artifactRecords.signatureAlgorithms, {});

    runSql(`
      INSERT INTO public."Organization" ("id", "name", "isActive", "createdAt", "updatedAt") VALUES ('${organizationId}', 'rotation inventory fixture', true, '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z');
      INSERT INTO public."Licensee" ("id", "orgId", "name", "prefix", "isActive", "createdAt", "updatedAt") VALUES ('${licenseeId}', '${organizationId}', 'rotation inventory fixture', 'RIF', true, '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z');
      INSERT INTO public."QRCode" ("id", "code", "licenseeId", "tokenExpiresAt", "issuanceMode", "createdAt", "updatedAt") VALUES
        ('${qrIds[0]}', 'rotation-fixture-1', '${licenseeId}', '2030-01-02T00:00:00Z', 'SIGNED', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z'),
        ('${qrIds[1]}', 'rotation-fixture-2', '${licenseeId}', '2030-01-03T00:00:00Z', 'SIGNED', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z'),
        ('${qrIds[2]}', 'rotation-fixture-3', '${licenseeId}', '2030-01-02T00:00:00Z', 'HMAC', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z');
      INSERT INTO public."CompliancePackJob" ("id", "status", "triggerType", "signatureAlgorithm", "finishedAt", "createdAt", "updatedAt") VALUES
        ('${artifactIds[0]}', 'COMPLETED', 'FIXTURE', 'Ed25519', '2030-02-02T00:00:00Z', '2030-02-01T00:00:00Z', '2030-02-02T00:00:00Z'),
        ('${artifactIds[1]}', 'COMPLETED', 'FIXTURE', 'Ed25519', '2030-02-03T00:00:00Z', '2030-02-01T00:00:00Z', '2030-02-03T00:00:00Z'),
        ('${artifactIds[2]}', 'COMPLETED', 'FIXTURE', 'RSA', '2030-02-02T00:00:00Z', '2030-02-01T00:00:00Z', '2030-02-02T00:00:00Z');
    `);

    const representative = runInventory();
    assertInventoryShape(representative);
    assert.equal(representative.qrArtifacts.count, 3);
    assert.equal(new Date(representative.qrArtifacts.maxExpiry).toISOString(), "2030-01-03T00:00:00.000Z");
    assert.deepEqual(representative.qrArtifacts.issuanceModes, { HMAC: 1, SIGNED: 2 });
    assert.equal(representative.artifactRecords.count, 3);
    assert.equal(new Date(representative.artifactRecords.maxFinishedAt).toISOString(), "2030-02-03T00:00:00.000Z");
    assert.deepEqual(representative.artifactRecords.signatureAlgorithms, { Ed25519: 2, RSA: 1 });
  } finally {
    runSql(`DELETE FROM public."CompliancePackJob" WHERE id IN ('${artifactIds.join("','")}'); DELETE FROM public."QRCode" WHERE id IN ('${qrIds.join("','")}'); DELETE FROM public."Licensee" WHERE id = '${licenseeId}'; DELETE FROM public."Organization" WHERE id = '${organizationId}'; REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM mscqr_prod_rls; REVOKE ALL PRIVILEGES ON SCHEMA public FROM mscqr_prod_rls; DROP ROLE IF EXISTS mscqr_prod_rls;`);
  }
});
