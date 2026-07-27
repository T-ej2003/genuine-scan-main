const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { resolveManufacturerSessionScope } = require("../dist/services/manufacturerScopeService");

const licensee = (id, orgId, isPrimary = false) => ({
  id,
  name: `Licensee ${id}`,
  prefix: id.toUpperCase(),
  brandName: null,
  orgId,
  isPrimary,
  scopeVersion: "2026-01-02T00:00:00.000Z",
});

const resolve = (result, input = {}) => resolveManufacturerSessionScope(
  { manufacturerId: "manufacturer-1", ...input },
  { $queryRaw: async () => [{ result }] }
);

(async () => {
  const tenantA = licensee("licensee-a", "org-a");
  const tenantB = licensee("licensee-b", "org-b", true);
  const result = await resolve({
    manufacturerId: "manufacturer-1",
    selectedLicensee: tenantB,
    linkedLicensees: [tenantB, tenantA],
  }, {
    legacyLicenseeId: tenantA.id,
    legacyOrgId: tenantA.orgId,
    requestedLicenseeId: tenantB.id,
    requestedOrgId: tenantB.orgId,
    requestedScopeVersion: tenantB.scopeVersion,
  });

  assert.equal(result.selectedLicensee.id, tenantB.id);
  assert.deepEqual(result.linkedLicenseeIds, [tenantB.id, tenantA.id]);
  await assert.rejects(
    resolve({ manufacturerId: "other-actor", selectedLicensee: tenantB, linkedLicensees: [tenantB] }),
    /MANUFACTURER_SCOPE_DENIED/
  );
  await assert.rejects(
    resolve({ manufacturerId: "manufacturer-1", selectedLicensee: tenantA, linkedLicensees: [tenantA] }, {
      legacyLicenseeId: "legacy-only-licensee",
    }),
    /MANUFACTURER_MEMBERSHIP_INCONSISTENT/
  );
  await assert.rejects(
    resolveManufacturerSessionScope(
      { manufacturerId: "manufacturer-1" },
      { $queryRaw: async () => { throw new Error("MANUFACTURER_SCOPE_STALE"); } }
    ),
    /MANUFACTURER_SCOPE_STALE/
  );

  const source = fs.readFileSync(
    path.join(__dirname, "../src/services/manufacturerScopeService.ts"),
    "utf8"
  );
  assert.match(source, /loadAuthenticatedManufacturerScope/);
  assert.doesNotMatch(
    source.slice(source.indexOf("export const resolveManufacturerSessionScope"), source.indexOf("export const upsertManufacturerLicenseeLink")),
    /manufacturerLicenseeLink\.findMany/
  );
  const authService = fs.readFileSync(path.join(__dirname, "../src/services/auth/authService.ts"), "utf8");
  const activeSession = authService.slice(
    authService.indexOf("const loadActiveSessionState"),
    authService.indexOf("type ActiveSessionState")
  );
  assert.match(activeSession, /loadAuthenticatedActor\(db\)/);
  assert.doesNotMatch(activeSession, /db\.user\./);
  console.log("manufacturer session scope boundary tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
