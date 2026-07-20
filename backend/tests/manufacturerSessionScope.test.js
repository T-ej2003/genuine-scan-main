const assert = require("node:assert/strict");

const { resolveManufacturerSessionScope } = require("../dist/services/manufacturerScopeService");

const row = (id, orgId, overrides = {}) => ({
  licenseeId: id,
  isPrimary: false,
  createdAt: new Date("2026-01-01T00:00:00.000Z"),
  updatedAt: new Date("2026-01-02T00:00:00.000Z"),
  licensee: {
    id,
    name: `Licensee ${id}`,
    prefix: id.toUpperCase(),
    brandName: null,
    orgId,
  },
  ...overrides,
});

const resolve = async (rows, input = {}) => {
  let query;
  const result = await resolveManufacturerSessionScope(
    { manufacturerId: "manufacturer-1", ...input },
    {
      manufacturerLicenseeLink: {
        findMany: async (args) => {
          query = args;
          return rows;
        },
      },
    }
  );
  return { result, query };
};

(async () => {
  const tenantA = row("licensee-a", "org-a");
  const tenantB = row("licensee-b", "org-b", { isPrimary: true });
  const { result, query } = await resolve([tenantB, tenantA], {
    legacyLicenseeId: tenantA.licenseeId,
    legacyOrgId: tenantA.licensee.orgId,
    requestedLicenseeId: tenantB.licenseeId,
    requestedOrgId: tenantB.licensee.orgId,
    requestedScopeVersion: tenantB.updatedAt.toISOString(),
  });

  assert.equal(result.selectedLicensee.id, tenantB.licenseeId, "fresh link, not legacy User scope, selects authority");
  assert.equal(result.selectedLicensee.orgId, tenantB.licensee.orgId, "organization is derived from Licensee.orgId");
  assert.deepEqual(result.linkedLicenseeIds, [tenantB.licenseeId, tenantA.licenseeId]);
  assert.equal(query.take, 101, "the bounded read fetches one overflow sentinel");
  assert.deepEqual(query.orderBy, [{ isPrimary: "desc" }, { createdAt: "asc" }, { licenseeId: "asc" }]);
  assert.equal(query.where.manufacturerId, "manufacturer-1");
  assert.equal(query.where.licensee.is.isActive, true);
  assert.equal(query.where.licensee.is.suspendedAt, null);
  assert.equal(query.where.licensee.is.organization.is.isActive, true);
  for (const prohibited of ["supportEmail", "supportPhone", "metadata", "passwordHash", "email", "tokenHash"]) {
    assert.equal(JSON.stringify(query.select).includes(prohibited), false, `${prohibited} must not enter the projection`);
  }

  const ambiguousSelection = await resolve([
    row("licensee-a", "org-a"),
    row("licensee-b", "org-b"),
  ]);
  assert.equal(ambiguousSelection.result.selectedLicensee, null, "multiple links without a primary install no active scope");

  await assert.rejects(
    resolve([tenantA], { requestedLicenseeId: "foreign-licensee" }),
    /MANUFACTURER_SCOPE_DENIED/
  );
  await assert.rejects(
    resolve([tenantA], { requestedLicenseeId: tenantA.licenseeId }),
    /MANUFACTURER_SCOPE_VERSION_REQUIRED/
  );
  await assert.rejects(
    resolve([tenantA], { requestedLicenseeId: tenantA.licenseeId, requestedScopeVersion: "2026-01-01T00:00:00.000Z" }),
    /MANUFACTURER_SCOPE_STALE/
  );
  await assert.rejects(
    resolve([tenantA], { requestedLicenseeId: tenantA.licenseeId, requestedOrgId: "foreign-org" }),
    /MANUFACTURER_SCOPE_DENIED/
  );
  await assert.rejects(
    resolve([tenantA], { legacyLicenseeId: "legacy-only-licensee" }),
    /MANUFACTURER_MEMBERSHIP_INCONSISTENT/
  );
  await assert.rejects(
    resolve([tenantA], { legacyOrgId: "legacy-only-org" }),
    /MANUFACTURER_MEMBERSHIP_INCONSISTENT/
  );
  await assert.rejects(
    resolve([], { legacyLicenseeId: "legacy-only-licensee", legacyOrgId: "legacy-only-org" }),
    /MANUFACTURER_MEMBERSHIP_REQUIRED/
  );
  await assert.rejects(
    resolve([
      row("licensee-a", "org-a", { isPrimary: true }),
      row("licensee-b", "org-b", { isPrimary: true }),
    ]),
    /MANUFACTURER_MEMBERSHIP_AMBIGUOUS/
  );
  await assert.rejects(
    resolve(Array.from({ length: 101 }, (_, index) => row(`licensee-${index}`, `org-${index}`))),
    /MANUFACTURER_MEMBERSHIP_SET_TOO_LARGE/
  );

  console.log("manufacturer session scope boundary tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
