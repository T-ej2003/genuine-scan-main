const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

process.env.NODE_ENV = "test";

const backendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(backendRoot, "..");
const schemaPath = path.join(backendRoot, "prisma/schema.prisma");
const candidateSqlPath = path.join(
  repoRoot,
  "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql"
);
const contextPath = path.join(backendRoot, "src/lib/stagingRlsBatchReadContext.ts");
const routeTestPaths = [
  "rlsBatchesReadRuntimeP2.test.js",
  "rlsBatchAllocationMapRuntimeP2.test.js",
  "rlsManufacturerPrintersReadRuntimeP2.test.js",
].map((fileName) => path.join(backendRoot, "tests", fileName));

const extractEnumValues = (schema) => {
  const match = schema.match(/enum\s+UserRole\s*\{([\s\S]*?)\n\}/);
  assert(match, "UserRole must remain the authoritative Prisma enum");
  return new Set(
    [...match[1].matchAll(/^\s*([A-Z][A-Z0-9_]*)\s*(?:\/\/.*)?$/gm)].map((entry) => entry[1])
  );
};

const extractUserRoleReferences = (source) =>
  new Set([...source.matchAll(/\bUserRole\.([A-Z][A-Z0-9_]*)\b/g)].map((entry) => entry[1]));

const extractRawRoleProperties = (source) =>
  new Set([...source.matchAll(/\brole\s*:\s*["']([A-Za-z_]+)["']/g)].map((entry) => entry[1].toUpperCase()));

const extractCandidateSqlRoleLiterals = (source) => {
  const roles = new Set();
  for (const clause of source.matchAll(/current_role\(\)\s*(?:=\s*'[^']+'|IN\s*\([^)]*\))/g)) {
    for (const literal of clause[0].matchAll(/'([a-z_]+)'/g)) roles.add(literal[1].toUpperCase());
  }
  return roles;
};

const extractDeclaredRoleList = (source, name) => {
  const match = source.match(new RegExp(`export const ${name} = \\[([\\s\\S]*?)\\] as const;`));
  assert(match, `${name} must be an explicit reviewed role list`);
  return extractUserRoleReferences(match[1]);
};

const schemaRoles = extractEnumValues(fs.readFileSync(schemaPath, "utf8"));
const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
const contextSource = fs.readFileSync(contextPath, "utf8");
const routeTestSources = routeTestPaths.map((filePath) => fs.readFileSync(filePath, "utf8"));

const activeRoles = new Set([
  "SUPER_ADMIN",
  "PLATFORM_SUPER_ADMIN",
  "LICENSEE_ADMIN",
  "MANUFACTURER",
]);
const dormantRoles = new Set(["ORG_ADMIN", "MANUFACTURER_ADMIN", "MANUFACTURER_USER"]);
const classifiedRoles = new Set([...activeRoles, ...dormantRoles]);

assert.deepEqual(
  [...schemaRoles].sort(),
  [...classifiedRoles].sort(),
  "every authoritative UserRole must be explicitly classified active or dormant for phase-one RLS"
);

const contextActiveRoles = extractDeclaredRoleList(contextSource, "PHASE_ONE_RLS_ACTIVE_ROLES");
const contextDormantRoles = extractDeclaredRoleList(contextSource, "PHASE_ONE_RLS_DORMANT_ROLES");
assert.deepEqual([...contextActiveRoles].sort(), [...activeRoles].sort(), "RLS context active roles drifted from the reviewed matrix");
assert.deepEqual([...contextDormantRoles].sort(), [...dormantRoles].sort(), "RLS context dormant roles drifted from the reviewed matrix");

const extractedSources = [
  { label: "candidate SQL", roles: extractCandidateSqlRoleLiterals(candidateSql) },
  { label: "RLS context construction", roles: new Set([...extractUserRoleReferences(contextSource), ...extractRawRoleProperties(contextSource)]) },
  ...routeTestSources.map((source, index) => ({
    label: path.basename(routeTestPaths[index]),
    roles: new Set([...extractUserRoleReferences(source), ...extractRawRoleProperties(source)]),
  })),
];

for (const { label, roles } of extractedSources) {
  for (const role of roles) {
    assert(schemaRoles.has(role), `${label} contains unknown app-role literal ${role}`);
    assert(classifiedRoles.has(role), `${label} contains unclassified app-role literal ${role}`);
  }
}

for (const role of dormantRoles) {
  assert.equal(
    extractCandidateSqlRoleLiterals(candidateSql).has(role),
    false,
    `dormant ${role} must not appear in a phase-one candidate policy`
  );
  assert.equal(contextActiveRoles.has(role), false, `dormant ${role} must not enter a phase-one RLS context`);
}

const { UserRole } = require("@prisma/client");
const { buildStagingRlsBatchReadContext } = require("../dist/lib/stagingRlsBatchReadContext");
for (const roleName of dormantRoles) {
  assert.throws(
    () =>
      buildStagingRlsBatchReadContext({
        userId: "phase-one-dormant-role",
        email: "phase-one-dormant-role@mscqr.test",
        role: UserRole[roleName],
        licenseeId: "phase-one-licensee",
        orgId: "phase-one-org",
        sessionStage: "ACTIVE",
        authAssurance: "ADMIN_MFA",
      }),
    /phase-one access is not enabled/,
    `dormant ${roleName} must fail closed before a RLS transaction starts`
  );
}

assert.throws(
  () =>
    buildStagingRlsBatchReadContext({
      userId: "phase-one-unknown-role",
      email: "phase-one-unknown-role@mscqr.test",
      role: "UNREVIEWED_ROLE",
      licenseeId: "phase-one-licensee",
      orgId: "phase-one-org",
      sessionStage: "ACTIVE",
      authAssurance: "ADMIN_MFA",
    }),
  /phase-one access is not enabled/,
  "an unknown app-role string must fail closed before a RLS transaction starts"
);

console.log("Phase-one RLS active/dormant role matrix tests passed");
