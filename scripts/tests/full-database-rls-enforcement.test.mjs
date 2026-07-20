import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertSafeAdminUrl, FullRlsCertificationSafetyError } from "../rls/certify-full-database.mjs";
import { validateGeneratedPackage } from "../rls/verify-full-rls-package.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(root, "documents/security/rls-program", name), "utf8"));
const packageInputs = () => ({
  manifest: readJson("generated/full-rls-implementation-manifest.json"),
  policies: readJson("generated/policy-inventory-report.json"),
  privileges: readJson("generated/column-privilege-report.json"),
  commandSemantics: readJson("command-semantics.json"),
});
const clone = (value) => structuredClone(value);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("full RLS generator covers all tables with fail-closed dispositions", () => {
  const generated = readJson("generated/full-rls-implementation-manifest.json");
  assert.equal(generated.tables.length, 77);
  assert.equal(generated.tables.filter((table) => table.rls === "ENABLE AND FORCE").length, 75);
  assert.equal(generated.tables.filter((table) => table.rls.startsWith("not-applicable")).length, 2);
  assert.equal(new Set(generated.tables.map((table) => table.table)).size, 77);
  assert.ok(generated.tables.every((table) => table.policyFamily && table.disposition && table.postgresqlCertification === "pending"));
  assert.ok(generated.tables.filter((table) => table.disposition === "fail-closed-no-runtime-grant").length > 0);
});

test("generated direct policies preserve exact actor, assurance, purpose and column semantics", () => {
  const inputs = packageInputs();
  const result = validateGeneratedPackage(inputs);
  assert.equal(result.policies, 39);
  assert.equal(result.directPolicySlices, 34);
  assert.equal(result.columnPrivilegeCells, 78);
  assert.ok(inputs.policies.rows.filter((policy) => !policy.internalHelperOnly && policy.actors.includes("platform-admin")).every((policy) => policy.assurance === "mfa-verified"));
  const platformOrganization = inputs.policies.rows.find((policy) => policy.table === "Organization" && policy.actors.includes("platform-admin"));
  const platformPolicyRule = inputs.policies.rows.find((policy) => policy.table === "PolicyRule" && policy.actors.includes("platform-admin"));
  const internalOrganization = inputs.policies.rows.find((policy) => policy.policyName === "full_rls_internal_manufacturer_org");
  assert.match(platformOrganization.scopePredicate, /scope_licensee\."orgId"="Organization"\."id"/);
  assert.match(platformPolicyRule.scopePredicate, /scope_licensee\."orgId"="PolicyRule"\."orgId"/);
  assert.match(internalOrganization.scopePredicate, /scope_licensee\."orgId"="Organization"\."id"/);
  const auditInserts = inputs.policies.rows.filter((policy) => policy.table === "AuditLog" && policy.command === "INSERT" && !policy.internalHelperOnly);
  assert.ok(auditInserts.every((policy) => policy.scopePredicate.includes('"userId" = app_rls.current_user_id()') || policy.scopePredicate.includes('"userId"=app_rls.current_user_id()')));
  assert.ok(auditInserts.filter((policy) => policy.actors.includes("platform-admin")).every((policy) => policy.scopePredicate.includes('scope_licensee."orgId"="AuditLog"."orgId"')));
});

test("risk analytics User privilege is the exact display and parent-predicate union", () => {
  const { policies, privileges } = packageInputs();
  const userSelect = privileges.rows.find((grant) => grant.table === "User" && grant.command === "SELECT");
  assert.deepEqual(userSelect.columns, ["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "name", "orgId", "role", "status"]);
  assert.deepEqual(userSelect.sourceCommandRuleIds, ["command-user-select-509547f03abe", "command-user-select-97535583a8fe"]);
  for (const prohibited of ["email", "pendingEmail", "passwordHash", "metadata", "failedLoginAttempts", "lockedUntil", "emailVerifiedAt"]) {
    assert(!userSelect.columns.includes(prohibited), `generated grant exposes User.${prohibited}`);
  }
  const riskPolicies = policies.rows.filter((policy) => policy.table === "User" && policy.workflowId === "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics");
  assert.equal(riskPolicies.length, 2);
  assert.ok(riskPolicies.every((policy) => policy.scopePredicate.includes('"id"=app_rls.current_user_id()') && policy.scopePredicate.includes('app_rls.manufacturer_scope_valid("id")')));
  const auditPolicies = policies.rows.filter((policy) => policy.table === "User" && policy.workflowId === "workflow-http-backend-src-controllers-audit-controller-ts-get-logs");
  assert.equal(auditPolicies.length, 2);
  assert.ok(auditPolicies.every((policy) => policy.scopePredicate.includes('"id" = app_rls.current_user_id()')));
});

test("package validation rejects broader actors, weaker assurance and omitted purpose", () => {
  for (const mutate of [
    (candidate) => candidate.policies.rows.find((policy) => !policy.internalHelperOnly).actors.push("platform-admin"),
    (candidate) => { candidate.policies.rows.find((policy) => !policy.internalHelperOnly && policy.assurance === "mfa-verified").assurance = "password-verified"; },
    (candidate) => { candidate.policies.rows.find((policy) => !policy.internalHelperOnly).purpose = []; },
  ]) {
    const candidate = clone(packageInputs());
    mutate(candidate);
    assert.throws(() => validateGeneratedPackage(candidate), /actor|assurance|purpose|platform|incomplete direct slice|source profile/i);
  }
});

test("package validation rejects missing source rules and broadened column grants", () => {
  const noSource = clone(packageInputs());
  noSource.policies.rows.find((policy) => !policy.internalHelperOnly).sourceCommandRuleIds = [];
  assert.throws(() => validateGeneratedPackage(noSource), /source rule/i);

  const broadGrant = clone(packageInputs());
  broadGrant.privileges.rows.find((grant) => grant.table === "User").columns.push("passwordHash");
  broadGrant.privileges.cells += 1;
  assert.throws(() => validateGeneratedPackage(broadGrant), /column (?:grant|privilege)/i);

  const legacyUserScope = clone(packageInputs());
  legacyUserScope.policies.rows.find((policy) => policy.table === "User" && policy.workflowId === "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics").scopePredicate = '("licenseeId" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id())';
  assert.throws(() => validateGeneratedPackage(legacyUserScope), /validated manufacturer (?:links|scope)/i);
});

test("package validation rejects an actor outside the exact certification profile", () => {
  const candidate = clone(packageInputs());
  const policy = candidate.policies.rows.find((entry) => !entry.internalHelperOnly);
  policy.actors = ["worker"];
  assert.throws(() => validateGeneratedPackage(candidate), /compatible direct certification profile|source profile/i);
});

test("generated role lifecycle is clean-room-only and leaves no legacy restoration path", () => {
  const sqlRoot = path.join(root, "scripts/rls/sql/generated");
  const preflight = fs.readFileSync(path.join(sqlRoot, "00-preflight.sql"), "utf8");
  const roles = fs.readFileSync(path.join(sqlRoot, "10-roles.sql"), "utf8");
  const ownership = fs.readFileSync(path.join(sqlRoot, "11-ownership-grants.sql"), "utf8");
  const migration = fs.readFileSync(path.join(sqlRoot, "15-migration-preflight.sql"), "utf8");
  const runtimeGrants = fs.readFileSync(path.join(sqlRoot, "21-runtime-grants.sql"), "utf8");
  const cleanup = fs.readFileSync(path.join(sqlRoot, "90-clean-room-role-cleanup.sql"), "utf8");
  const lifecycle = readJson("generated/role-lifecycle-report.json");
  assert.match(preflight, /pre-existing managed role/);
  assert.match(preflight, /pre-existing application objects/);
  assert.match(preflight, /pre-existing default ACLs/);
  assert.match(preflight, /pre-existing database grants/);
  assert.doesNotMatch(preflight, /CREATE\s+(?:ROLE|SCHEMA|TABLE)/i);
  assert.equal((roles.match(/CREATE ROLE/g) || []).length, 9);
  assert.match(roles, /clean-room preflight refuses a pre-existing managed role/);
  assert.ok(roles.indexOf("clean-room preflight refuses") < roles.indexOf("CREATE ROLE"));
  assert.match(roles, /CREATE SCHEMA mscqr_rls_install/);
  assert.match(migration, /zero-migration clean/);
  assert.doesNotMatch(migration, /SET\s+(?:LOCAL\s+)?ROLE/i);
  assert.match(ownership, /post-migration table inventory/);
  assert.match(ownership, /ALTER TABLE public/);
  assert.match(runtimeGrants, /exact clean-room package marker/);
  assert.match(cleanup, /green database must be dropped before package-role cleanup/);
  assert.match(cleanup, /role cleanup refuses an unmarked or drifted role/);
  assert.match(cleanup, /DROP ROLE %I/);
  for (const name of [
    "00-preflight.sql", "10-roles.sql", "15-migration-preflight.sql", "11-ownership-grants.sql", "20-context-helpers.sql", "21-runtime-grants.sql", "30-policies.sql",
    "40-post-apply-verification.sql", "50-certification-fixtures.sql", "90-clean-room-role-cleanup.sql",
  ]) {
    const phase = fs.readFileSync(path.join(sqlRoot, name), "utf8");
    assert.match(phase, /^\\set ON_ERROR_STOP on\nBEGIN;\n/);
    assert.match(phase, /\nCOMMIT;\n$/);
    assert.equal((phase.match(/^BEGIN;$/gm) || []).length, 1, `${name} must have one phase transaction`);
    assert.equal((phase.match(/^COMMIT;$/gm) || []).length, 1, `${name} must have one phase commit`);
  }
  assert.equal(lifecycle.schemaVersion, 5);
  assert.equal(lifecycle.deploymentModel, "clean-room-blue-green");
  assert.equal(lifecycle.legacyRoleRestoration, false);
  assert.equal(lifecycle.legacyAclRestoration, false);
  assert.equal(lifecycle.legacyDefaultAclRestoration, false);
  assert.equal(lifecycle.legacyOwnershipRestoration, false);
  assert.equal(lifecycle.dropOwnedAllowed, false);
  assert.doesNotMatch(`${preflight}\n${roles}\n${ownership}\n${runtimeGrants}\n${cleanup}`, /DROP OWNED|existed_before|schema_privileges_before|default_privileges_before/i);
});

test("generated package assigns every artifact to one exact executor phase", () => {
  const sqlRoot = path.join(root, "scripts/rls/sql/generated");
  const report = readJson("generated/package-execution-report.json");
  const checksums = readJson("generated/checksums.json").files;
  const expectedPhases = ["admin-bootstrap", "migration", "admin-ownership", "runtime-policy", "verification", "clean-room-destroy"];
  assert.equal(report.schemaVersion, 2);
  assert.equal(report.deploymentModel, "clean-room-blue-green");
  assert.equal(report.blueDatabaseMutationAllowed, false);
  assert.deepEqual(report.phases.map(({ id, order }) => ({ id, order })), expectedPhases.map((id, index) => ({ id, order: index + 1 })));

  const phaseById = new Map(report.phases.map((phase) => [phase.id, phase]));
  const adminRole = {
    certification: "certification-administrator",
    development: "mscqr_dev_admin",
    staging: "mscqr_staging_admin",
    production: "unresolved-production-administrator",
  }[report.targetEnvironment];
  const manifest = readJson("generated/full-rls-implementation-manifest.json");
  const migrationRole = manifest.roles.migration;
  assert.ok(adminRole && migrationRole, `unsupported package environment ${report.targetEnvironment}`);
  for (const id of ["admin-bootstrap", "admin-ownership", "runtime-policy", "verification", "clean-room-destroy"]) assert.equal(phaseById.get(id).executorRole, adminRole);
  assert.equal(phaseById.get("admin-bootstrap").executorClass, phaseById.get("runtime-policy").executorClass);
  assert.equal(phaseById.get("admin-bootstrap").executorClass, phaseById.get("admin-ownership").executorClass);
  assert.notEqual(phaseById.get("migration").executorClass, phaseById.get("admin-bootstrap").executorClass);
  assert.equal(phaseById.get("migration").executorRole, migrationRole);
  assert.deepEqual(report.phases.map((phase) => phase.mutating), [true, true, true, true, false, true]);
  assert.ok(report.phases.every((phase) => phase.executorClass && Array.isArray(phase.requiredCapabilities) && phase.requiredCapabilities.length > 0));
  assert.match(phaseById.get("clean-room-destroy").failureDisposition, /role-cleanup/);
  assert.ok(phaseById.get("clean-room-destroy").externalPrerequisites.includes("green-database-dropped-from-maintenance-database"));

  const phaseFiles = report.phases.flatMap((phase) => {
    assert.equal(phase.entrypoint, phase.files[0], `${phase.id} must name one executable entrypoint before its checksum-only dependencies`);
    const entrypoint = fs.readFileSync(path.join(sqlRoot, phase.entrypoint), "utf8");
    const entrypointLines = entrypoint.split(/\r?\n/);
    for (const dependency of phase.files.slice(1)) assert.equal(entrypointLines.filter((line) => line === `\\ir ${dependency}`).length, 1, `${phase.id} entrypoint must include ${dependency} once`);
    assert.deepEqual(Object.keys(phase.fileChecksums).sort(), [...phase.files].sort(), `${phase.id} checksum coverage drifted`);
    for (const name of phase.files) {
      const contents = fs.readFileSync(path.join(sqlRoot, name));
      assert.equal(phase.fileChecksums[name], sha256(contents), `${phase.id}/${name} phase checksum drifted`);
      assert.equal(checksums[name], phase.fileChecksums[name], `${phase.id}/${name} global checksum drifted`);
    }
    return phase.files;
  });
  const allSql = fs.readdirSync(sqlRoot).filter((name) => name.endsWith(".sql")).sort();
  const classified = [...phaseFiles, ...report.certificationOnlyFiles].sort();
  assert.equal(new Set(classified).size, classified.length, "a generated SQL file is assigned more than once");
  assert.deepEqual(classified, allSql, "every generated SQL file must have one executor or be certification-only");
  assert.equal(checksums["package-execution-report.json"], sha256(fs.readFileSync(path.join(root, "documents/security/rls-program/generated/package-execution-report.json"))));

  const migrationRoot = path.join(root, "backend/prisma/migrations");
  const migrationEntries = fs.readdirSync(migrationRoot)
    .filter((directory) => fs.existsSync(path.join(migrationRoot, directory, "migration.sql")))
    .sort()
    .map((name) => ({ name, sha256: sha256(fs.readFileSync(path.join(migrationRoot, name, "migration.sql"))) }));
  assert.deepEqual(report.prismaMigrations, migrationEntries);

  const migrationSql = [...phaseById.get("migration").files.map((name) => fs.readFileSync(path.join(sqlRoot, name), "utf8")), ...migrationEntries.map(({ name }) => fs.readFileSync(path.join(migrationRoot, name, "migration.sql"), "utf8"))].join("\n");
  for (const forbidden of [
    /\b(?:CREATE|ALTER|DROP)\s+ROLE\b/i,
    /\bGRANT\s+(?![^;]*\bON\b)[^;]+\bTO\b/i,
    /\bSET\s+(?:LOCAL\s+)?ROLE\b/i,
    /\bALTER\s+(?:TABLE|SCHEMA|SEQUENCE|FUNCTION|PROCEDURE|TYPE|VIEW|MATERIALIZED\s+VIEW)\b[^;]*\bOWNER\s+TO\b/is,
    /\b(?:REASSIGN|DROP)\s+OWNED\b/i,
    /\b(?:CREATE|ALTER|DROP)\s+POLICY\b/i,
    /\bALTER\s+TABLE\b[^;]*\b(?:ENABLE|DISABLE|FORCE|NO\s+FORCE)\s+ROW\s+LEVEL\s+SECURITY\b/is,
  ]) assert.doesNotMatch(migrationSql, forbidden, `migration package contains administrative SQL: ${forbidden}`);

  const dockerfile = fs.readFileSync(path.join(root, "backend/Dockerfile"), "utf8");
  assert.doesNotMatch(dockerfile, /scripts\/rls\/sql\/generated|documents\/security\/rls-program\/generated/,
    "the blue application image must not contain the green administrative package");
});

test("reduced surface has no prematurely enabled protected workflow", () => {
  const allowlist = readJson("essential-workflow-allowlist.json");
  const shutdown = readJson("unsupported-workflow-shutdown.json");
  assert.equal(allowlist.launchBlocked, true);
  assert.equal(allowlist.certification.enabledWorkflowCount, 0);
  assert.deepEqual(allowlist.protectedRouteGate.enabledRoutes, []);
  assert.deepEqual(shutdown.enabledProtectedRoutes, []);
  assert.equal(shutdown.overrides.production, "startup failure");
});

test("disposable certification URL guard rejects remote and production targets", () => {
  assert.throws(() => assertSafeAdminUrl("postgresql://user@example.com/mscqr_full_rls_test"), FullRlsCertificationSafetyError);
  assert.throws(() => assertSafeAdminUrl("postgresql://user@127.0.0.1/production"), FullRlsCertificationSafetyError);
  assert.throws(() => assertSafeAdminUrl("postgresql://user@127.0.0.1/postgres"), FullRlsCertificationSafetyError);
  assert.doesNotThrow(() => assertSafeAdminUrl("postgresql://mscqr_rls_cert_admin@127.0.0.1:55434/mscqr_full_rls_admin"));
});
