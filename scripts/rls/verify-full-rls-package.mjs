import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TABLE_INVENTORY_BASELINE } from "./lib/table-inventory-baseline.mjs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { calculateCleanRoomSourceContract } from "./lib/clean-room-source-contract.mjs";
import { buildRegisteredCallPathEvidence } from "./lib/application-path-certifications.mjs";
import { EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT, EXPECTED_WORKFLOW_COUNT } from "./lib/workflow-inventory-baseline.mjs";
import { NAMED_SQL_FUNCTION_CONTRACTS } from "./lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const generatedRoot = path.join(root, "documents/security/rls-program/generated");
const sqlRoot = path.join(root, "scripts/rls/sql/generated");
const programmeRoot = path.join(root, "documents/security/rls-program");
const readGenerated = (name) => fs.readFileSync(name.endsWith(".sql") ? path.join(sqlRoot, name) : path.join(generatedRoot, name));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(programmeRoot, name), "utf8"));
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sorted = (values) => [...new Set(values)].sort();
const equal = (left, right) => JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
const ensure = (condition, message) => { if (!condition) throw new Error(message); };

export const validateGeneratedPackage = ({ manifest, policies, privileges, commandSemantics }) => {
  const rules = new Map(commandSemantics.rules.map((rule) => [rule.id, rule]));
  for (const contract of NAMED_SQL_FUNCTION_CONTRACTS) {
    for (const [table, command] of contract.tableCommands || []) {
      const id = `contract:${contract.id}:${table}:${command}`;
      rules.set(id, { id, table, command, contractId: contract.id });
    }
  }
  const profiles = commandSemantics.sqlCertificationProfiles || [];
  const directProfiles = profiles.filter((profile) => profile.status === "direct-policy-candidate");
  const namedProfiles = profiles.filter((profile) => profile.status === "named-function-candidate");
  const blockedProfiles = profiles.filter((profile) => profile.status === "direct-policy-blocked");
  const profileBySlice = new Map();

  for (const profile of directProfiles) {
    ensure(profile.workflowId && profile.route && profile.actorClass, `${profile.id} lacks workflow, route or actor`);
    ensure(profile.minimumAssurance && profile.purposeCodes?.length && profile.scopeType, `${profile.id} lacks assurance, purpose or scope`);
    for (const ruleId of profile.commandRuleIds || []) {
      const rule = rules.get(ruleId);
      ensure(rule, `${profile.id} references unknown command rule ${ruleId}`);
      ensure(rule.supportingWorkflowIds?.includes(profile.workflowId), `${profile.id}/${ruleId} workflow mismatch`);
      ensure(rule.actorClasses?.includes(profile.actorClass), `${profile.id}/${ruleId} actor is broader than its source rule`);
      const required = rule.minimumAssuranceByActorClass?.[profile.actorClass] || rule.minimumAssurance;
      ensure(required === profile.minimumAssurance, `${profile.id}/${ruleId} weakens actor-specific assurance`);
      ensure(rule.status === "architecture-resolved" && !rule.requiresNamedFunction, `${profile.id}/${ruleId} is not directly implementable`);
      profileBySlice.set(`${profile.workflowId}|${profile.actorClass}|${ruleId}`, profile);
    }
  }
  for (const profile of namedProfiles) {
    ensure(profile.workflowId && profile.route && profile.routes?.length && profile.actorClass, `${profile.id} lacks workflow, routes or actor`);
    const functionSignatures = profile.functionSignatures || [profile.functionSignature];
    ensure(functionSignatures.length > 0 && functionSignatures.every((signature) => signature?.startsWith("app_rls.")) && profile.minimumAssurance && profile.purposeCodes?.length && profile.scopeType, `${profile.id} lacks an exact named-function boundary`);
    for (const ruleId of profile.commandRuleIds || []) {
      const rule = rules.get(ruleId);
      ensure(rule, `${profile.id} references unknown command rule ${ruleId}`);
      ensure(rule.supportingWorkflowIds?.includes(profile.workflowId), `${profile.id}/${ruleId} workflow mismatch`);
      ensure(rule.actorClasses?.includes(profile.actorClass), `${profile.id}/${ruleId} actor is broader than its source rule`);
      const required = rule.minimumAssuranceByActorClass?.[profile.actorClass] || rule.minimumAssurance;
      ensure(required === profile.minimumAssurance, `${profile.id}/${ruleId} weakens actor-specific assurance`);
      ensure(rule.status === "architecture-resolved" && rule.requiresNamedFunction, `${profile.id}/${ruleId} is not a named-function rule`);
      if (rule.namedFunctionSignatures) ensure(
        JSON.stringify([...functionSignatures].sort()) === JSON.stringify([...rule.namedFunctionSignatures].sort()),
        `${profile.id}/${ruleId} named-function set drifted`
      );
    }
  }
  const dashboardProfiles = namedProfiles.filter((profile) => profile.id.startsWith("sql-profile-dashboard-snapshot-"));
  ensure(dashboardProfiles.length === 6, "Dashboard snapshot named-function profiles are incomplete");
  ensure(equal(dashboardProfiles.map((profile) => profile.actorClass), ["licensee-admin", "manufacturer", "platform-admin"]), "Dashboard snapshot actor profiles drifted");
  ensure(dashboardProfiles.every((profile) => equal(profile.routes, ["GET /api/dashboard/stats", "GET /api/events/dashboard"]) && equal(profile.purposeCodes, ["dashboard-snapshot-read"])), "Dashboard snapshot route or purpose profiles drifted");
  ensure(blockedProfiles.some((profile) => profile.status === "direct-policy-blocked" && profile.blockers?.length), "Blocked direct-policy contracts were lost");
  ensure(manifest.deploymentModel === "clean-room-blue-green", "Generated package is not clean-room blue/green");
  ensure(manifest.counts.tables === TABLE_INVENTORY_BASELINE.tables && manifest.counts.forceRlsTargets === TABLE_INVENTORY_BASELINE.forceRlsTargets && manifest.counts.migrationOnly === TABLE_INVENTORY_BASELINE.migrationOnly, "Generated full-RLS table counts drifted");
  ensure(manifest.counts.directPolicySlices === directProfiles.reduce((count, profile) => count + profile.commandRuleIds.length, 0), "Direct policy slice count drifted");
  ensure(manifest.counts.generatedPolicies === policies.rows.length && policies.count === policies.rows.length, "Generated policy count drifted");
  ensure(manifest.counts.columnPrivilegeCells === privileges.cells, "Generated column privilege count drifted");
  ensure(new Set(manifest.tables.map((table) => table.table)).size === TABLE_INVENTORY_BASELINE.tables, "Generated table dispositions are not unique");
  ensure(manifest.tables.filter((table) => table.rls === "ENABLE AND FORCE").length === TABLE_INVENTORY_BASELINE.forceRlsTargets, "Every intended table must be FORCE RLS");
  ensure(manifest.tables.every((table) => table.policyFamily && table.disposition && Array.isArray(table.policySlices) && Array.isArray(table.columnGrants)), "A table lacks an exact policy disposition");

  const policyNames = new Set();
  const directPolicies = [];
  for (const policy of policies.rows) {
    ensure(policy.policyName && !policyNames.has(policy.policyName), `Duplicate or blank policy name ${policy.policyName || "<blank>"}`);
    policyNames.add(policy.policyName);
    ensure(policy.sourceCommandRuleIds?.length && policy.sourceCommandRuleIds.every((id) => rules.has(id)), `${policy.policyName} lacks valid source rules`);
    ensure(policy.command && policy.table && policy.scopePredicate, `${policy.policyName} lacks command, table or predicate`);
    ensure(policy.certificationStatus === "pending", `${policy.policyName} falsely claims certification`);
    if (policy.internalHelperOnly) {
      ensure(policy.columns?.length === 0 && policy.assurance === "source-rule-specific", `${policy.policyName} exposes or flattens helper authority`);
      continue;
    }
    directPolicies.push(policy);
    ensure(policy.workflowId && policy.route && policy.actors?.length === 1 && policy.purpose?.length && policy.columns?.length, `${policy.policyName} has an incomplete direct slice`);
    ensure(policy.sourceCommandRuleIds.length === 1, `${policy.policyName} merged incompatible command rules`);
    const ruleId = policy.sourceCommandRuleIds[0];
    const rule = rules.get(ruleId);
    const profile = profileBySlice.get(`${policy.workflowId}|${policy.actors[0]}|${ruleId}`);
    ensure(profile, `${policy.policyName} has no compatible direct certification profile`);
    ensure(policy.route === profile.route && policy.assurance === profile.minimumAssurance && equal(policy.purpose, profile.purposeCodes), `${policy.policyName} drifted from its source profile`);
    ensure(policy.command === rule.command && policy.table === manifest.tables.find((entry) => entry.tableId === rule.tableId)?.table, `${policy.policyName} table or command drifted`);
    ensure(equal(policy.columns, rule.allowedColumns || []), `${policy.policyName} columns drifted from its source rule`);
  }

  const riskProfiles = namedProfiles.filter((profile) => profile.workflowId === "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics");
  ensure(riskProfiles.length === 2 && equal(riskProfiles.map((profile) => profile.actorClass), ["licensee-admin", "platform-admin"]) &&
    riskProfiles.every((profile) =>
      profile.functionSignature === "app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone)" &&
      equal(profile.purposeCodes, ["tenant-risk-analytics"])
    ) &&
    riskProfiles.find((profile) => profile.actorClass === "platform-admin")?.minimumAssurance === "mfa-verified",
  "Risk analytics named-function boundary is incomplete or weakens platform assurance");
  const riskUserPolicy = policies.rows.find((policy) => policy.table === "User" && policy.policyName === "full_rls_internal_owner_user_select");
  ensure(riskUserPolicy?.scopePredicate.includes('"id"=app_rls.current_user_id()') &&
    riskUserPolicy.scopePredicate.includes("app_rls.current_purpose()='tenant-risk-analytics'") &&
    riskUserPolicy.scopePredicate.includes("\"role\" IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')"),
  "Risk analytics owner policy lost actor hydration or bounded manufacturer projection");
  const auditUserPolicies = directPolicies.filter((policy) => policy.table === "User" && policy.workflowId === "workflow-http-backend-src-controllers-audit-controller-ts-get-logs");
  ensure(auditUserPolicies.length === 2 && auditUserPolicies.every((policy) => policy.scopePredicate.includes('"id" = app_rls.current_user_id()')), "Audit User policies lost actor-self scope");

  const expectedGrants = new Map();
  for (const policy of directPolicies) {
    if (["QRCode", "QRRange"].includes(policy.table)) continue;
    const key = `${policy.table}|${policy.command}`;
    const entry = expectedGrants.get(key) || { columns: [], sourceCommandRuleIds: [] };
    entry.columns.push(...policy.columns);
    entry.sourceCommandRuleIds.push(...policy.sourceCommandRuleIds);
    expectedGrants.set(key, entry);
  }
  ensure(privileges.rows.every(({ table }) => !["QRCode", "QRRange"].includes(table)), "Authenticated application retains direct QR table privileges");
  ensure(privileges.rows.length === expectedGrants.size, "Column grant rows do not match compatible semantic slices");
  for (const grant of privileges.rows) {
    const expected = expectedGrants.get(`${grant.table}|${grant.command}`);
    ensure(expected && equal(grant.columns, expected.columns), `${grant.table} ${grant.command} column grant exceeds reviewed union`);
    ensure(equal(grant.sourceCommandRuleIds, expected.sourceCommandRuleIds), `${grant.table} ${grant.command} source rule IDs drifted`);
  }
  ensure(privileges.cells === privileges.rows.reduce((count, row) => count + row.columns.length, 0), "Column privilege cell total drifted");
  return { tables: TABLE_INVENTORY_BASELINE.tables, forceRlsTargets: TABLE_INVENTORY_BASELINE.forceRlsTargets, policies: policies.rows.length, directPolicySlices: directPolicies.length, columnPrivilegeCells: privileges.cells };
};

export const verifyFullRlsPackage = () => {
  const checksums = JSON.parse(readGenerated("checksums.json"));
  const source = calculateCleanRoomSourceContract(root);
  ensure(checksums.schemaVersion === 3 && checksums.deploymentModel === "clean-room-blue-green", "Checksum manifest is not clean-room bound");
  ensure(checksums.sourceContractSha256 === source.sourceContractSha256, "Generated package is stale relative to its authoritative source contract");
  ensure(JSON.stringify(checksums.sourceContractInputs) === JSON.stringify(source.inputs), "Generated source-input inventory drifted");
  for (const [name, expected] of Object.entries(checksums.files)) ensure(digest(readGenerated(name)) === expected, `Generated checksum mismatch for ${name}`);

  const manifest = JSON.parse(readGenerated("full-rls-implementation-manifest.json"));
  const policies = JSON.parse(readGenerated("policy-inventory-report.json"));
  const privileges = JSON.parse(readGenerated("column-privilege-report.json"));
  const roleLifecycle = JSON.parse(readGenerated("role-lifecycle-report.json"));
  const execution = JSON.parse(readGenerated("package-execution-report.json"));
  const workflowCallPaths = JSON.parse(readGenerated("workflow-call-path-evidence.json"));
  const expectedWorkflowCallPaths = buildRegisteredCallPathEvidence({
    workflowsManifest: readJson("workflows.json"),
    partition: readJson("workflow-three-session-partition.json"),
    repoRoot: root,
  });
  ensure(JSON.stringify(workflowCallPaths) === JSON.stringify(expectedWorkflowCallPaths), "Generated workflow call-path evidence is stale or manually edited");
  ensure(workflowCallPaths.workflowCount === EXPECTED_WORKFLOW_COUNT && workflowCallPaths.workflows.length === EXPECTED_WORKFLOW_COUNT, "Workflow call-path evidence is not exhaustive");
  const summary = validateGeneratedPackage({ manifest, policies, privileges, commandSemantics: readJson("command-semantics.json") });
  ensure(manifest.counts.registeredWorkflowCallPaths === EXPECTED_WORKFLOW_COUNT && manifest.counts.applicationPathCertifiedWorkflows === workflowCallPaths.summary.applicationPathCertified, "Implementation manifest workflow evidence counts drifted");

  const sqlNames = fs.readdirSync(sqlRoot).filter((name) => name.endsWith(".sql")).sort();
  ensure(equal(sqlNames, Object.keys(checksums.files).filter((name) => name.endsWith(".sql"))), "Global checksums do not cover every SQL artifact exactly once");
  ensure(execution.schemaVersion === 2 && execution.deploymentModel === "clean-room-blue-green" && execution.sourceContractSha256 === manifest.sourceContractSha256, "Execution report is not source-contract bound");
  ensure(!execution.blueDatabaseMutationAllowed && /separate encrypted RDS/i.test(execution.greenInfrastructureBoundary), "Execution report does not isolate green from blue");
  const phaseIds = ["admin-bootstrap", "migration", "admin-ownership", "runtime-policy", "verification", "clean-room-destroy"];
  ensure(JSON.stringify(execution.phases.map(({ id, order }) => ({ id, order }))) === JSON.stringify(phaseIds.map((id, index) => ({ id, order: index + 1 }))), "Clean-room phase order drifted");
  const phaseById = new Map(execution.phases.map((phase) => [phase.id, phase]));
  ensure(phaseById.get("migration")?.executorRole === manifest.roles.migration && phaseById.get("migration")?.executorClass === "restricted-migration", "Migration phase lost its exact restricted identity");
  ensure(!phaseById.get("verification")?.mutating, "Verification phase must be read-only");
  ensure(phaseById.get("clean-room-destroy")?.externalPrerequisites?.includes("green-database-dropped-from-maintenance-database"), "Cleanup can run before green database destruction");
  const classified = [...execution.phases.flatMap((phase) => phase.files), ...(execution.certificationOnlyFiles || [])];
  ensure(new Set(classified).size === classified.length && equal(classified, sqlNames), "Every SQL artifact must have exactly one executor classification");
  for (const phase of execution.phases) {
    ensure(phase.entrypoint === phase.files[0] && phase.requiredCapabilities?.length && phase.failureDisposition, `${phase.id} lacks an executable authority/failure contract`);
    ensure(equal(Object.keys(phase.fileChecksums), phase.files), `${phase.id} file checksum coverage drifted`);
    for (const name of phase.files) ensure(phase.fileChecksums[name] === checksums.files[name], `${phase.id}/${name} checksum drifted`);
    const entrypointLines = readGenerated(phase.entrypoint).toString().split(/\r?\n/);
    for (const dependency of phase.files.slice(1)) ensure(entrypointLines.filter((line) => line === `\\ir ${dependency}`).length === 1, `${phase.id} must include ${dependency} exactly once`);
  }

  for (const name of ["00-preflight.sql", "10-roles.sql", "15-migration-preflight.sql", "11-ownership-grants.sql", "20-context-helpers.sql", "21-runtime-grants.sql", "30-policies.sql", "40-post-apply-verification.sql", "50-certification-fixtures.sql", "90-clean-room-role-cleanup.sql"]) {
    const sql = readGenerated(name).toString();
    ensure(sql.startsWith("\\set ON_ERROR_STOP on\nBEGIN;\n") && sql.trimEnd().endsWith("COMMIT;"), `${name} is not phase-transaction atomic`);
    ensure((sql.match(/^BEGIN;$/gm) || []).length === 1 && (sql.match(/^COMMIT;$/gm) || []).length === 1, `${name} has ambiguous transaction boundaries`);
  }
  const allSql = sqlNames.map((name) => readGenerated(name).toString()).join("\n");
  for (const forbidden of [/USING\s*\(\s*TRUE\s*\)/i, /WITH\s+CHECK\s*\(\s*TRUE\s*\)/i, /GRANT\s+(?:SELECT|INSERT|UPDATE)\s+ON\s+(?:TABLE\s+)?public\./i, /DROP\s+OWNED\s+BY/i, /\sBYPASSRLS\b/i]) ensure(!forbidden.test(allSql), `Unsafe generated SQL pattern: ${forbidden}`);
  for (const legacy of ["mscqr_rls_apply_state", "existed_before", "schema_privileges_before", "default_privileges_before", "99-post-rollback-verification.sql", "90-rollback.sql"]) ensure(!allSql.includes(legacy) && !sqlNames.includes(legacy), `Legacy in-place restoration residue remains: ${legacy}`);

  const preflight = readGenerated("00-preflight.sql").toString();
  for (const proof of [/green database name matching/i, /pre-existing managed role/i, /pre-existing application objects/i, /pre-existing policies/i, /pre-existing default ACLs/i, /pre-existing database grants/i, /non-baseline public schema grants/i, /another green database session/i]) ensure(proof.test(preflight), `Clean-room preflight proof missing: ${proof}`);
  ensure(!/CREATE\s+(?:ROLE|SCHEMA|TABLE)/i.test(preflight), "Read-only preflight mutates cluster or database state");
  const rolesSql = readGenerated("10-roles.sql").toString();
  ensure((rolesSql.match(/CREATE ROLE/g) || []).length === 9 && !/CREATE ROLE[^;]*IF NOT EXISTS/i.test(rolesSql), "Managed roles are not created unconditionally and exactly once");
  ensure((rolesSql.match(/COMMENT ON ROLE/g) || []).length === 9 && rolesSql.includes(manifest.roleMarker), "Managed roles lack exact package markers");
  ensure(/REVOKE CONNECT,TEMPORARY ON DATABASE/.test(rolesSql) && /migration/.test(rolesSql) && /ALTER DEFAULT PRIVILEGES/.test(rolesSql), "Role phase lacks database or pre-migration default hardening");
  const migrationSql = readGenerated("15-migration-preflight.sql").toString();
  ensure(/zero-migration clean/.test(migrationSql) && /_prisma_migrations/.test(migrationSql) && !/SET\s+(?:LOCAL\s+)?ROLE/i.test(migrationSql), "Migration boundary is not zero-based and owner-free");
  const ownershipSql = readGenerated("11-ownership-grants.sql").toString();
  ensure(/post-migration table inventory/.test(ownershipSql) && /post-migration enum inventory/.test(ownershipSql) && /ALTER TABLE public/.test(ownershipSql) && /ALTER TYPE public/.test(ownershipSql), "Ownership phase lacks exact migration inventory or transfer");
  ensure(!/schema_privilege|object_privilege|restor/i.test(ownershipSql), "Ownership phase still contains legacy restoration machinery");
  const cleanup = readGenerated("90-clean-room-role-cleanup.sql").toString();
  ensure(/green database must be dropped before package-role cleanup/.test(cleanup) && /role cleanup refuses an unmarked or drifted role/.test(cleanup) && /DROP ROLE/.test(cleanup), "Clean-room role cleanup is not database-absence and marker bound");
  ensure(!/DROP DATABASE/i.test(cleanup), "Role cleanup attempts to drop its own or an unbound database");
  const verification = readGenerated("40-post-apply-verification.sql").toString();
  ensure(!/^\s*(?:CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE)\b/im.test(verification), "Verification SQL is not read-only");
  ensure((readGenerated("30-policies.sql").toString().match(/FORCE ROW LEVEL SECURITY/g) || []).length === TABLE_INVENTORY_BASELINE.forceRlsTargets, `Generated SQL does not FORCE exactly ${TABLE_INVENTORY_BASELINE.forceRlsTargets} tables`);
  ensure((readGenerated("30-policies.sql").toString().match(/CREATE POLICY/g) || []).length === policies.rows.length, "Generated SQL policy count differs from inventory");
  const runtimeGrantSql = readGenerated("21-runtime-grants.sql").toString();
  const exactTableGrantCount = (runtimeGrantSql.match(/GRANT\s+(?:SELECT|INSERT|UPDATE)\s*\(/g) || []).length
    + (runtimeGrantSql.match(/GRANT\s+DELETE\s+ON\s+TABLE\s+public\./g) || []).length;
  ensure(exactTableGrantCount === privileges.rows.length + (privileges.functionOwnerRows || []).length, "Generated SQL exact table grants differ from inventory");

  ensure(roleLifecycle.schemaVersion === 5 && roleLifecycle.deploymentModel === "clean-room-blue-green", "Role lifecycle report is not clean-room blue/green");
  ensure(roleLifecycle.preflight?.mutationAllowed === false && roleLifecycle.legacyRoleRestoration === false && roleLifecycle.legacyAclRestoration === false && roleLifecycle.legacyDefaultAclRestoration === false && roleLifecycle.legacyOwnershipRestoration === false, "Role lifecycle report retains historical restoration");
  const contracts = JSON.parse(readGenerated("contract-only-implementation-inventory.json"));
  const grouped = Object.values(contracts.groups || {}).flat();
  ensure(contracts.workflowCount === EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT && grouped.length === EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT && new Set(grouped.map((entry) => entry.workflowId)).size === EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT, "Contract-only workflow inventory lost or duplicated workflows");
  return { valid: true, ...summary, deploymentModel: "clean-room-blue-green", registeredWorkflowCallPaths: EXPECTED_WORKFLOW_COUNT, applicationPathCertifiedWorkflows: workflowCallPaths.summary.applicationPathCertified, contractOnlyWorkflows: EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT, executionPhases: execution.phases.length, checksums: Object.keys(checksums.files).length };
};

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) console.log(JSON.stringify(verifyFullRlsPackage()));
