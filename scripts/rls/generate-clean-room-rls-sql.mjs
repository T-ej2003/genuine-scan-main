import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT } from "./lib/workflow-inventory-baseline.mjs";
import { calculateCleanRoomSourceContract } from "./lib/clean-room-source-contract.mjs";
import {
  BATCH_OPERATIONAL_READ_WORKFLOW_IDS,
  buildRegisteredCallPathEvidence,
} from "./lib/application-path-certifications.mjs";
import { NAMED_SQL_FUNCTION_CONTRACTS, validateNamedSqlFunctionContracts } from "./lib/named-sql-function-contracts.mjs";
import { TABLE_INVENTORY_BASELINE } from "./lib/table-inventory-baseline.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const sqlRoot = path.join(repoRoot, "scripts/rls/sql/generated");
const generatedRoot = path.join(programRoot, "generated");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const stable = (value) => `${JSON.stringify(value, null, 2)}\n`;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const q = (value) => `"${String(value).replaceAll('"', '""')}"`;
const lit = (value) => `'${String(value).replaceAll("'", "''")}'`;
const shortName = (...parts) => {
  const raw = parts.join("_").toLowerCase().replace(/[^a-z0-9_]/g, "_");
  return raw.length <= 63 ? raw : `${raw.slice(0, 52)}_${sha256(raw).slice(0, 10)}`;
};
const transactionalPhase = (sql) => {
  const prefix = "\\set ON_ERROR_STOP on\n";
  if (!sql.startsWith(prefix)) throw new Error("Generated SQL phase must enable ON_ERROR_STOP");
  const body = sql.slice(prefix.length).trimEnd().split("\n").map((line) => line.trimEnd()).join("\n");
  return `${prefix}BEGIN;\n${body}\nCOMMIT;\n`;
};
const readContractSources = (contracts, replacements = []) =>
  [...new Set(contracts.map((contract) => contract.definitionLocation))]
    .map((location) => {
      let source = fs.readFileSync(path.join(repoRoot, location), "utf8");
      for (const [needle, replacement] of replacements) source = source.replaceAll(needle, replacement);
      return source.trim();
    })
    .filter(Boolean)
    .join("\n\n");
const mergeOwnerPolicies = (entries) => [...entries.reduce((groups, [table, command, predicate]) => {
  const key = `${table}:${command}`;
  const group = groups.get(key) || { table, command, predicates: [] };
  if (!group.predicates.includes(predicate)) group.predicates.push(predicate);
  groups.set(key, group);
  return groups;
}, new Map()).values()].map(({ table, command, predicates }) => [
  table,
  command,
  predicates.length === 1 ? predicates[0] : predicates.map((predicate) => `(${predicate})`).join(" OR "),
]);

const tablesManifest = readJson("tables.json");
const workflowsManifest = readJson("workflows.json");
const commandSemantics = readJson("command-semantics.json");
const runtimeIdentities = readJson("runtime-identities.json");
const ownership = readJson("object-ownership-chain.json");
const allowlist = readJson("essential-workflow-allowlist.json");
const familiesManifest = readJson("context-boundary-families.json");
const workflowPartition = readJson("workflow-three-session-partition.json");
const registeredCallPathEvidence = buildRegisteredCallPathEvidence({ workflowsManifest, partition: workflowPartition, repoRoot });
const { sourceContractSha256, inputs: sourceContractInputs, prismaMigrations, prismaSchemaSource } = calculateCleanRoomSourceContract(repoRoot);
const prismaEnumNames = [...new Set([...prismaSchemaSource.matchAll(/^enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/gm)].map((match) => match[1]))].sort();
const environmentArgIndex = process.argv.indexOf("--environment");
const targetEnvironment = environmentArgIndex === -1 ? "certification" : process.argv[environmentArgIndex + 1];
if (!["certification", "development", "staging", "production"].includes(targetEnvironment)) throw new Error("--environment must be certification, development, staging or production");
const deploymentArgIndex = process.argv.indexOf("--deployment-id");
const deploymentId = deploymentArgIndex === -1
  ? ({ certification: "cert", development: "local" }[targetEnvironment] || "")
  : String(process.argv[deploymentArgIndex + 1] || "").trim().toLowerCase();
if (!/^[a-z][a-z0-9_]{0,15}$/.test(deploymentId)) throw new Error("staging and production generation require --deployment-id with a 1-16 character lowercase identifier");

const tables = [...tablesManifest.tables].sort((left, right) => left.physicalTable.localeCompare(right.physicalTable));
const tableById = new Map(tables.map((table) => [table.id, table]));
const workflowById = new Map(workflowsManifest.workflows.map((workflow) => [workflow.id, workflow]));
const ruleById = new Map(commandSemantics.rules.map((rule) => [rule.id, rule]));
const forceTargets = tables.filter((table) => table.rlsApplicability === "force-rls-target");
const migrationOnly = tables.filter((table) => table.rlsApplicability !== "force-rls-target");
if (tables.length !== TABLE_INVENTORY_BASELINE.tables || forceTargets.length !== TABLE_INVENTORY_BASELINE.forceRlsTargets || migrationOnly.length !== TABLE_INVENTORY_BASELINE.migrationOnly) throw new Error(`Expected ${TABLE_INVENTORY_BASELINE.tables}/${TABLE_INVENTORY_BASELINE.forceRlsTargets}/${TABLE_INVENTORY_BASELINE.migrationOnly} tables; found ${tables.length}/${forceTargets.length}/${migrationOnly.length}`);

const candidateWorkflowIds = new Set(allowlist.workflows
  .filter((entry) => entry.currentRuntimeStatus === "runtime-implemented-postgresql-pending")
  .map((entry) => entry.workflowId));
const scheduledComplianceWorkflow = "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler";
const directProfiles = (commandSemantics.sqlCertificationProfiles || []).filter((profile) => profile.status === "direct-policy-candidate");
const blockedProfiles = (commandSemantics.sqlCertificationProfiles || []).filter((profile) => profile.status === "direct-policy-blocked");
if (!directProfiles.length || !blockedProfiles.length) throw new Error("Exact SQL certification profiles are required");

const scalarFields = (table) => new Set(table.schemaEvidence.fields.filter((field) => !field.relation).map((field) => field.name));
const slices = [];
for (const profile of directProfiles) {
  const workflow = workflowById.get(profile.workflowId);
  if (!workflow || !candidateWorkflowIds.has(profile.workflowId)) throw new Error(`SQL profile ${profile.id} does not reference a PostgreSQL-pending implemented workflow`);
  if (!profile.actorClass || !profile.minimumAssurance || !profile.purposeCodes?.length || !profile.scopeType || !profile.route) throw new Error(`SQL profile ${profile.id} is semantically incomplete`);
  for (const ruleId of profile.commandRuleIds || []) {
    const rule = ruleById.get(ruleId);
    const table = rule && tableById.get(rule.tableId);
    if (!rule || !table || !rule.supportingWorkflowIds?.includes(profile.workflowId)) throw new Error(`SQL profile ${profile.id} has invalid source rule ${ruleId}`);
    if (!rule.actorClasses.includes(profile.actorClass)) throw new Error(`SQL profile ${profile.id} broadens actors beyond ${ruleId}`);
    if (rule.minimumAssuranceByActorClass?.[profile.actorClass] !== profile.minimumAssurance) throw new Error(`SQL profile ${profile.id} weakens assurance from ${ruleId}`);
    if (rule.status !== "architecture-resolved" || rule.requiresNamedFunction || rule.authorizationBoundary !== "ordinary-rls") throw new Error(`SQL profile ${profile.id} attempts direct access for a blocked rule`);
    const columns = [...new Set(rule.allowedColumns || [])].sort();
    if (rule.command !== "DELETE" && !columns.length) throw new Error(`SQL rule ${ruleId} has no approved columns`);
    const fields = scalarFields(table);
    if (columns.some((column) => !fields.has(column))) throw new Error(`SQL rule ${ruleId} references a non-column projection`);
    slices.push({
      id: shortName("slice", profile.id, rule.id),
      profileId: profile.id,
      sourceCommandRuleIds: [rule.id],
      workflowId: profile.workflowId,
      route: profile.route,
      tableId: table.id,
      table: table.physicalTable,
      command: rule.command,
      actors: [profile.actorClass],
      roleValues: [...profile.roleValues].sort(),
      minimumAssurance: profile.minimumAssurance,
      purposeCodes: [...profile.purposeCodes].sort(),
      scopeType: profile.scopeType,
      columns,
      certificationStatus: "pending",
    });
  }
}

const commandGroups = new Map();
for (const slice of slices) {
  const key = `${slice.tableId}:${slice.command}`;
  const group = commandGroups.get(key) || [];
  group.push(slice);
  commandGroups.set(key, group);
}
for (const [key, group] of commandGroups) {
  const projections = new Set(group.map((slice) => JSON.stringify(slice.columns)));
  if (projections.size === 1) continue;
  const columns = [...new Set(group.flatMap((slice) => slice.columns))].sort();
  const workflowIds = [...new Set(group.map((slice) => slice.workflowId))].sort();
  const reviewedRiskUserUnion = key === "table-user:SELECT"
    && JSON.stringify(columns) === JSON.stringify(["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "name", "orgId", "role", "status"])
    && JSON.stringify(workflowIds) === JSON.stringify(["workflow-http-backend-src-controllers-audit-controller-ts-get-logs", "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"]);
  if (!reviewedRiskUserUnion) throw new Error(`Incompatible direct column projections must remain blocked: ${key}`);
}

const certificationRoleNames = {
  owner: "mscqr_rls_cert_owner", authOwner: "mscqr_rls_cert_auth_owner", app: "mscqr_rls_cert_app",
  read: "mscqr_rls_cert_read", preauth: "mscqr_rls_cert_preauth", worker: "mscqr_rls_cert_worker",
  scheduled: "mscqr_rls_cert_scheduled", operator: "mscqr_rls_cert_operator", migration: "mscqr_rls_cert_migration",
};
const identityKeys = {
  owner: "identity-table-owner", authOwner: "identity-auth-function-owner", app: "identity-authenticated-app",
  read: "identity-restricted-read", preauth: "identity-pre-auth-app", worker: "identity-worker",
  scheduled: "identity-scheduled-job", operator: "identity-operator", migration: "identity-migration",
};
const identityFor = (key) => runtimeIdentities.identities.find((entry) => entry.id === identityKeys[key]);
const greenRolePrefixes = { development: "mscqr_dev_rls", staging: "mscqr_stg_rls", production: "mscqr_prd_rls" };
const greenRoleSuffixes = { owner: "owner", authOwner: "auth_owner", app: "app", read: "read", preauth: "preauth", worker: "worker", scheduled: "scheduled", operator: "operator", migration: "migration" };
const roleNames = Object.fromEntries(Object.keys(identityKeys).map((key) => [
  key,
  targetEnvironment === "certification" ? certificationRoleNames[key] : `${greenRolePrefixes[targetEnvironment]}_${deploymentId}_${greenRoleSuffixes[key]}`,
]));
for (const [key, name] of Object.entries(roleNames)) {
  if (!identityFor(key) || name.length > 63) throw new Error(`No valid clean-room role contract for ${identityKeys[key]}`);
}
const roleSpecs = Object.keys(identityKeys).map((key) => ({ key, name: roleNames[key], login: identityFor(key)?.loginExpectation === "LOGIN" }));
const roleValuesSql = roleSpecs.map((role) => `(${lit(role.name)}, ${role.login})`).join(",\n    ");
const managedRoleList = roleSpecs.map((role) => lit(role.name)).join(", ");
const administrativeExecutorRoles = {
  certification: "certification-administrator",
  development: "mscqr_dev_admin",
  staging: "mscqr_staging_admin",
  production: "unresolved-production-administrator",
};
const administrativeExecutorRole = administrativeExecutorRoles[targetEnvironment];
const candidateDatabasePatterns = {
  certification: "^mscqr_full_rls_cert_[a-z0-9_]+$",
  development: `^mscqr_dev_rls_green_${deploymentId}$`,
  staging: `^mscqr_staging_rls_green_${deploymentId}$`,
  production: `^mscqr_production_rls_green_${deploymentId}$`,
};
const candidateDatabasePattern = candidateDatabasePatterns[targetEnvironment];
const roleMarker = `mscqr-full-rls-clean-room:${targetEnvironment}:${sourceContractSha256}`;
const b01Contracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.definitionLocation === "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql"
    && contract.security.runtimeExecuteGrantees.includes("preauth")
);
const authenticatedSessionContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  ["b01-issue-authenticated-session", "b01-require-authenticated-session", "b01-revoke-authenticated-session", "b01-revoke-all-authenticated-sessions"].includes(contract.id)
);
const authenticationClosureContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-b-b01-authentication-closure"
);
const preAuthContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-b-b01-preauth"
);
const c03Contracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-c-c03"
);
const administrationContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-c-c01-administration"
);
const qrSystemContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "release-fix-4-qr-system"
);
const printingLifecycleContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "release-fix-5-printing-lifecycle"
);
const publicVerificationContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "release-fix-6-public-verification"
);
const scheduledContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-b-b03-scheduled"
);
const outboxContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-b-b03-outbox"
);
const b03AuthenticatedContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-b-b03-authenticated"
);
const operationalReadContracts = validateNamedSqlFunctionContracts().filter((contract) =>
  contract.security.deploymentPhase === "session-a-operational-read"
);
const b01FunctionSource = b01Contracts.length
  ? fs.readFileSync(path.join(repoRoot, b01Contracts[0].definitionLocation), "utf8").replaceAll("{{AUTH_OWNER}}", q(roleNames.authOwner))
  : "";
const b01FunctionSignatures = b01Contracts.map((contract) => `app_auth.${contract.name}(${contract.signature})`);
const authenticatedSessionFunctionSource = authenticatedSessionContracts.length
  ? fs.readFileSync(path.join(repoRoot, authenticatedSessionContracts[0].definitionLocation), "utf8").replaceAll("{{AUTH_OWNER}}", q(roleNames.authOwner))
  : "";
const authenticatedSessionFunctionSignatures = authenticatedSessionContracts.map((contract) => `app_auth.${contract.name}(${contract.signature})`);
const authenticatedSessionPreauthSignatures = authenticatedSessionContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("preauth")).map((contract) => `app_auth.${contract.name}(${contract.signature})`);
const authenticatedSessionAppSignatures = authenticatedSessionContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_auth.${contract.name}(${contract.signature})`);
const authenticationClosureFunctionSource = authenticationClosureContracts.length
  ? fs.readFileSync(path.join(repoRoot, authenticationClosureContracts[0].definitionLocation), "utf8")
  : "";
const authenticationClosureFunctionSignatures = authenticationClosureContracts.map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const authenticationClosurePreauthSignatures = authenticationClosureContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("preauth")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const authenticationClosureAppSignatures = authenticationClosureContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const authenticationClosureOwnerPrivileges = [...new Map(authenticationClosureContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const authenticationClosureOwnerPolicies = [...new Map(authenticationClosureContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const preAuthFunctionSource = preAuthContracts.length
  ? fs.readFileSync(path.join(repoRoot, preAuthContracts[0].definitionLocation), "utf8").replaceAll("{{AUTH_OWNER}}", q(roleNames.authOwner))
  : "";
const preAuthFunctionSignatures = preAuthContracts.map((contract) => `app_auth.${contract.name}(${contract.signature})`);
const preAuthOwnerPrivileges = [...new Map(preAuthContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const preAuthOwnerPolicies = [...new Map(preAuthContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const c03FunctionSource = `${fs.readFileSync(path.join(repoRoot, "backend/src/rls-waves/session-c/c03/c03Boundary.sql"), "utf8")}\n${readContractSources(c03Contracts, [
  ["{{AUTH_OWNER}}", q(roleNames.authOwner)],
  ["{{APP_ROLE}}", lit(roleNames.app)],
  ["{{PREAUTH_ROLE}}", roleNames.preauth],
  ["{{WORKER_ROLE}}", roleNames.worker],
])}`;
const c03AppSignatures = c03Contracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const c03PreauthSignatures = c03Contracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("preauth")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const c03WorkerSignatures = c03Contracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("worker")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const c03OwnerPrivileges = [...new Map(c03Contracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const c03OwnerPolicies = mergeOwnerPolicies(c03Contracts.flatMap((contract) => contract.security.ownerPolicies || []));
const administrationFunctionSource = administrationContracts.length
  ? fs.readFileSync(path.join(repoRoot, administrationContracts[0].definitionLocation), "utf8")
  : "";
const administrationAppSignatures = administrationContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const administrationOwnerPrivileges = [...new Map(administrationContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const administrationOwnerPolicies = [...new Map(administrationContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const qrSystemFunctionSource = qrSystemContracts.length
  ? fs.readFileSync(path.join(repoRoot, qrSystemContracts[0].definitionLocation), "utf8")
      .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker))
  : "";
const qrSystemAppSignatures = qrSystemContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const qrSystemWorkerSignatures = qrSystemContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("worker")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const qrSystemOwnerPrivileges = [...new Map(qrSystemContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const qrSystemOwnerPolicies = [...new Map(qrSystemContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const printingLifecycleFunctionSource = printingLifecycleContracts.length
  ? fs.readFileSync(path.join(repoRoot, printingLifecycleContracts[0].definitionLocation), "utf8")
      .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
      .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker))
  : "";
const printingLifecycleAppSignatures = printingLifecycleContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const printingLifecycleWorkerSignatures = printingLifecycleContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("worker")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const printingLifecycleOwnerPrivileges = [...new Map(printingLifecycleContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const printingLifecycleOwnerPolicies = [...new Map(printingLifecycleContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const publicVerificationFunctionSource = publicVerificationContracts.length
  ? fs.readFileSync(path.join(repoRoot, publicVerificationContracts[0].definitionLocation), "utf8")
  : "";
const publicVerificationSignatures = publicVerificationContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("preauth")).map((contract) => `app_public.${contract.name}(${contract.signature})`);
const publicVerificationOwnerPrivileges = [...new Map(publicVerificationContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const publicVerificationOwnerPolicies = [...new Map(publicVerificationContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const contractEvidenceFor = (contracts, table, command) => contracts
  .filter((contract) => contract.tableCommands.some(([candidateTable, candidateCommand]) => candidateTable === table && candidateCommand === command))
  .map((contract) => `contract:${contract.id}:${table}:${command}`)
  .sort();
const c03PolicyEvidenceFor = (table, command) => {
  const contracts = contractEvidenceFor(c03Contracts, table, command);
  if (contracts.length) return contracts;
  return [commandSemantics.rules.find((rule) =>
    rule.tableId === tables.find((entry) => entry.physicalTable === table)?.id &&
    rule.command === command && rule.authorizationBoundary !== "prohibited"
  )?.id].filter(Boolean);
};
const scheduledFunctionSource = scheduledContracts.length
  ? fs.readFileSync(path.join(repoRoot, scheduledContracts[0].definitionLocation), "utf8")
      .replaceAll("{{AUTH_OWNER}}", q(roleNames.authOwner))
      .replaceAll("{{SCHEDULED_ROLE}}", lit(roleNames.scheduled))
      .replaceAll("{{OPERATOR_ROLE}}", lit(roleNames.operator))
  : "";
const scheduledSignatures = scheduledContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("scheduled")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const scheduledOperatorSignatures = scheduledContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("operator")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const scheduledOwnerPrivileges = [...new Map(scheduledContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const scheduledOwnerPolicies = [...new Map(scheduledContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const outboxFunctionSource = outboxContracts.length
  ? fs.readFileSync(path.join(repoRoot, outboxContracts[0].definitionLocation), "utf8")
      .replaceAll("{{AUTH_OWNER}}", q(roleNames.authOwner))
      .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
      .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker))
  : "";
const outboxAppSignatures = outboxContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("app")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const outboxWorkerSignatures = outboxContracts.filter((contract) => contract.security.runtimeExecuteGrantees.includes("worker")).map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const outboxOwnerPrivileges = [...new Map(outboxContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const outboxOwnerPolicies = [...new Map(outboxContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const b03AuthenticatedFunctionSource = readContractSources(b03AuthenticatedContracts, [
  ["{{AUTH_OWNER}}", q(roleNames.authOwner)],
  ["{{APP_ROLE}}", lit(roleNames.app)],
]);
const b03AuthenticatedAppSignatures = b03AuthenticatedContracts.map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const b03AuthenticatedOwnerPrivileges = [...new Map(b03AuthenticatedContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const b03AuthenticatedOwnerPolicies = mergeOwnerPolicies(b03AuthenticatedContracts.flatMap((contract) => contract.security.ownerPolicies || []));
const operationalReadFunctionSource = operationalReadContracts.length
  ? fs.readFileSync(path.join(repoRoot, operationalReadContracts[0].definitionLocation), "utf8")
      .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
  : "";
const operationalReadSignatures = operationalReadContracts.map((contract) => `app_rls.${contract.name}(${contract.signature})`);
const operationalReadInternalSignatures = [
  "app_rls.setting(text)",
  "app_rls.uuid_setting(text)",
  "app_rls.current_user_id()",
  "app_rls.current_organization_id()",
  "app_rls.current_licensee_id()",
  "app_rls.current_manufacturer_id()",
  "app_rls.current_role()",
  "app_rls.current_assurance()",
  "app_rls.current_request_id()",
  "app_rls.current_purpose()",
  "app_rls.attributed_request()",
  "app_rls.dashboard_scope_fingerprint(text)",
  "app_rls.authorize_dashboard_snapshot(text,text,text)",
  "app_rls.dashboard_snapshot_scope(text,text,text)",
  "app_rls.dashboard_snapshot_data(text,text,text,text)",
  "app_rls.batch_scope_fingerprint(text,text,text)",
  "app_rls.batch_operational_batch_allowed(text,text)",
  "app_rls.authorize_batch_operational_read(text,text,text,text)",
  "app_rls.batch_operational_scope(text,text,text,text)",
  "app_rls.batch_operational_rows(text,text,text,text,text,integer,integer)",
  "app_rls.batch_operational_total(text,text,text,text,text)",
  "app_rls.batch_inventory_rollups(text,text,text,text,text,text[])",
  "app_rls.batch_unassigned_ranges(text,text,text,text,text,text[])",
  "app_rls.batch_status_fallback(text,text,text,text,text,text[])",
  "app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text[])",
];
const operationalReadOwnerPrivileges = [...new Map(operationalReadContracts.flatMap((contract) => contract.security.ownerPrivileges || []).map((entry) => [JSON.stringify(entry), entry])).values()];
const operationalReadOwnerPolicies = [...new Map(operationalReadContracts.flatMap((contract) => contract.security.ownerPolicies || []).map((entry) => [JSON.stringify(entry), entry])).values()];
// This is deliberately an exact runtime execution allowlist.  The functions
// are the only app_rls public boundaries emitted by this clean-room package;
// context setters and authorization helpers stay internal to their owner.
const appRuntimeFunctionSignatures = [
  "app_rls.setting(text)",
  "app_rls.uuid_setting(text)",
  "app_rls.current_user_id()",
  "app_rls.current_organization_id()",
  "app_rls.current_licensee_id()",
  "app_rls.current_manufacturer_id()",
  "app_rls.current_role()",
  "app_rls.current_assurance()",
  "app_rls.current_request_id()",
  "app_rls.current_purpose()",
  "app_rls.attributed_request()",
  "app_rls.manufacturer_scope_valid(text)",
  "app_rls.actor_scope_valid()",
];
const b01FunctionOwnerGrants = [
  ["RefreshToken", "SELECT", ["id","orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt","revokedAt","revokedReason","replacedByTokenHash","rotationRequestId","rotationClaimedAt","rotationCompletedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityAssurance","sessionCapabilityExpiresAt","sessionCapabilityLastUsedAt","sessionCapabilityRevokedAt","sessionCapabilityRevokedReason"]],
  ["RefreshToken", "INSERT", ["id","orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt"]],
  ["RefreshToken", "UPDATE", ["revokedAt","revokedReason","lastUsedAt","replacedByTokenHash","rotationRequestId","rotationClaimedAt","rotationCompletedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityAssurance","sessionCapabilityExpiresAt","sessionCapabilityLastUsedAt","sessionCapabilityRevokedAt","sessionCapabilityRevokedReason"]],
  ["User", "SELECT", ["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","emailVerifiedAt"]],
  ["ManufacturerLicenseeLink", "SELECT", ["manufacturerId","licenseeId","isPrimary","createdAt","updatedAt"]],
  ["Licensee", "SELECT", ["id","orgId","name","prefix","brandName","isActive","suspendedAt"]],
  ["Organization", "SELECT", ["id","isActive"]],
  ["AdminMfaCredential", "SELECT", ["userId","isEnabled","lastUsedAt"]],
  ["AdminWebAuthnCredential", "SELECT", ["userId","lastUsedAt"]],
  ["UserMfaFactor", "SELECT", ["userId","type","lastUsedAt","disabledAt"]],
  ["UserBackupCode", "SELECT", ["userId","usedAt"]],
  ["AuthMfaChallenge", "INSERT", ["id","userId","ticketHash","sessionBindingHash","purpose","riskScore","riskLevel","reasons","createdIpHash","createdUserAgentHash","maxAttempts","createdAt","updatedAt","expiresAt"]],
  ["AuditLogOutbox", "INSERT", ["id","payload","updatedAt"]],
];
const b01OwnerGrantSql = b01FunctionOwnerGrants.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const preAuthOwnerGrantSql = preAuthOwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const authenticationClosureOwnerGrantSql = authenticationClosureOwnerPrivileges.map(([table, command, columns]) => command === "DELETE"
  ? `GRANT DELETE ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
  : `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const c03OwnerGrantSql = c03OwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const administrationOwnerGrantSql = administrationOwnerPrivileges.map(([table, command, columns]) => command === "DELETE"
  ? `GRANT DELETE ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
  : `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const qrSystemOwnerGrantSql = qrSystemOwnerPrivileges.map(([table, command, columns]) => command === "DELETE"
  ? `GRANT DELETE ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
  : `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const printingLifecycleOwnerGrantSql = printingLifecycleOwnerPrivileges.map(([table, command, columns]) =>
  command === "DELETE"
    ? `GRANT DELETE ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
    : `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
).join("\n");
const publicVerificationOwnerGrantSql = publicVerificationOwnerPrivileges.map(([table, command, columns]) =>
  command === "DELETE"
    ? `GRANT DELETE ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
    : `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`
).join("\n");
const scheduledOwnerGrantSql = scheduledOwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const outboxOwnerGrantSql = outboxOwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const b03AuthenticatedOwnerGrantSql = b03AuthenticatedOwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const operationalReadOwnerGrantSql = operationalReadOwnerPrivileges.map(([table, command, columns]) => `GRANT ${command} (${columns.map(q).join(", ")}) ON TABLE public.${q(table)} TO ${q(roleNames.authOwner)};`).join("\n");
const functionOwnerRows = [
  ...b01FunctionOwnerGrants.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: b01Contracts.map((contract) => contract.id) })),
  ...preAuthOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: preAuthContracts.map((contract) => contract.id) })),
  ...authenticationClosureOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: authenticationClosureContracts.map((contract) => contract.id) })),
  ...c03OwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: c03Contracts.map((contract) => contract.id) })),
  ...administrationOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: administrationContracts.map((contract) => contract.id) })),
  ...qrSystemOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: qrSystemContracts.map((contract) => contract.id) })),
  ...printingLifecycleOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: printingLifecycleContracts.map((contract) => contract.id) })),
  ...publicVerificationOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: publicVerificationContracts.map((contract) => contract.id) })),
  ...scheduledOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: scheduledContracts.map((contract) => contract.id) })),
  ...outboxOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: outboxContracts.map((contract) => contract.id) })),
  ...b03AuthenticatedOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: b03AuthenticatedContracts.map((contract) => contract.id) })),
  ...operationalReadOwnerPrivileges.map(([table, command, columns]) => ({ table, command, columns, grantee: roleNames.authOwner, ownerIdentity: "identity-auth-function-owner", contracts: operationalReadContracts.map((contract) => contract.id) })),
];
const b01PolicyOwner = `current_user=${lit(roleNames.authOwner)}`;
const b01User = `current_setting('app.b01_user_id',true)`;
const b01Predecessor = `current_setting('app.b01_predecessor_id',true)`;
const b01Successor = `current_setting('app.b01_successor_id',true)`;
const b01Operation = `current_setting('app.b01_operation',true)`;
const b01Token = `"tokenHash"=ANY(string_to_array(current_setting('app.b01_token_hashes',true),','))`;
const b01DerivedToken = `id=${b01Predecessor} AND "userId"=${b01User}`;
const b01BootstrapToken = `${b01Token} AND ${b01Predecessor}='' AND ${b01User}=''`;
const b01UserWideOperation = `${b01Operation} IN ('revoke-scope','reuse-revoke','account-unavailable','stale-membership')`;
const b01BoundContext = `${b01Predecessor}<>''`;
const b01BoundUser = `${b01BoundContext} AND "userId"=${b01User}`;
const b01TablePolicies = [
  ["RefreshToken", "SELECT", `(${b01PolicyOwner} AND (${b01Token} OR ${b01DerivedToken} OR (${b01UserWideOperation} AND "userId"=${b01User})))`],
  ["RefreshToken", "UPDATE", `(${b01PolicyOwner} AND (${b01BootstrapToken} OR ${b01DerivedToken} OR (${b01UserWideOperation} AND "userId"=${b01User})))`],
  ["RefreshToken", "INSERT", `(${b01PolicyOwner} AND ${b01Operation}='complete-rotation' AND id=${b01Successor} AND "userId"=${b01User})`],
  ["User", "SELECT", `(${b01PolicyOwner} AND ${b01Predecessor}<>'' AND id=${b01User})`],
  ["ManufacturerLicenseeLink", "SELECT", `(${b01PolicyOwner} AND ${b01BoundContext} AND "manufacturerId"=${b01User})`],
  ["Licensee", "SELECT", `(${b01PolicyOwner} AND ${b01BoundContext} AND ("orgId"=NULLIF(current_setting('app.b01_organization_id',true),'') OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=${b01User} AND ml."licenseeId"=id)))`],
  ["Organization", "SELECT", `(${b01PolicyOwner} AND ${b01BoundContext} AND id=NULLIF(current_setting('app.b01_organization_id',true),''))`],
  ["AdminMfaCredential", "SELECT", `(${b01PolicyOwner} AND ${b01BoundUser})`],
  ["AdminWebAuthnCredential", "SELECT", `(${b01PolicyOwner} AND ${b01BoundUser})`],
  ["UserMfaFactor", "SELECT", `(${b01PolicyOwner} AND ${b01BoundUser})`],
  ["UserBackupCode", "SELECT", `(${b01PolicyOwner} AND ${b01BoundUser})`],
  ["AuthMfaChallenge", "INSERT", `(${b01PolicyOwner} AND ${b01Operation}='create-mfa' AND "userId"=${b01User} AND purpose='admin_login' AND "consumedAt" IS NULL AND "supersededAt" IS NULL)`],
  ["AuditLogOutbox", "INSERT", `(${b01PolicyOwner} AND ${b01Predecessor}<>'' AND payload->>'userId'=${b01User} AND payload->'details'->>'requestId'=current_setting('app.b01_request_id',true) AND payload->>'action' IN ('AUTH_REFRESH_DISABLED_DENIED','AUTH_REFRESH_REUSE_DETECTED','AUTH_REFRESH_EXPIRED','AUTH_REFRESH_STALE_MEMBERSHIP_DENIED','MANUFACTURER_SCOPE_SWITCH','AUTH_REFRESH_MFA_CHALLENGE_REQUIRED','AUTH_REFRESH_REVOKED','AUTH_REFRESH_ROTATED'))`],
];
const authenticatedSessionPolicy = `(current_setting('app.auth_session_operation',true)='verify' AND "sessionCapabilityHash"=current_setting('app.auth_session_hash',true) OR current_setting('app.auth_session_operation',true)='issue' AND id=current_setting('app.auth_session_id',true) AND "tokenHash"=current_setting('app.auth_session_refresh_hash',true) OR current_setting('app.auth_session_operation',true)='revoke-one' AND "userId"=current_setting('app.user_id',true) AND id=current_setting('app.auth_session_target_id',true) OR current_setting('app.auth_session_operation',true)='revoke-user' AND "userId"=current_setting('app.user_id',true))`;
const authenticatedSessionUserPolicy = `(current_setting('app.auth_session_operation',true)='verify' AND public."User".id=current_setting('app.user_id',true) AND EXISTS (SELECT 1 FROM public."RefreshToken" s WHERE s."userId"=public."User".id AND s."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND s."sessionCapabilityHashVersion"='sha256-v1' AND s."sessionCapabilityRevokedAt" IS NULL AND s."sessionCapabilityExpiresAt">clock_timestamp() AND s."revokedAt" IS NULL AND s."expiresAt">clock_timestamp()))`;
const b01SourceRuleIds = new Map([
  ["RefreshToken:SELECT", "command-refresh-token-select-65b85bc0759d"], ["RefreshToken:INSERT", "command-refresh-token-insert-65b85bc0759d"], ["RefreshToken:UPDATE", "command-refresh-token-update-65b85bc0759d"],
  ["User:SELECT", "command-user-select-65b85bc0759d"], ["ManufacturerLicenseeLink:SELECT", "command-manufacturer-licensee-link-select-65b85bc0759d"], ["Licensee:SELECT", "command-licensee-select-65b85bc0759d"], ["Organization:SELECT", "command-organization-select-65b85bc0759d"],
  ["AdminMfaCredential:SELECT", "command-admin-mfa-credential-select-65b85bc0759d"], ["AdminWebAuthnCredential:SELECT", "command-admin-web-authn-credential-select-65b85bc0759d"], ["UserMfaFactor:SELECT", "command-user-mfa-factor-select-65b85bc0759d"], ["UserBackupCode:SELECT", "command-user-backup-code-select-65b85bc0759d"],
  ["AuthMfaChallenge:INSERT", "command-auth-mfa-challenge-insert-65b85bc0759d"], ["AuditLogOutbox:INSERT", "command-audit-log-outbox-insert-65b85bc0759d"],
]);

const assuranceGuard = (slice) => {
  const allowed = slice.minimumAssurance === "mfa-verified"
    ? ["mfa-verified", "step-up-verified", "dual-approved-break-glass"]
    : ["password-verified", "mfa-verified", "step-up-verified", "dual-approved-break-glass"];
  return `app_rls.current_assurance() IN (${allowed.map(lit).join(", ")})`;
};
const roleGuard = (slice) => `app_rls.current_role() IN (${slice.roleValues.map(lit).join(", ")})`;
const purposeGuard = (slice) => `app_rls.current_purpose() IN (${slice.purposeCodes.map(lit).join(", ")})`;
const manufacturerRoles = "app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')";
const tenantAdminRoles = "app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN')";
const platformRoles = "app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')";

const scopeForSlice = (slice) => {
  const table = tableById.get(slice.tableId);
  const fields = scalarFields(table);
  const licensee = fields.has("licenseeId") ? q("licenseeId") : null;
  const org = fields.has("orgId") ? q("orgId") : fields.has("organizationId") ? q("organizationId") : null;
  const manufacturer = slice.actors[0] === "manufacturer";
  const platform = slice.actors[0] === "platform-admin";
  const platformOrgMatch = (column) => `EXISTS (SELECT 1 FROM public.${q("Licensee")} scope_licensee WHERE scope_licensee.${q("id")}=app_rls.current_licensee_id() AND scope_licensee.${q("orgId")}=${q(table.physicalTable)}.${column} AND scope_licensee.${q("isActive")}=TRUE AND scope_licensee.${q("suspendedAt")} IS NULL)`;
  const scopedOrg = (column) => platform
    ? `(${column} IS NULL OR ${platformOrgMatch(column)})`
    : `(${column} IS NULL OR ${column}=app_rls.current_organization_id())`;
  if (table.physicalTable === "AuditLog") {
    if (manufacturer) return `(${q("userId")} = app_rls.current_user_id() AND ${q("licenseeId")} = app_rls.current_licensee_id() AND ${q("orgId")} = app_rls.current_organization_id() AND app_rls.manufacturer_scope_valid(app_rls.current_user_id()))`;
    if (platform) return slice.command === "INSERT"
      ? `(${q("userId")}=app_rls.current_user_id() AND ${q("licenseeId")}=app_rls.current_licensee_id() AND ${platformOrgMatch(q("orgId"))})`
      : `${q("licenseeId")}=app_rls.current_licensee_id()`;
    return `(${slice.command === "INSERT" ? `${q("userId")} = app_rls.current_user_id() AND ` : ""}${q("licenseeId")} = app_rls.current_licensee_id() AND ${slice.command === "INSERT" ? `${q("orgId")} = app_rls.current_organization_id()` : `(${q("orgId")} IS NULL OR ${q("orgId")} = app_rls.current_organization_id())`})`;
  }
  if (table.physicalTable === "User") {
    if (slice.workflowId === "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics") return `(${q("id")}=app_rls.current_user_id() OR app_rls.manufacturer_scope_valid(${q("id")}))`;
    if (manufacturer) return `(${q("id")} = app_rls.current_user_id() AND app_rls.manufacturer_scope_valid(${q("id")}))`;
    return `((${q("id")} = app_rls.current_user_id() OR ${q("licenseeId")} = app_rls.current_licensee_id() OR app_rls.manufacturer_scope_valid(${q("id")})) AND (${q("orgId")} IS NULL OR ${q("orgId")} = app_rls.current_organization_id()))`;
  }
  if (table.physicalTable === "Organization") return platform ? platformOrgMatch(q("id")) : `${q("id")} = app_rls.current_organization_id()`;
  if (table.physicalTable === "Licensee") return platform ? `${q("id")}=app_rls.current_licensee_id()` : `(${q("id")} = app_rls.current_licensee_id() AND ${q("orgId")} = app_rls.current_organization_id())`;
  if (table.physicalTable === "PolicyRule") return `(
    (${q("licenseeId")} = app_rls.current_licensee_id() AND ${scopedOrg(q("orgId"))} AND (${q("manufacturerId")} IS NULL OR app_rls.manufacturer_scope_valid(${q("manufacturerId")})))
    OR (${q("licenseeId")} IS NULL AND ${platform ? platformOrgMatch(q("orgId")) : `${q("orgId")} = app_rls.current_organization_id()`} AND ${q("manufacturerId")} IS NULL)
    OR (${q("licenseeId")} IS NULL AND ${q("manufacturerId")} IS NOT NULL AND ${scopedOrg(q("orgId"))} AND app_rls.manufacturer_scope_valid(${q("manufacturerId")}))
  ) AND ${q("isActive")} = TRUE`;
  if (table.physicalTable === "TraceEvent" && manufacturer) return `(${q("licenseeId")} = app_rls.current_licensee_id() AND ${q("manufacturerId")} = app_rls.current_user_id() AND app_rls.manufacturer_scope_valid(app_rls.current_user_id()))`;
  if (licensee && org) return `(${licensee} = app_rls.current_licensee_id() AND ${scopedOrg(org)})`;
  if (licensee) return `${licensee} = app_rls.current_licensee_id()`;
  if (org) return `${org} = app_rls.current_organization_id()`;
  throw new Error(`No exact direct scope expression for ${slice.id}`);
};

for (const slice of slices) {
  slice.scopePredicate = scopeForSlice(slice);
  slice.policyPredicate = `(app_rls.attributed_request() AND app_rls.actor_scope_valid() AND ${roleGuard(slice)} AND ${assuranceGuard(slice)} AND ${purposeGuard(slice)} AND (${slice.scopePredicate}))`;
  slice.policyName = shortName("full_rls", slice.table, slice.command, slice.profileId, slice.actors[0]);
}

const grants = [...commandGroups.values()].map((group) => ({
  tableId: group[0].tableId,
  table: group[0].table,
  command: group[0].command,
  columns: [...new Set(group.flatMap((slice) => slice.columns))].sort(),
  sourceCommandRuleIds: [...new Set(group.flatMap((slice) => slice.sourceCommandRuleIds))].sort(),
})).filter(({ table }) => !["QRCode", "QRRange"].includes(table))
  .sort((left, right) => `${left.table}:${left.command}`.localeCompare(`${right.table}:${right.command}`));
const appTypeGrantNames = [...new Set(grants.flatMap((grant) => {
  const fields = new Map(tableById.get(grant.tableId).schemaEvidence.fields.map((field) => [field.name, field]));
  return grant.columns.map((column) => fields.get(column)?.type).filter((type) => prismaEnumNames.includes(type));
}))].sort();
const dispositions = tables.map((table) => {
  const tableSlices = slices.filter((slice) => slice.tableId === table.id);
  const tableGrants = grants.filter((grant) => grant.tableId === table.id);
  return {
    tableId: table.id,
    table: table.physicalTable,
    category: table.category,
    rls: table.rlsApplicability === "force-rls-target" ? "ENABLE AND FORCE" : "not-applicable-migration-only",
    owner: "identity-table-owner",
    policyFamily: tableSlices.length ? "exact-command-rule-slices" : table.rlsApplicability === "force-rls-target" ? "deny-by-default-no-policy" : "migration-only",
    policySlices: tableSlices.map((slice) => slice.id),
    columnGrants: tableGrants,
    disposition: tableSlices.length ? "exact-policy-certification-candidate" : table.rlsApplicability === "force-rls-target" ? "fail-closed-no-runtime-grant" : "migration-only-no-runtime-grant",
    postgresqlCertification: "pending",
  };
});

// This is emitted as a psql script, where each top-level statement is its own
// transaction unless the caller explicitly starts one.  SET LOCAL inside the
// validation DO block would therefore expire before the protected statements
// that follow.  Validate first, then keep the reviewed role for the script
// section until the paired RESET ROLE.
const setRole = (role) => `DO $$ BEGIN
  IF NOT pg_has_role(session_user,${lit(role)},'SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for ${role}'; END IF;
END $$;
SET ROLE ${q(role)};`;
const resetRole = `RESET ROLE;`;
const targetTableList = tables.map((table) => lit(table.physicalTable)).join(", ");
const expectedMigrationTableList = [...tables.map((table) => table.physicalTable), "_prisma_migrations"].sort();
const expectedMigrationTableValues = expectedMigrationTableList.map((name) => `(${lit(name)})`).join(",");
const expectedEnumValues = prismaEnumNames.map((name) => `(${lit(name)})`).join(",");
const loginRoleNames = roleSpecs.filter((role) => role.login).map((role) => role.name);
const cleanRoomObjectRefusalSql = `
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname<>'information_schema' AND nspname<>'public') THEN RAISE EXCEPTION 'clean-room preflight refuses an unexpected user schema'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public')
  THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing application objects'; END IF;
  IF EXISTS (SELECT 1 FROM pg_policies) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing policies'; END IF;
  IF EXISTS (SELECT 1 FROM pg_default_acl) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing default ACLs'; END IF;
  IF EXISTS (SELECT 1 FROM pg_publication) OR EXISTS (SELECT 1 FROM pg_subscription) THEN RAISE EXCEPTION 'clean-room preflight refuses publications or subscriptions'; END IF;`;
const cleanRoomRoleRefusalSql = `
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN (${managedRoleList})) THEN RAISE EXCEPTION 'clean-room preflight refuses a pre-existing managed role'; END IF;`;
const cleanRoomAclRefusalSql = `
  IF EXISTS (SELECT 1 FROM pg_database WHERE datname=current_database() AND datacl IS NOT NULL) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing database grants'; END IF;
  IF (SELECT count(*) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl WHERE n.nspname='public')<>3
     OR NOT has_schema_privilege('public','public','USAGE') OR has_schema_privilege('public','public','CREATE')
     OR EXISTS (
       SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl
       WHERE n.nspname='public' AND NOT (
         (acl.grantee=n.nspowner AND acl.grantor=n.nspowner AND acl.privilege_type IN ('USAGE','CREATE') AND NOT acl.is_grantable)
         OR (acl.grantee=0 AND acl.grantor=n.nspowner AND acl.privilege_type='USAGE' AND NOT acl.is_grantable)
       )
     )
  THEN RAISE EXCEPTION 'clean-room preflight refuses non-baseline public schema grants'; END IF;`;

const environmentExecutorCheckSql = targetEnvironment === "production"
  ? "  RAISE EXCEPTION 'Production generation is evidence-only until the exact brokered administrator is recorded and approved';"
  : `  IF current_user<>${lit(administrativeExecutorRole)} THEN RAISE EXCEPTION 'Expected ${administrativeExecutorRole} brokered administrative executor'; END IF;`;
const stagingExecutorAttributeCheckSql = targetEnvironment === "staging"
  ? "  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) THEN RAISE EXCEPTION 'Staging administrator must not be SUPERUSER or BYPASSRLS'; END IF;"
  : "";
const cleanRoomPreflightBodySql = `
${environmentExecutorCheckSql}
${stagingExecutorAttributeCheckSql}
  IF current_setting('server_version_num')::integer / 10000 <> 18 THEN RAISE EXCEPTION 'Full RLS package requires PostgreSQL 18 catalog semantics'; END IF;
  IF current_database() !~ ${lit(candidateDatabasePattern)} THEN RAISE EXCEPTION 'clean-room package is bound to a green database name matching ${candidateDatabasePattern}'; END IF;
  SELECT owner_role.rolname INTO STRICT database_owner FROM pg_database d JOIN pg_roles owner_role ON owner_role.oid=d.datdba WHERE d.datname=current_database();
  IF database_owner<>current_user THEN RAISE EXCEPTION 'clean-room executor must own the green candidate database'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND (NOT rolcreaterole OR NOT rolcreatedb)) THEN RAISE EXCEPTION 'clean-room executor requires CREATEROLE and CREATEDB without runtime use'; END IF;
  IF current_user IN (${managedRoleList}) THEN RAISE EXCEPTION 'administrative executor may not be a managed identity'; END IF;
  IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()) THEN
    PERFORM pg_sleep(1);
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()) THEN RAISE EXCEPTION 'clean-room preflight refuses another green database session'; END IF;
  END IF;
${cleanRoomRoleRefusalSql}
${cleanRoomObjectRefusalSql}
${cleanRoomAclRefusalSql}
  IF EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname<>'plpgsql' OR n.nspname<>'pg_catalog') THEN RAISE EXCEPTION 'clean-room preflight refuses non-baseline extensions'; END IF;`;
const preflightSql = `\\set ON_ERROR_STOP on
SELECT current_database() AS green_database, current_user AS executor;
DO $$ DECLARE database_owner text; BEGIN
${cleanRoomPreflightBodySql}
END $$;
`;

const migrationDefaultPrivilegeHardeningSql = [
  "TABLES", "SEQUENCES", "ROUTINES", "TYPES", "SCHEMAS", "LARGE OBJECTS",
].map((objectClass) => `ALTER DEFAULT PRIVILEGES FOR ROLE ${q(roleNames.migration)} REVOKE ALL ON ${objectClass} FROM PUBLIC;`).join("\n");
const roleCreationSql = `\\set ON_ERROR_STOP on
DO $$ DECLARE database_owner text; BEGIN
${cleanRoomPreflightBodySql}
${roleSpecs.map((role) => `  EXECUTE ${lit(`CREATE ROLE ${q(role.name)} ${role.login ? "LOGIN" : "NOLOGIN"} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`)};`).join("\n")}
END $$;
${roleSpecs.map((role) => `GRANT ${q(role.name)} TO ${q(administrativeExecutorRole)} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE ${q(role.name)} IS ${lit(roleMarker)};`).join("\n")}
CREATE SCHEMA mscqr_rls_install AUTHORIZATION ${q(administrativeExecutorRole)};
REVOKE ALL ON SCHEMA mscqr_rls_install FROM PUBLIC;
CREATE TABLE mscqr_rls_install.state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  target_environment text NOT NULL,
  deployment_id text NOT NULL,
  green_database text NOT NULL,
  source_contract_sha256 text NOT NULL,
  package_role_marker text NOT NULL,
  administrator_role text NOT NULL,
  phase text NOT NULL,
  traffic_enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE mscqr_rls_install.expected_policy (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  policy_name text NOT NULL,
  permissive boolean NOT NULL,
  command_name text NOT NULL,
  role_names text[] NOT NULL,
  using_tree text,
  with_check_tree text,
  policy_comment text NOT NULL,
  PRIMARY KEY(schema_name,table_name,policy_name)
);
CREATE TABLE mscqr_rls_install.expected_routine (
  schema_name text NOT NULL,
  routine_name text NOT NULL,
  identity_arguments text NOT NULL,
  result_type text NOT NULL,
  routine_kind text NOT NULL,
  owner_name text NOT NULL,
  language_name text NOT NULL,
  volatility text NOT NULL,
  security_definer boolean NOT NULL,
  leakproof boolean NOT NULL,
  strict boolean NOT NULL,
  parallel_mode text NOT NULL,
  configuration text[],
  source_body text NOT NULL,
  acl_rows jsonb NOT NULL,
  PRIMARY KEY(schema_name,routine_name,identity_arguments)
);
REVOKE ALL ON ALL TABLES IN SCHEMA mscqr_rls_install FROM PUBLIC;
INSERT INTO mscqr_rls_install.state(target_environment,deployment_id,green_database,source_contract_sha256,package_role_marker,administrator_role,phase)
VALUES (${lit(targetEnvironment)},${lit(deploymentId)},current_database(),${lit(sourceContractSha256)},${lit(roleMarker)},current_user,'roles-created');
DO $$ BEGIN
  EXECUTE format('REVOKE CONNECT,TEMPORARY ON DATABASE %I FROM PUBLIC',current_database());
${loginRoleNames.map((role) => `  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),${lit(role)});`).join("\n")}
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO %I',current_database(),${lit(roleNames.migration)});
END $$;
GRANT USAGE,CREATE ON SCHEMA public TO ${q(roleNames.migration)};
GRANT USAGE ON SCHEMA mscqr_rls_install TO ${q(roleNames.migration)};
GRANT SELECT ON TABLE mscqr_rls_install.state TO ${q(roleNames.migration)};
${setRole(roleNames.migration)}
${migrationDefaultPrivilegeHardeningSql}
${resetRole}
`;

const installStatePredicate = (phase) => `singleton
    AND target_environment=${lit(targetEnvironment)}
    AND deployment_id=${lit(deploymentId)}
    AND green_database=current_database()
    AND source_contract_sha256=${lit(sourceContractSha256)}
    AND package_role_marker=${lit(roleMarker)}
    AND administrator_role=${lit(administrativeExecutorRole)}
    AND phase=${lit(phase)}
    AND NOT traffic_enabled`;
const exactManagedRoleStateSql = `
  IF (SELECT count(*) FROM pg_roles WHERE rolname IN (${managedRoleList}))<>${roleSpecs.length}
     OR EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ${roleValuesSql}) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>${lit(roleMarker)})
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;`;
const exactManagedMembershipStateSql = `
  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN (${managedRoleList}))<>${roleSpecs.length * 2}
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN (${managedRoleList}) AND (member.rolname<>${lit(administrativeExecutorRole)} OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN (${managedRoleList}) AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname=${lit(administrativeExecutorRole)} AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname=${lit(administrativeExecutorRole)} AND grantor.rolname=${lit(administrativeExecutorRole)} AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN (${managedRoleList}))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;`;
const requirePackagePhaseSql = (phase, label, { administrator = true } = {}) => `
  ${administrator ? `IF current_user<>${lit(administrativeExecutorRole)} THEN RAISE EXCEPTION '${label} requires the reviewed brokered administrator'; END IF;` : ""}
  IF current_database() !~ ${lit(candidateDatabasePattern)} THEN RAISE EXCEPTION '${label} is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE ${installStatePredicate(phase)}) THEN RAISE EXCEPTION '${label} lacks the exact clean-room package marker'; END IF;
${exactManagedRoleStateSql}
${exactManagedMembershipStateSql}`;

const migrationPreflightSql = `\\set ON_ERROR_STOP on
SELECT current_database() AS green_database, current_user AS migration_executor;
DO $$ BEGIN
  IF current_user<>${lit(roleNames.migration)} THEN RAISE EXCEPTION 'migration package requires exact identity ${roleNames.migration}'; END IF;
${requirePackagePhaseSql("roles-created", "migration package", { administrator: false })}
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname=current_user) THEN RAISE EXCEPTION 'migration identity may not inherit or SET another role'; END IF;
  IF NOT has_schema_privilege(current_user,'public','USAGE') OR NOT has_schema_privilege(current_user,'public','CREATE') THEN RAISE EXCEPTION 'migration identity lacks initial clean-room schema authority'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public')
     OR to_regclass('public._prisma_migrations') IS NOT NULL
  THEN RAISE EXCEPTION 'migration package refuses a database that is not zero-migration clean'; END IF;
END $$;
`;

const postMigrationInventorySql = `
  IF EXISTS (
    (SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') EXCEPT SELECT table_name FROM (VALUES ${expectedMigrationTableValues}) expected(table_name))
    UNION ALL
    (SELECT table_name FROM (VALUES ${expectedMigrationTableValues}) expected(table_name) EXCEPT SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p'))
  ) THEN RAISE EXCEPTION 'post-migration table inventory differs from the reviewed zero-based Prisma schema'; END IF;
  IF EXISTS (
    (SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e' EXCEPT SELECT type_name FROM (VALUES ${expectedEnumValues}) expected(type_name))
    UNION ALL
    (SELECT type_name FROM (VALUES ${expectedEnumValues}) expected(type_name) EXCEPT SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e')
  ) THEN RAISE EXCEPTION 'post-migration enum inventory differs from the reviewed Prisma schema'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('S','v','m','f'))
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
  THEN RAISE EXCEPTION 'post-migration inventory contains an unreviewed public object class'; END IF;`;
const postMigrationBlankSecuritySql = `
  IF EXISTS (SELECT 1 FROM pg_policies) OR EXISTS (SELECT 1 FROM pg_publication) OR EXISTS (SELECT 1 FROM pg_subscription) THEN RAISE EXCEPTION 'post-migration inventory contains unreviewed security or replication state'; END IF;`;
const restrictedMigrationOwnershipSql = `
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p') AND r.rolname<>${lit(roleNames.migration)})
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_roles r ON r.oid=t.typowner WHERE n.nspname='public' AND t.typtype='e' AND r.rolname<>${lit(roleNames.migration)})
  THEN RAISE EXCEPTION 'restricted migration identity does not own every zero-based Prisma object'; END IF;`;

const ownerDefaultPrivilegeHardeningSql = [
  { role: roleNames.owner, schemas: ["public", "app_rls"] },
  { role: roleNames.authOwner, schemas: ["app_auth", "app_public"] },
].map(({ role, schemas }) => [
  setRole(role),
  ...["TABLES", "SEQUENCES", "ROUTINES", "TYPES", "SCHEMAS", "LARGE OBJECTS"].map((objectClass) => `ALTER DEFAULT PRIVILEGES FOR ROLE ${q(role)} REVOKE ALL ON ${objectClass} FROM PUBLIC;`),
  ...schemas.flatMap((schema) => ["TABLES", "SEQUENCES", "ROUTINES", "TYPES"].map((objectClass) => `ALTER DEFAULT PRIVILEGES FOR ROLE ${q(role)} IN SCHEMA ${q(schema)} REVOKE ALL ON ${objectClass} FROM PUBLIC;`)),
  resetRole,
].join("\n")).join("\n");
const roleOwnershipSql = `\\set ON_ERROR_STOP on
DO $$ BEGIN
${requirePackagePhaseSql("roles-created", "ownership package")}
${postMigrationInventorySql}
${postMigrationBlankSecuritySql}
${restrictedMigrationOwnershipSql}
END $$;
GRANT USAGE, CREATE ON SCHEMA public TO ${q(roleNames.owner)};
GRANT ${q(roleNames.owner)} TO ${q(roleNames.migration)} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
${setRole(roleNames.migration)}
${tables.map((table) => `ALTER TABLE public.${q(table.physicalTable)} OWNER TO ${q(roleNames.owner)};`).join("\n")}
${prismaEnumNames.map((type) => `ALTER TYPE public.${q(type)} OWNER TO ${q(roleNames.owner)};`).join("\n")}
${resetRole}
REVOKE ${q(roleNames.owner)} FROM ${q(roleNames.migration)};
ALTER SCHEMA public OWNER TO ${q(roleNames.owner)};
${setRole(roleNames.owner)}
${tables.map((table) => `REVOKE ALL ON TABLE public.${q(table.physicalTable)} FROM PUBLIC;`).join("\n")}
${prismaEnumNames.map((type) => `REVOKE ALL ON TYPE public.${q(type)} FROM PUBLIC;`).join("\n")}
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM ${q(roleNames.migration)};
GRANT USAGE ON SCHEMA public TO ${q(roleNames.migration)};
GRANT USAGE ON SCHEMA public TO ${q(roleNames.authOwner)};
${resetRole}
CREATE SCHEMA app_rls AUTHORIZATION ${q(roleNames.owner)};
CREATE SCHEMA app_auth AUTHORIZATION ${q(roleNames.authOwner)};
CREATE SCHEMA app_public AUTHORIZATION ${q(roleNames.authOwner)};
REVOKE SELECT ON TABLE mscqr_rls_install.state FROM ${q(roleNames.migration)};
REVOKE USAGE ON SCHEMA mscqr_rls_install FROM ${q(roleNames.migration)};
${ownerDefaultPrivilegeHardeningSql}
UPDATE mscqr_rls_install.state SET phase='ownership-installed' WHERE singleton;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE u.rolname IN (${managedRoleList})) THEN RAISE EXCEPTION 'ownership package left a managed identity as a role member'; END IF;
END $$;
`;

const columnGrantSql = grants.map((grant) => grant.command === "DELETE"
  ? `GRANT DELETE ON TABLE public.${q(grant.table)} TO ${q(roleNames.app)};`
  : `GRANT ${grant.command} (${grant.columns.map(q).join(", ")}) ON TABLE public.${q(grant.table)} TO ${q(roleNames.app)};`).join("\n");
const appTypeGrantSql = appTypeGrantNames.map((type) => `GRANT USAGE ON TYPE public.${q(type)} TO ${q(roleNames.app)};`).join("\n");
const runtimeGrantsSql = `\\set ON_ERROR_STOP on
DO $$ BEGIN
${requirePackagePhaseSql("context-helpers-installed", "runtime grants")}
END $$;
${setRole(roleNames.owner)}
GRANT USAGE ON SCHEMA public,app_rls TO ${q(roleNames.app)};
GRANT USAGE ON SCHEMA public,app_rls TO ${q(roleNames.read)};
GRANT USAGE ON SCHEMA public,app_rls TO ${q(roleNames.worker)},${q(roleNames.scheduled)};
GRANT USAGE ON SCHEMA public,app_rls TO ${q(roleNames.operator)};
${columnGrantSql}
${appTypeGrantSql}
${b01OwnerGrantSql}
${preAuthOwnerGrantSql}
${authenticationClosureOwnerGrantSql}
${c03OwnerGrantSql}
${administrationOwnerGrantSql}
${qrSystemOwnerGrantSql}
${printingLifecycleOwnerGrantSql}
${publicVerificationOwnerGrantSql}
${scheduledOwnerGrantSql}
${outboxOwnerGrantSql}
${b03AuthenticatedOwnerGrantSql}
${operationalReadOwnerGrantSql}
GRANT USAGE ON SCHEMA public TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
GRANT USAGE ON SCHEMA app_auth TO ${q(roleNames.preauth)};
GRANT USAGE ON SCHEMA app_public TO ${q(roleNames.preauth)};
${resetRole}
${setRole(roleNames.owner)}
GRANT USAGE ON SCHEMA app_rls TO ${q(roleNames.preauth)};
${resetRole}
${setRole(roleNames.authOwner)}
${b01FunctionSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${resetRole}
UPDATE mscqr_rls_install.state SET phase='runtime-grants-installed' WHERE singleton;
`;

const dashboardSnapshotFunctionsSql = `
CREATE FUNCTION app_rls.dashboard_scope_fingerprint(requested_licensee_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  selector text := NULLIF(btrim(requested_licensee_id),'');
  actor_licensee_id text;
  actor_organization_id text;
  membership_count bigint;
  primary_count bigint;
  membership_fingerprint text;
BEGIN
  IF NOT app_rls.attributed_request()
     OR app_rls.current_purpose()<>'dashboard-snapshot-read'
     OR app_rls.current_user_id() IS NULL
     OR app_rls.current_role() IS NULL
     OR app_rls.current_request_id() !~ '^[A-Za-z0-9._:-]{1,128}$'
  THEN RAISE EXCEPTION 'dashboard access denied: missing verified request context'; END IF;
  IF selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'dashboard access denied: invalid licensee selector'; END IF;
  IF ((${platformRoles} OR ${manufacturerRoles}) AND app_rls.current_assurance() NOT IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR (${tenantAdminRoles} AND app_rls.current_assurance() NOT IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR NOT (${platformRoles} OR ${tenantAdminRoles} OR ${manufacturerRoles})
  THEN RAISE EXCEPTION 'dashboard access denied: actor role or assurance'; END IF;

  SELECT u.${q("licenseeId")},u.${q("orgId")} INTO actor_licensee_id,actor_organization_id
  FROM public.${q("User")} u
  WHERE u.${q("id")}=app_rls.current_user_id()
    AND u.${q("role")}::text=app_rls.current_role()
    AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE'
    AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied: actor row'; END IF;

  IF ${tenantAdminRoles} THEN
    IF app_rls.current_licensee_id() IS NULL OR app_rls.current_organization_id() IS NULL
       OR app_rls.current_manufacturer_id() IS NOT NULL
    THEN RAISE EXCEPTION 'dashboard access denied: tenant derived context'; END IF;
    IF actor_licensee_id IS DISTINCT FROM app_rls.current_licensee_id()
       OR actor_organization_id IS DISTINCT FROM app_rls.current_organization_id()
    THEN RAISE EXCEPTION 'dashboard access denied: tenant actor relationship'; END IF;
    IF selector IS NOT NULL AND selector IS DISTINCT FROM app_rls.current_licensee_id()
    THEN RAISE EXCEPTION 'dashboard access denied: tenant selector'; END IF;
    IF NOT EXISTS (
         SELECT 1 FROM public.${q("Licensee")} l
         WHERE l.${q("id")}=app_rls.current_licensee_id() AND l.${q("orgId")}=app_rls.current_organization_id()
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL
       )
    THEN RAISE EXCEPTION 'dashboard access denied: tenant live licensee'; END IF;
    IF NOT EXISTS (
         SELECT 1 FROM public.${q("Organization")} o
         WHERE o.${q("id")}=app_rls.current_organization_id() AND o.${q("isActive")}=TRUE
       )
    THEN RAISE EXCEPTION 'dashboard access denied: tenant live organization'; END IF;
    RETURN md5(concat_ws('|','tenant',app_rls.current_user_id(),app_rls.current_role(),app_rls.current_licensee_id(),app_rls.current_organization_id()));
  END IF;

  IF ${manufacturerRoles} THEN
    IF app_rls.current_manufacturer_id() IS DISTINCT FROM app_rls.current_user_id()
       OR app_rls.current_organization_id() IS NOT NULL
       OR app_rls.current_licensee_id() IS DISTINCT FROM selector
    THEN RAISE EXCEPTION 'dashboard access denied: manufacturer scope'; END IF;
    SELECT count(*),count(*) FILTER (WHERE ml.${q("isPrimary")}),string_agg(ml.${q("licenseeId")}||':'||ml.${q("isPrimary")}::text||':'||extract(epoch FROM ml.${q("updatedAt")})::text,',' ORDER BY ml.${q("licenseeId")})
      INTO membership_count,primary_count,membership_fingerprint
    FROM public.${q("ManufacturerLicenseeLink")} ml
    JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
    JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE ml.${q("manufacturerId")}=app_rls.current_user_id()
      AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
    IF membership_count NOT BETWEEN 1 AND 100 OR primary_count>1
       OR (actor_licensee_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=actor_licensee_id
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
       OR (actor_organization_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND l.${q("orgId")}=actor_organization_id
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
       OR (selector IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=selector
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
    THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
    RETURN md5(concat_ws('|','manufacturer',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'all'),membership_fingerprint));
  END IF;

  IF app_rls.current_manufacturer_id() IS NOT NULL OR app_rls.current_organization_id() IS NOT NULL
     OR app_rls.current_licensee_id() IS DISTINCT FROM selector
     OR (selector IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
       WHERE l.${q("id")}=selector AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
     ))
  THEN RAISE EXCEPTION 'dashboard access denied: platform scope'; END IF;
  RETURN md5(concat_ws('|','platform',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'global')));
END
$function$;

CREATE FUNCTION app_rls.authorize_dashboard_snapshot(audit_id text,requested_licensee_id text,route_surface text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  fingerprint text;
  audit_organization_id text := app_rls.current_organization_id();
BEGIN
  IF audit_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR route_surface NOT IN ('GET /api/dashboard/stats','GET /api/events/dashboard')
  THEN RAISE EXCEPTION 'dashboard access denied: request attribution'; END IF;
  fingerprint := app_rls.dashboard_scope_fingerprint(requested_licensee_id);
  IF app_rls.current_licensee_id() IS NOT NULL AND audit_organization_id IS NULL THEN
    SELECT l.${q("orgId")} INTO audit_organization_id
    FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE l.${q("id")}=app_rls.current_licensee_id()
      AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
    IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied: audit organization'; END IF;
  END IF;
  INSERT INTO public.${q("AuditLog")}
    (${q("id")},${q("userId")},${q("orgId")},${q("licenseeId")},${q("action")},${q("entityType")},${q("entityId")},${q("details")})
  VALUES (
    lower(audit_id),app_rls.current_user_id(),audit_organization_id,app_rls.current_licensee_id(),
    'DASHBOARD_SNAPSHOT_READ','DashboardSnapshot',coalesce(app_rls.current_licensee_id(),app_rls.current_user_id()),
    jsonb_build_object(
      'actorId',app_rls.current_user_id(),'role',app_rls.current_role(),'assurance',app_rls.current_assurance(),
      'requestId',app_rls.current_request_id(),'purposeCode',app_rls.current_purpose(),'route',route_surface,
      'scopeFingerprint',fingerprint,'outcome','SUCCESS','workflowIds',jsonb_build_array(
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot',
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate'
      )
    )
  ) ON CONFLICT (${q("id")}) DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM public.${q("AuditLog")} a
    WHERE a.${q("id")}=lower(audit_id) AND a.${q("userId")}=app_rls.current_user_id()
      AND a.${q("orgId")} IS NOT DISTINCT FROM audit_organization_id
      AND a.${q("licenseeId")} IS NOT DISTINCT FROM app_rls.current_licensee_id()
      AND a.${q("action")}='DASHBOARD_SNAPSHOT_READ' AND a.${q("entityType")}='DashboardSnapshot'
      AND a.${q("entityId")}=coalesce(app_rls.current_licensee_id(),app_rls.current_user_id())
      AND a.${q("details")}->>'actorId'=app_rls.current_user_id()
      AND a.${q("details")}->>'role'=app_rls.current_role()
      AND a.${q("details")}->>'assurance'=app_rls.current_assurance()
      AND a.${q("details")}->>'requestId'=app_rls.current_request_id()
      AND a.${q("details")}->>'purposeCode'='dashboard-snapshot-read'
      AND a.${q("details")}->>'route'=route_surface
      AND a.${q("details")}->>'scopeFingerprint'=fingerprint
      AND a.${q("details")}->>'outcome'='SUCCESS'
      AND a.${q("details")}->'workflowIds'=jsonb_build_array(
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot',
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate'
      )
  ) THEN RAISE EXCEPTION 'dashboard access denied: audit persistence'; END IF;
  RETURN fingerprint;
END
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_scope(audit_id text,requested_licensee_id text,route_surface text)
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_dashboard_snapshot(audit_id,requested_licensee_id,route_surface)
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_data(audit_id text,requested_licensee_id text,route_surface text,expected_scope_fingerprint text)
RETURNS TABLE(
  total_qr_codes bigint,active_licensees bigint,manufacturers bigint,total_batches bigint,
  dormant bigint,active bigint,activated bigint,allocated bigint,printed bigint,redeemed bigint,blocked bigint,scanned bigint,
  rollup_authoritative boolean
) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  fingerprint text;
  rollup_total bigint;
  rollup_dormant bigint;
  rollup_active bigint;
  rollup_activated bigint;
  rollup_allocated bigint;
  rollup_printed bigint;
  rollup_redeemed bigint;
  rollup_blocked bigint;
  rollup_scanned bigint;
BEGIN
  fingerprint := app_rls.authorize_dashboard_snapshot(audit_id,requested_licensee_id,route_surface);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'dashboard access denied: scope fingerprint'; END IF;

  IF ${manufacturerRoles} THEN
    SELECT count(*) INTO active_licensees
    FROM public.${q("Licensee")} l
    JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE EXISTS (
      SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
      WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=l.${q("id")}
    ) AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
  ELSIF ${platformRoles} AND app_rls.current_licensee_id() IS NULL THEN
    SELECT count(*) INTO active_licensees
    FROM public.${q("Licensee")} l
    WHERE l.${q("isActive")}=TRUE;
  ELSE
    SELECT count(*) INTO active_licensees
    FROM public.${q("Licensee")} l
    JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE l.${q("id")}=app_rls.current_licensee_id()
      AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
  END IF;

  SELECT count(*) INTO manufacturers
  FROM public.${q("User")} u
  WHERE u.${q("role")} IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND u.${q("isActive")}=TRUE
    AND (
      (${manufacturerRoles} AND u.${q("id")}=app_rls.current_user_id())
      OR (${platformRoles} AND app_rls.current_licensee_id() IS NULL)
      OR ((${tenantAdminRoles} OR ${platformRoles}) AND app_rls.current_licensee_id() IS NOT NULL AND (
        u.${q("licenseeId")}=app_rls.current_licensee_id()
        OR EXISTS (SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml WHERE ml.${q("manufacturerId")}=u.${q("id")} AND ml.${q("licenseeId")}=app_rls.current_licensee_id())
      ))
    );

  SELECT count(*) INTO total_batches
  FROM public.${q("Batch")} b
  WHERE (
    (${manufacturerRoles} AND b.${q("manufacturerId")}=app_rls.current_user_id() AND EXISTS (
      SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
      JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
      JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
      WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=b.${q("licenseeId")}
        AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
        AND (app_rls.current_licensee_id() IS NULL OR ml.${q("licenseeId")}=app_rls.current_licensee_id())
    ))
    OR (${tenantAdminRoles} AND b.${q("licenseeId")}=app_rls.current_licensee_id())
    OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR b.${q("licenseeId")}=app_rls.current_licensee_id()))
  );

  SELECT coalesce(sum(r.${q("totalCodes")}),0),coalesce(sum(r.${q("dormant")}),0),coalesce(sum(r.${q("active")}),0),
         coalesce(sum(r.${q("activated")}),0),coalesce(sum(r.${q("allocated")}),0),coalesce(sum(r.${q("printed")}),0),
         coalesce(sum(r.${q("redeemed")}),0),coalesce(sum(r.${q("blocked")}),0),coalesce(sum(r.${q("scanned")}),0)
    INTO rollup_total,rollup_dormant,rollup_active,rollup_activated,rollup_allocated,rollup_printed,rollup_redeemed,rollup_blocked,rollup_scanned
  FROM public.${q("InventoryStatusRollup")} r
  WHERE (
    (${manufacturerRoles} AND r.${q("manufacturerId")}=app_rls.current_user_id() AND EXISTS (
      SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
      JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
      JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
      WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=r.${q("licenseeId")}
        AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
        AND (app_rls.current_licensee_id() IS NULL OR ml.${q("licenseeId")}=app_rls.current_licensee_id())
    ))
    OR (${tenantAdminRoles} AND r.${q("licenseeId")}=app_rls.current_licensee_id())
    OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR r.${q("licenseeId")}=app_rls.current_licensee_id()))
  );

  IF rollup_total>0 OR rollup_dormant>0 OR rollup_active>0 OR rollup_activated>0 OR rollup_allocated>0
     OR rollup_printed>0 OR rollup_redeemed>0 OR rollup_blocked>0 OR rollup_scanned>0
  THEN
    rollup_authoritative:=TRUE;
    total_qr_codes:=rollup_total; dormant:=rollup_dormant; active:=rollup_active; activated:=rollup_activated;
    allocated:=rollup_allocated; printed:=rollup_printed; redeemed:=rollup_redeemed; blocked:=rollup_blocked; scanned:=rollup_scanned;
  ELSE
    rollup_authoritative:=FALSE;
    SELECT count(*),count(*) FILTER (WHERE qcode.${q("status")}='DORMANT'),count(*) FILTER (WHERE qcode.${q("status")}='ACTIVE'),
           count(*) FILTER (WHERE qcode.${q("status")}='ACTIVATED'),count(*) FILTER (WHERE qcode.${q("status")}='ALLOCATED'),
           count(*) FILTER (WHERE qcode.${q("status")}='PRINTED'),count(*) FILTER (WHERE qcode.${q("status")}='REDEEMED'),
           count(*) FILTER (WHERE qcode.${q("status")}='BLOCKED'),count(*) FILTER (WHERE qcode.${q("status")}='SCANNED')
      INTO total_qr_codes,dormant,active,activated,allocated,printed,redeemed,blocked,scanned
    FROM public.${q("QRCode")} qcode
    WHERE (
      (${manufacturerRoles} AND EXISTS (
        SELECT 1 FROM public.${q("Batch")} b WHERE b.${q("id")}=qcode.${q("batchId")} AND b.${q("manufacturerId")}=app_rls.current_user_id()
      ) AND EXISTS (
        SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
        JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
        JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
        WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=qcode.${q("licenseeId")}
          AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
          AND (app_rls.current_licensee_id() IS NULL OR ml.${q("licenseeId")}=app_rls.current_licensee_id())
      ))
      OR (${tenantAdminRoles} AND qcode.${q("licenseeId")}=app_rls.current_licensee_id())
      OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR qcode.${q("licenseeId")}=app_rls.current_licensee_id()))
    );
  END IF;
  RETURN NEXT;
END
$function$;`;

const batchOperationalAssurance = `((${tenantAdminRoles} AND app_rls.current_assurance() IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass')) OR ((${manufacturerRoles} OR ${platformRoles}) AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass')))`;
const operationalSessionBinding = `(current_user=${lit(roleNames.authOwner)} AND app_rls.operational_read_session_valid())`;
const batchOperationalBase = `(${operationalSessionBinding} AND app_rls.attributed_request() AND app_rls.current_purpose()='batch-operational-read' AND app_rls.current_request_id() ~ '^[A-Za-z0-9._:-]{1,128}$' AND ${batchOperationalAssurance})`;
const batchOperationalLinkedLicensee = (licenseeExpression) => `EXISTS (
  SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} scope_ml
  JOIN public.${q("Licensee")} scope_l ON scope_l.${q("id")}=scope_ml.${q("licenseeId")}
  JOIN public.${q("Organization")} scope_o ON scope_o.${q("id")}=scope_l.${q("orgId")}
  WHERE scope_ml.${q("manufacturerId")}=app_rls.current_user_id()
    AND scope_ml.${q("licenseeId")}=${licenseeExpression}
    AND scope_l.${q("isActive")}=TRUE AND scope_l.${q("suspendedAt")} IS NULL AND scope_o.${q("isActive")}=TRUE
    AND (app_rls.current_licensee_id() IS NULL OR scope_ml.${q("licenseeId")}=app_rls.current_licensee_id())
)`;
const batchOperationalListBatchScope = (alias) => `(((${tenantAdminRoles} OR ${platformRoles}) AND ${alias}.${q("licenseeId")}=app_rls.current_licensee_id()) OR (${manufacturerRoles} AND ${alias}.${q("manufacturerId")}=app_rls.current_user_id() AND ${batchOperationalLinkedLicensee(`${alias}.${q("licenseeId")}`)}))`;
const batchOperationalWorkflowIdsSql = BATCH_OPERATIONAL_READ_WORKFLOW_IDS.map(lit).join(",");

const batchOperationalAuthorizationFunctionsSql = `
CREATE FUNCTION app_rls.batch_scope_fingerprint(requested_licensee_id text,route_surface text,focus_batch_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  selector text := NULLIF(btrim(requested_licensee_id),'');
  focus_id text := NULLIF(btrim(focus_batch_id),'');
  actor_licensee_id text;
  actor_organization_id text;
  membership_count bigint;
  primary_count bigint;
  membership_fingerprint text;
BEGIN
  IF NOT ${batchOperationalBase}
     OR app_rls.current_user_id() IS NULL OR app_rls.current_role() IS NULL
     OR route_surface IS NULL
     OR (requested_licensee_id IS NOT NULL AND btrim(requested_licensee_id)='')
     OR (focus_batch_id IS NOT NULL AND btrim(focus_batch_id)='')
     OR route_surface NOT IN ('GET /api/qr/batches','GET /api/qr/batches/:id/allocation-map')
     OR (route_surface='GET /api/qr/batches' AND focus_id IS NOT NULL)
     OR (route_surface='GET /api/qr/batches/:id/allocation-map' AND focus_id IS NULL)
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF (selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
     OR (focus_id IS NOT NULL AND focus_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;

  SELECT u.${q("licenseeId")},u.${q("orgId")} INTO actor_licensee_id,actor_organization_id
  FROM public.${q("User")} u
  WHERE u.${q("id")}=app_rls.current_user_id() AND u.${q("role")}::text=app_rls.current_role()
    AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE'
    AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;

  IF ${tenantAdminRoles} THEN
    IF app_rls.current_licensee_id() IS NULL OR app_rls.current_organization_id() IS NULL
       OR app_rls.current_manufacturer_id() IS NOT NULL
       OR actor_licensee_id IS DISTINCT FROM app_rls.current_licensee_id()
       OR actor_organization_id IS DISTINCT FROM app_rls.current_organization_id()
       OR (selector IS NOT NULL AND selector IS DISTINCT FROM app_rls.current_licensee_id())
       OR NOT EXISTS (
         SELECT 1 FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE l.${q("id")}=app_rls.current_licensee_id() AND l.${q("orgId")}=app_rls.current_organization_id()
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       )
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    RETURN md5(concat_ws('|','tenant',app_rls.current_user_id(),app_rls.current_role(),app_rls.current_licensee_id(),app_rls.current_organization_id(),route_surface,coalesce(focus_id,'list')));
  END IF;

  IF ${manufacturerRoles} THEN
    IF app_rls.current_manufacturer_id() IS DISTINCT FROM app_rls.current_user_id()
       OR app_rls.current_organization_id() IS NOT NULL
       OR app_rls.current_licensee_id() IS DISTINCT FROM selector
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    SELECT count(*),count(*) FILTER (WHERE ml.${q("isPrimary")}),string_agg(ml.${q("licenseeId")}||':'||ml.${q("isPrimary")}::text||':'||extract(epoch FROM ml.${q("updatedAt")})::text,',' ORDER BY ml.${q("licenseeId")})
      INTO membership_count,primary_count,membership_fingerprint
    FROM public.${q("ManufacturerLicenseeLink")} ml
    JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
    JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE ml.${q("manufacturerId")}=app_rls.current_user_id()
      AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
    IF membership_count NOT BETWEEN 1 AND 100 OR primary_count>1
       OR (actor_licensee_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=actor_licensee_id
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
       OR (actor_organization_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND l.${q("orgId")}=actor_organization_id
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
       OR (selector IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml
         JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")}
         JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
         WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=selector
           AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
       ))
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    RETURN md5(concat_ws('|','manufacturer',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'all'),membership_fingerprint,route_surface,coalesce(focus_id,'list')));
  END IF;

  IF NOT ${platformRoles} OR selector IS NULL OR app_rls.current_licensee_id() IS DISTINCT FROM selector
     OR app_rls.current_manufacturer_id() IS NOT NULL OR app_rls.current_organization_id() IS NOT NULL
     OR NOT EXISTS (
       SELECT 1 FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
       WHERE l.${q("id")}=selector AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE
     )
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN md5(concat_ws('|','platform',app_rls.current_user_id(),app_rls.current_role(),selector,route_surface,coalesce(focus_id,'list')));
END
$function$;

CREATE FUNCTION app_rls.batch_operational_batch_allowed(candidate_batch_id text,focus_batch_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE focus_id text := NULLIF(btrim(focus_batch_id),''); focus_licensee_id text; source_batch_id text;
BEGIN
  IF candidate_batch_id IS NULL OR candidate_batch_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RETURN FALSE; END IF;
  IF focus_id IS NULL THEN
    RETURN EXISTS (SELECT 1 FROM public.${q("Batch")} b WHERE b.${q("id")}=candidate_batch_id AND (
      ((${tenantAdminRoles} OR ${platformRoles}) AND b.${q("licenseeId")}=app_rls.current_licensee_id())
      OR (${manufacturerRoles} AND b.${q("manufacturerId")}=app_rls.current_user_id() AND ${batchOperationalLinkedLicensee(`b.${q("licenseeId")}`)})
    ));
  END IF;
  SELECT f.${q("licenseeId")},coalesce(f.${q("rootBatchId")},f.${q("parentBatchId")},f.${q("id")}) INTO focus_licensee_id,source_batch_id
  FROM public.${q("Batch")} f WHERE f.${q("id")}=focus_id AND (
    ((${tenantAdminRoles} OR ${platformRoles}) AND f.${q("licenseeId")}=app_rls.current_licensee_id())
    OR (${manufacturerRoles} AND f.${q("manufacturerId")}=app_rls.current_user_id() AND ${batchOperationalLinkedLicensee(`f.${q("licenseeId")}`)})
  );
  IF NOT FOUND THEN RETURN FALSE; END IF;
  RETURN EXISTS (SELECT 1 FROM public.${q("Batch")} b WHERE b.${q("id")}=candidate_batch_id AND b.${q("licenseeId")}=focus_licensee_id
    AND (b.${q("id")}=source_batch_id OR b.${q("parentBatchId")}=source_batch_id OR b.${q("rootBatchId")}=source_batch_id));
END
$function$;

CREATE FUNCTION app_rls.authorize_batch_operational_read(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; audit_organization_id text := app_rls.current_organization_id(); focus_id text := NULLIF(btrim(focus_batch_id),'');
BEGIN
  IF audit_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  fingerprint := app_rls.batch_scope_fingerprint(requested_licensee_id,route_surface,focus_id);
  IF focus_id IS NOT NULL AND NOT app_rls.batch_operational_batch_allowed(focus_id,focus_id) THEN
    RAISE EXCEPTION 'batch operational access denied';
  END IF;
  IF app_rls.current_licensee_id() IS NOT NULL AND audit_organization_id IS NULL THEN
    SELECT l.${q("orgId")} INTO audit_organization_id FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")}
    WHERE l.${q("id")}=app_rls.current_licensee_id() AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  INSERT INTO public.${q("AuditLog")} (${q("id")},${q("userId")},${q("orgId")},${q("licenseeId")},${q("action")},${q("entityType")},${q("entityId")},${q("details")})
  VALUES (lower(audit_id),app_rls.current_user_id(),audit_organization_id,app_rls.current_licensee_id(),'BATCH_OPERATIONAL_READ','BatchOperationalRead',coalesce(focus_id,app_rls.current_licensee_id(),app_rls.current_user_id()),
    jsonb_build_object('actorId',app_rls.current_user_id(),'role',app_rls.current_role(),'assurance',app_rls.current_assurance(),'requestId',app_rls.current_request_id(),'purposeCode',app_rls.current_purpose(),'route',route_surface,'focusBatchId',focus_id,'scopeFingerprint',fingerprint,'outcome','SUCCESS','workflowIds',jsonb_build_array(${batchOperationalWorkflowIdsSql})))
  ON CONFLICT (${q("id")}) DO NOTHING;
  IF NOT EXISTS (SELECT 1 FROM public.${q("AuditLog")} a WHERE a.${q("id")}=lower(audit_id) AND a.${q("userId")}=app_rls.current_user_id()
    AND a.${q("orgId")} IS NOT DISTINCT FROM audit_organization_id AND a.${q("licenseeId")} IS NOT DISTINCT FROM app_rls.current_licensee_id()
    AND a.${q("action")}='BATCH_OPERATIONAL_READ' AND a.${q("entityType")}='BatchOperationalRead'
    AND a.${q("entityId")}=coalesce(focus_id,app_rls.current_licensee_id(),app_rls.current_user_id())
    AND a.${q("details")}->>'requestId'=app_rls.current_request_id() AND a.${q("details")}->>'purposeCode'='batch-operational-read'
    AND a.${q("details")}->>'route'=route_surface AND a.${q("details")}->>'focusBatchId' IS NOT DISTINCT FROM focus_id
    AND a.${q("details")}->>'scopeFingerprint'=fingerprint AND a.${q("details")}->>'outcome'='SUCCESS'
    AND a.${q("details")}->'workflowIds'=jsonb_build_array(${batchOperationalWorkflowIdsSql}))
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN fingerprint;
END
$function$;

CREATE FUNCTION app_rls.batch_operational_scope(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text)
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id)
$function$;`;

const batchOperationalRowFunctionsSql = `
CREATE FUNCTION app_rls.batch_operational_rows(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,page_limit integer,page_offset integer)
RETURNS TABLE(row_data jsonb) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; focus_licensee_id text; source_batch_id text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR page_limit IS NULL OR page_offset IS NULL
     OR page_limit NOT BETWEEN 0 AND 500 OR page_offset<0
     OR (focus_batch_id IS NULL AND page_limit=0)
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF focus_batch_id IS NOT NULL THEN
    SELECT f.${q("licenseeId")},coalesce(f.${q("rootBatchId")},f.${q("parentBatchId")},f.${q("id")})
      INTO focus_licensee_id,source_batch_id
    FROM public.${q("Batch")} f WHERE f.${q("id")}=focus_batch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  RETURN QUERY
  SELECT to_jsonb(b) || jsonb_build_object(
    'licensee',jsonb_build_object('id',l.${q("id")},'name',l.${q("name")},'prefix',l.${q("prefix")}),
    'manufacturer',CASE WHEN m.${q("id")} IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',m.${q("id")},'name',m.${q("name")},'email',m.${q("email")}) END,
    '_count',jsonb_build_object('qrCodes',(SELECT count(*) FROM public.${q("QRCode")} qcode WHERE qcode.${q("batchId")}=b.${q("id")}))
  ) || CASE WHEN focus_batch_id IS NULL THEN jsonb_build_object(
    'parentBatch',CASE WHEN parent_b.${q("id")} IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',parent_b.${q("id")},'name',parent_b.${q("name")}) END,
    'rootBatch',CASE WHEN root_b.${q("id")} IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',root_b.${q("id")},'name',root_b.${q("name")}) END
  ) ELSE '{}'::jsonb END
  FROM public.${q("Batch")} b
  JOIN public.${q("Licensee")} l ON l.${q("id")}=b.${q("licenseeId")}
  LEFT JOIN public.${q("User")} m ON m.${q("id")}=b.${q("manufacturerId")}
  LEFT JOIN public.${q("Batch")} parent_b ON parent_b.${q("id")}=b.${q("parentBatchId")}
  LEFT JOIN public.${q("Batch")} root_b ON root_b.${q("id")}=b.${q("rootBatchId")}
  WHERE (focus_batch_id IS NULL AND ${batchOperationalListBatchScope("b")})
     OR (focus_batch_id IS NOT NULL AND b.${q("licenseeId")}=focus_licensee_id
       AND (b.${q("id")}=source_batch_id OR b.${q("parentBatchId")}=source_batch_id OR b.${q("rootBatchId")}=source_batch_id))
  ORDER BY CASE WHEN focus_batch_id IS NULL THEN b.${q("updatedAt")} END DESC,
           CASE WHEN focus_batch_id IS NULL THEN b.${q("createdAt")} END DESC,
           CASE WHEN focus_batch_id IS NOT NULL THEN b.${q("createdAt")} END ASC,
           CASE WHEN focus_batch_id IS NOT NULL THEN b.${q("id")} END ASC
  LIMIT CASE WHEN focus_batch_id IS NULL THEN page_limit ELSE 2147483647 END
  OFFSET CASE WHEN focus_batch_id IS NULL THEN page_offset ELSE 0 END;
END
$function$;

CREATE FUNCTION app_rls.batch_operational_total(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text)
RETURNS TABLE(total bigint) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; focus_licensee_id text; source_batch_id text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF focus_batch_id IS NOT NULL THEN
    SELECT f.${q("licenseeId")},coalesce(f.${q("rootBatchId")},f.${q("parentBatchId")},f.${q("id")})
      INTO focus_licensee_id,source_batch_id
    FROM public.${q("Batch")} f WHERE f.${q("id")}=focus_batch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  RETURN QUERY SELECT count(*) FROM public.${q("Batch")} b
  WHERE (focus_batch_id IS NULL AND ${batchOperationalListBatchScope("b")})
     OR (focus_batch_id IS NOT NULL AND b.${q("licenseeId")}=focus_licensee_id
       AND (b.${q("id")}=source_batch_id OR b.${q("parentBatchId")}=source_batch_id OR b.${q("rootBatchId")}=source_batch_id));
END
$function$;`;

const batchOperationalArrayGuardSql = `expected_scope_fingerprint IS DISTINCT FROM fingerprint OR batch_ids IS NULL OR cardinality(batch_ids) NOT BETWEEN 1 AND 500
     OR cardinality(batch_ids)<>(SELECT count(DISTINCT id) FROM unnest(batch_ids) id)
     OR EXISTS (SELECT 1 FROM unnest(batch_ids) id WHERE id IS NULL OR NOT app_rls.batch_operational_batch_allowed(id,focus_batch_id))`;

const batchOperationalSummaryFunctionsSql = `
CREATE FUNCTION app_rls.batch_inventory_rollups(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,dormant integer,active integer,activated integer,allocated integer,printed integer,redeemed integer,blocked integer,scanned integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF ${batchOperationalArrayGuardSql} THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT r.${q("batchId")},r.${q("dormant")},r.${q("active")},r.${q("activated")},r.${q("allocated")},r.${q("printed")},r.${q("redeemed")},r.${q("blocked")},r.${q("scanned")}
  FROM public.${q("InventoryStatusRollup")} r WHERE r.${q("batchId")}=ANY(batch_ids);
END
$function$;

CREATE FUNCTION app_rls.batch_unassigned_ranges(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF ${batchOperationalArrayGuardSql} THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT qcode.${q("batchId")},count(*),coalesce(min(qcode.${q("displayCode")}),min(qcode.${q("code")})),coalesce(max(qcode.${q("displayCode")}),max(qcode.${q("code")}))
  FROM public.${q("QRCode")} qcode WHERE qcode.${q("batchId")}=ANY(batch_ids) AND qcode.${q("status")} IN ('DORMANT','ACTIVE')
  GROUP BY qcode.${q("batchId")};
END
$function$;

CREATE FUNCTION app_rls.batch_status_fallback(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,status text,item_count bigint)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF ${batchOperationalArrayGuardSql} THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT qcode.${q("batchId")},qcode.${q("status")}::text,count(*) FROM public.${q("QRCode")} qcode
  WHERE qcode.${q("batchId")}=ANY(batch_ids) GROUP BY qcode.${q("batchId")},qcode.${q("status")};
END
$function$;

CREATE FUNCTION app_rls.batch_reservable_qr_summaries(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF ${batchOperationalArrayGuardSql} THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY
  SELECT qcode.${q("batchId")},count(*),min(coalesce(qcode.${q("displayCode")},qcode.${q("code")})),max(coalesce(qcode.${q("displayCode")},qcode.${q("code")}))
  FROM public.${q("QRCode")} qcode
  LEFT JOIN public.${q("PrintItem")} pi ON pi.${q("qrCodeId")}=qcode.${q("id")}
  LEFT JOIN public.${q("PrintSession")} ps ON ps.${q("id")}=pi.${q("printSessionId")}
  LEFT JOIN public.${q("PrintJob")} pj ON pj.${q("id")}=ps.${q("printJobId")}
  WHERE qcode.${q("batchId")}=ANY(batch_ids) AND qcode.${q("status")}='ALLOCATED' AND qcode.${q("printJobId")} IS NULL
    AND (pi.${q("id")} IS NULL OR (pi.${q("printConfirmedAt")} IS NULL
      AND (pi.${q("confirmationEvidence")} IS NULL OR pi.${q("confirmationEvidence")}::text IN ('null','{}'))
      AND ((pi.${q("state")}::text IN ('FAILED','FROZEN') AND pi.${q("agentAckedAt")} IS NULL AND pi.${q("dispatchedAt")} IS NULL AND pi.${q("deviceJobRef")} IS NULL
        AND (pi.${q("deadLetterReason")} IN ('operator_abandoned_unconfirmed_run','pre_dispatch_failure','connector_payload_validation_failed_before_dispatch','printer_agent_payload_failed_before_dispatch')
          OR pi.${q("failureReason")} ILIKE '%operator closed unconfirmed failed print run%' OR pi.${q("failureReason")} ILIKE '%operator abandoned unconfirmed print run%'
          OR pi.${q("failureReason")} ILIKE '%before any printer acknowledgement%' OR pi.${q("failureReason")} ILIKE '%pre-dispatch%' OR pi.${q("failureReason")} ILIKE '%pre dispatch%')
        AND ps.${q("status")}::text IN ('CANCELLED','FAILED') AND pj.${q("status")}::text IN ('CANCELLED','FAILED'))
      OR (pi.${q("state")}::text='CANCELLED' AND ps.${q("status")}::text='STOPPED' AND pj.${q("status")}::text IN ('STOPPED','PARTIALLY_COMPLETED')))))
  GROUP BY qcode.${q("batchId")};
END
$function$;`;

const contextHelpersSql = `\\set ON_ERROR_STOP on
DO $$ BEGIN
${requirePackagePhaseSql("ownership-installed", "context helpers")}
END $$;
${setRole(roleNames.owner)}
CREATE FUNCTION app_rls.setting(setting_name text) RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT NULLIF(btrim(current_setting(setting_name,true)),'') $$;
CREATE FUNCTION app_rls.uuid_setting(setting_name text) RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT CASE WHEN app_rls.setting(setting_name) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN lower(app_rls.setting(setting_name)) ELSE NULL END $$;
${[["current_user_id", "app.user_id"], ["current_organization_id", "app.organization_id"], ["current_licensee_id", "app.licensee_id"], ["current_manufacturer_id", "app.manufacturer_id"]].map(([name, setting]) => `CREATE FUNCTION app_rls.${name}() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.uuid_setting(${lit(setting)}) $$;`).join("\n")}
CREATE FUNCTION app_rls.current_role() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.role') $$;
CREATE FUNCTION app_rls.current_assurance() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.auth_assurance') $$;
CREATE FUNCTION app_rls.current_request_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.request_id') $$;
CREATE FUNCTION app_rls.current_purpose() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.purpose') $$;
CREATE FUNCTION app_rls.attributed_request() RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.current_request_id() IS NOT NULL AND app_rls.current_purpose() IS NOT NULL $$;
CREATE FUNCTION app_rls.install_actor_context(user_id text,actor_role text,organization_id text,licensee_id text,manufacturer_id text,assurance text,request_id text,purpose_code text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
  IF current_setting('app.context_installed',true)='1' OR app_rls.uuid_setting('app.user_id') IS NOT NULL THEN RAISE EXCEPTION 'canonical context already installed in this transaction'; END IF;
  IF user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid actor identifier'; END IF;
  IF actor_role !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN RAISE EXCEPTION 'invalid actor role'; END IF;
  IF assurance NOT IN ('password-verified','mfa-bootstrap','mfa-verified','step-up-verified','system-verified','operator-approved','dual-approved-break-glass') THEN RAISE EXCEPTION 'invalid assurance'; END IF;
  IF request_id IS NULL OR btrim(request_id)='' OR purpose_code IS NULL OR btrim(purpose_code)='' THEN RAISE EXCEPTION 'request attribution is required'; END IF;
  IF organization_id<>'' AND organization_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid organization identifier'; END IF;
  IF licensee_id<>'' AND licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid licensee identifier'; END IF;
  IF manufacturer_id<>'' AND manufacturer_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid manufacturer identifier'; END IF;
  PERFORM set_config('app.user_id',lower(user_id),true),set_config('app.role',actor_role,true),set_config('app.organization_id',lower(coalesce(organization_id,'')),true),set_config('app.licensee_id',lower(coalesce(licensee_id,'')),true),set_config('app.manufacturer_id',lower(coalesce(manufacturer_id,'')),true),set_config('app.auth_assurance',assurance,true),set_config('app.request_id',request_id,true),set_config('app.purpose',purpose_code,true),set_config('app.context_installed','1',true);
END $$;
CREATE FUNCTION app_rls.manufacturer_scope_valid(target_manufacturer_id text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $$
  SELECT target_manufacturer_id IS NOT NULL AND target_manufacturer_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND app_rls.current_licensee_id() IS NOT NULL
    AND ((${manufacturerRoles} AND target_manufacturer_id=app_rls.current_user_id() AND app_rls.current_purpose() IN ('audit-log-read','trace-timeline-read')) OR ((${tenantAdminRoles} OR ${platformRoles}) AND app_rls.current_purpose()='tenant-risk-analytics'))
    AND EXISTS (SELECT 1 FROM public.${q("User")} u JOIN public.${q("ManufacturerLicenseeLink")} ml ON ml.${q("manufacturerId")}=u.${q("id")} JOIN public.${q("Licensee")} l ON l.${q("id")}=ml.${q("licenseeId")} JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")} WHERE u.${q("id")}=target_manufacturer_id AND u.${q("role")} IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE' AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL AND ml.${q("licenseeId")}=app_rls.current_licensee_id() AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND (app_rls.current_organization_id() IS NULL OR l.${q("orgId")}=app_rls.current_organization_id()) AND o.${q("isActive")}=TRUE)
$$;
CREATE FUNCTION app_rls.actor_scope_valid() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $$
  SELECT CASE
    WHEN ${manufacturerRoles} THEN
      app_rls.current_manufacturer_id()=app_rls.current_user_id()
      AND EXISTS (SELECT 1 FROM public.${q("User")} u WHERE u.${q("id")}=app_rls.current_user_id() AND u.${q("role")}::text=app_rls.current_role() AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE' AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL)
      AND app_rls.manufacturer_scope_valid(app_rls.current_user_id())
    WHEN ${tenantAdminRoles} THEN
      EXISTS (SELECT 1 FROM public.${q("User")} u JOIN public.${q("Licensee")} l ON l.${q("id")}=u.${q("licenseeId")} JOIN public.${q("Organization")} o ON o.${q("id")}=u.${q("orgId")} AND o.${q("id")}=l.${q("orgId")} WHERE u.${q("id")}=app_rls.current_user_id() AND u.${q("role")}::text=app_rls.current_role() AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE' AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL AND u.${q("licenseeId")}=app_rls.current_licensee_id() AND u.${q("orgId")}=app_rls.current_organization_id() AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE)
    WHEN ${platformRoles} THEN
      app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass')
      AND EXISTS (SELECT 1 FROM public.${q("User")} u WHERE u.${q("id")}=app_rls.current_user_id() AND u.${q("role")}::text=app_rls.current_role() AND u.${q("isActive")}=TRUE AND u.${q("status")}='ACTIVE' AND u.${q("deletedAt")} IS NULL AND u.${q("disabledAt")} IS NULL)
      AND EXISTS (SELECT 1 FROM public.${q("Licensee")} l JOIN public.${q("Organization")} o ON o.${q("id")}=l.${q("orgId")} WHERE l.${q("id")}=app_rls.current_licensee_id() AND (app_rls.current_organization_id() IS NULL OR l.${q("orgId")}=app_rls.current_organization_id()) AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL AND o.${q("isActive")}=TRUE)
    ELSE FALSE
  END
$$;
${dashboardSnapshotFunctionsSql}
${batchOperationalAuthorizationFunctionsSql}
${batchOperationalRowFunctionsSql}
${batchOperationalSummaryFunctionsSql}
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM ${q(roleNames.app)};
${appRuntimeFunctionSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${operationalReadInternalSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.authOwner)};`).join("\n")}
${resetRole}
${operationalReadFunctionSource ? `${setRole(roleNames.authOwner)}
${operationalReadFunctionSource}
${operationalReadSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${resetRole}` : ""}
${b01FunctionSource ? `${setRole(roleNames.authOwner)}
${b01FunctionSource}
${b01FunctionSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${resetRole}` : ""}
${preAuthFunctionSource ? `${setRole(roleNames.authOwner)}
${preAuthFunctionSource}
${preAuthFunctionSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${resetRole}` : ""}
${authenticatedSessionFunctionSource ? `${setRole(roleNames.authOwner)}
${authenticatedSessionFunctionSource}
GRANT USAGE ON SCHEMA app_auth TO ${q(roleNames.app)};
${authenticatedSessionPreauthSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${authenticatedSessionAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${resetRole}` : ""}
${authenticationClosureFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${authenticationClosureFunctionSource}
${authenticationClosurePreauthSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${authenticationClosureAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${c03FunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${c03FunctionSource}
${c03AppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${c03PreauthSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${c03WorkerSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.worker)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${administrationFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${administrationFunctionSource}
${administrationAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${qrSystemFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${qrSystemFunctionSource}
${qrSystemAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${qrSystemWorkerSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.worker)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${printingLifecycleFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${printingLifecycleFunctionSource}
${printingLifecycleAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${printingLifecycleWorkerSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.worker)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${publicVerificationFunctionSource ? `${setRole(roleNames.authOwner)}
${publicVerificationFunctionSource}
${publicVerificationSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.preauth)};`).join("\n")}
${resetRole}` : ""}
${scheduledFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${scheduledFunctionSource}
${scheduledSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.scheduled)};`).join("\n")}
${scheduledOperatorSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.operator)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${outboxFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${outboxFunctionSource}
${outboxAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${outboxWorkerSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.worker)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
${b03AuthenticatedFunctionSource ? `${setRole(roleNames.owner)}
GRANT USAGE,CREATE ON SCHEMA app_rls TO ${q(roleNames.authOwner)};
${resetRole}
${setRole(roleNames.authOwner)}
${b03AuthenticatedFunctionSource}
${b03AuthenticatedAppSignatures.map((signature) => `GRANT EXECUTE ON FUNCTION ${signature} TO ${q(roleNames.app)};`).join("\n")}
${resetRole}
${setRole(roleNames.owner)}
REVOKE CREATE ON SCHEMA app_rls FROM ${q(roleNames.authOwner)};
${resetRole}` : ""}
INSERT INTO mscqr_rls_install.expected_routine(
  schema_name,routine_name,identity_arguments,result_type,routine_kind,owner_name,language_name,volatility,
  security_definer,leakproof,strict,parallel_mode,configuration,source_body,acl_rows
)
SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_function_result(p.oid),p.prokind::text,
  owner_role.rolname,l.lanname,p.provolatile::text,p.prosecdef,p.proleakproof,p.proisstrict,p.proparallel::text,
  p.proconfig,p.prosrc,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_array(COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      ORDER BY COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
    FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
    JOIN pg_roles grantor ON grantor.oid=acl.grantor
  ),'[]'::jsonb)
FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace
JOIN pg_roles owner_role ON owner_role.oid=p.proowner
JOIN pg_language l ON l.oid=p.prolang
WHERE n.nspname IN ('app_rls','app_auth','app_public');
UPDATE mscqr_rls_install.state SET phase='context-helpers-installed' WHERE singleton;
`;

const exactRuleIdForSource = ({ sourceFile, functionName, table, command }) => {
  const workflowIds = new Set(workflowsManifest.workflows
    .filter((workflow) => workflow.canonicalSourceFiles.includes(sourceFile) && workflow.entryPoint.endsWith(`:${functionName}`))
    .map((workflow) => workflow.id));
  const tableId = tables.find((item) => item.physicalTable === table)?.id;
  const ruleIds = commandSemantics.rules
    .filter((rule) => rule.tableId === tableId && rule.command === command && rule.supportingWorkflowIds?.some((workflowId) => workflowIds.has(workflowId)))
    .map((rule) => rule.id)
    .sort();
  if (ruleIds.length !== 1) throw new Error(`Expected one source rule for ${sourceFile}:${functionName}:${table}:${command}; found ${ruleIds.length}`);
  return ruleIds[0];
};
const internalSourceRuleIds = [
  exactRuleIdForSource({ sourceFile: "backend/src/services/auditService.ts", functionName: "createAuditLogInTransaction", table: "AuditLog", command: "INSERT" }),
  exactRuleIdForSource({ sourceFile: "backend/src/controllers/auditController.ts", functionName: "getLogs", table: "AuditLog", command: "SELECT" }),
  exactRuleIdForSource({ sourceFile: "backend/src/services/analyticsService.ts", functionName: "getRiskAnalytics", table: "PolicyRule", command: "SELECT" }),
  exactRuleIdForSource({ sourceFile: "backend/src/services/traceEventService.ts", functionName: "getTraceTimeline", table: "TraceEvent", command: "SELECT" }),
];
const dashboardWorkflowIds = new Set([
  "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot",
  "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate",
]);
const dashboardSourceRuleIds = commandSemantics.rules
  .filter((rule) => rule.allowedColumns?.length && rule.supportingWorkflowIds?.some((workflowId) => dashboardWorkflowIds.has(workflowId)))
  .map((rule) => rule.id)
  .sort();
if (dashboardSourceRuleIds.length !== 15) throw new Error(`Expected 15 exact dashboard source rules, found ${dashboardSourceRuleIds.length}`);
const dashboardRuleIdsFor = (table, command) => {
  const tableId = tables.find((item) => item.physicalTable === table)?.id;
  const ids = commandSemantics.rules
    .filter((rule) => rule.tableId === tableId && rule.command === command && rule.supportingWorkflowIds?.some((workflowId) => dashboardWorkflowIds.has(workflowId)))
    .map((rule) => rule.id)
    .sort();
  if (!ids.length) throw new Error(`Dashboard policy ${table}:${command} has no exact source rule`);
  return ids;
};
const batchWorkflowIds = new Set(BATCH_OPERATIONAL_READ_WORKFLOW_IDS);
const batchSourceRuleIds = commandSemantics.rules
  .filter((rule) => rule.supportingWorkflowIds?.some((workflowId) => batchWorkflowIds.has(workflowId)))
  .map((rule) => rule.id)
  .sort();
if (!batchSourceRuleIds.length) throw new Error("Batch operational policies have no exact source rules");
const batchRuleIdsFor = (table, command) => {
  const tableId = tables.find((item) => item.physicalTable === table)?.id;
  const ids = commandSemantics.rules
    .filter((rule) => rule.tableId === tableId && rule.command === command && rule.supportingWorkflowIds?.some((workflowId) => batchWorkflowIds.has(workflowId)))
    .map((rule) => rule.id)
    .sort();
  if (!ids.length) throw new Error(`Batch operational policy ${table}:${command} has no exact source rule`);
  return ids;
};
const dashboardPolicyBase = `(${operationalSessionBinding} AND app_rls.attributed_request() AND app_rls.current_purpose()='dashboard-snapshot-read' AND (
  ((${platformRoles} OR ${manufacturerRoles}) AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))
  OR (${tenantAdminRoles} AND app_rls.current_assurance() IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass'))
))`;
const operationalScopeLoading = `${operationalSessionBinding} AND current_setting('app.operational_scope_loading',true)='1'`;
const operationalLicenseeScope = (column) =>
  `${column}=ANY(string_to_array(current_setting('app.operational_scope_licensee_ids',true),','))`;
const internalPolicySlices = [
  { table: "User", name: "full_rls_internal_actor_user", predicate: `(((${q("id")}=app_rls.current_user_id() AND ${q("role")}::text=app_rls.current_role()) OR (((${tenantAdminRoles} OR ${platformRoles}) AND app_rls.current_purpose()='tenant-risk-analytics') AND ${q("role")} IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')) OR (${platformRoles} AND app_rls.current_purpose()='platform-audit-log-read' AND ${q("licenseeId")}=app_rls.current_licensee_id())) AND ${q("isActive")}=TRUE AND ${q("status")}='ACTIVE' AND ${q("deletedAt")} IS NULL AND ${q("disabledAt")} IS NULL)` },
  { table: "ManufacturerLicenseeLink", name: "full_rls_internal_manufacturer_link", predicate: `${q("licenseeId")}=app_rls.current_licensee_id() AND ((${manufacturerRoles} AND ${q("manufacturerId")}=app_rls.current_user_id()) OR ((${tenantAdminRoles} OR ${platformRoles}) AND app_rls.current_purpose()='tenant-risk-analytics'))` },
  { table: "Licensee", name: "full_rls_internal_manufacturer_licensee", predicate: `${q("id")}=app_rls.current_licensee_id() AND (app_rls.current_organization_id() IS NULL OR ${q("orgId")}=app_rls.current_organization_id()) AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL` },
  { table: "Organization", name: "full_rls_internal_manufacturer_org", predicate: `((${q("id")}=app_rls.current_organization_id()) OR (${platformRoles} AND app_rls.current_purpose() IN ('tenant-risk-analytics','platform-audit-log-read') AND EXISTS (SELECT 1 FROM public.${q("Licensee")} scope_licensee WHERE scope_licensee.${q("id")}=app_rls.current_licensee_id() AND scope_licensee.${q("orgId")}=${q("Organization")}.${q("id")}))) AND ${q("isActive")}=TRUE` },
  { table: "AuditLog", name: "full_rls_internal_platform_audit_details", predicate: `${platformRoles} AND app_rls.current_purpose()='platform-audit-log-read' AND ${q("licenseeId")}=app_rls.current_licensee_id()` },
].map((policy) => ({ ...policy, sourceCommandRuleIds: internalSourceRuleIds, actors: ["licensee-admin", "manufacturer", "platform-admin"], assurance: "source-rule-specific", purpose: ["tenant-risk-analytics", "audit-log-read", "platform-audit-log-read", "trace-timeline-read"], scopeType: "internal-manufacturer-validation", scopePredicate: policy.predicate, command: "SELECT", columns: [], certificationStatus: "pending", internalHelperOnly: true }))
  .concat([
    {
      table: "ManufacturerLicenseeLink", name: "full_rls_internal_operational_scope_link", command: "SELECT",
      columns: ["manufacturerId", "licenseeId"],
      predicate: `${operationalScopeLoading} AND ${q("manufacturerId")}=app_rls.current_user_id()`,
    },
    {
      table: "Licensee", name: "full_rls_internal_operational_scope_licensee", command: "SELECT",
      columns: ["id", "orgId", "isActive", "suspendedAt"],
      predicate: `${operationalScopeLoading} AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL`,
    },
    {
      table: "Organization", name: "full_rls_internal_operational_scope_organization", command: "SELECT",
      columns: ["id", "isActive"],
      predicate: `${operationalScopeLoading} AND ${q("isActive")}=TRUE`,
    },
    {
      table: "User", name: "full_rls_internal_dashboard_manufacturer_user", command: "SELECT",
      columns: ["id", "role", "isActive", "status", "deletedAt", "disabledAt", "licenseeId", "orgId"],
      predicate: `${dashboardPolicyBase} AND ${q("role")} IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND ${q("isActive")}=TRUE AND (
        (${manufacturerRoles} AND ${q("id")}=app_rls.current_user_id())
        OR (${platformRoles} AND app_rls.current_licensee_id() IS NULL)
        OR ((${tenantAdminRoles} OR ${platformRoles}) AND app_rls.current_licensee_id() IS NOT NULL AND (${q("licenseeId")}=app_rls.current_licensee_id() OR EXISTS (
          SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml WHERE ml.${q("manufacturerId")}=${q("User")}.${q("id")} AND ml.${q("licenseeId")}=app_rls.current_licensee_id()
        )))
      )`,
    },
    {
      table: "ManufacturerLicenseeLink", name: "full_rls_internal_dashboard_manufacturer_link", command: "SELECT",
      columns: ["manufacturerId", "licenseeId", "isPrimary", "updatedAt"],
      predicate: `${dashboardPolicyBase} AND (
        (${manufacturerRoles} AND ${q("manufacturerId")}=app_rls.current_user_id())
        OR (${tenantAdminRoles} AND ${q("licenseeId")}=app_rls.current_licensee_id())
        OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR ${q("licenseeId")}=app_rls.current_licensee_id()))
      )`,
    },
    {
      table: "Licensee", name: "full_rls_internal_dashboard_licensee", command: "SELECT",
      columns: ["id", "orgId", "isActive", "suspendedAt"],
      predicate: `${dashboardPolicyBase} AND (
        (${manufacturerRoles} AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL AND EXISTS (SELECT 1 FROM public.${q("ManufacturerLicenseeLink")} ml WHERE ml.${q("manufacturerId")}=app_rls.current_user_id() AND ml.${q("licenseeId")}=${q("Licensee")}.${q("id")}))
        OR (${tenantAdminRoles} AND ${q("id")}=app_rls.current_licensee_id() AND ${q("orgId")}=app_rls.current_organization_id() AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL)
        OR (${platformRoles} AND ((app_rls.current_licensee_id() IS NULL AND ${q("isActive")}=TRUE) OR (${q("id")}=app_rls.current_licensee_id() AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL)))
      )`,
    },
    {
      table: "Organization", name: "full_rls_internal_dashboard_organization", command: "SELECT",
      columns: ["id", "isActive"],
      predicate: `${dashboardPolicyBase} AND ${q("isActive")}=TRUE AND (
        (${tenantAdminRoles} AND ${q("id")}=app_rls.current_organization_id())
        OR (${manufacturerRoles} AND EXISTS (
          SELECT 1 FROM public.${q("Licensee")} l JOIN public.${q("ManufacturerLicenseeLink")} ml ON ml.${q("licenseeId")}=l.${q("id")}
          WHERE l.${q("orgId")}=${q("Organization")}.${q("id")} AND ml.${q("manufacturerId")}=app_rls.current_user_id()
            AND l.${q("isActive")}=TRUE AND l.${q("suspendedAt")} IS NULL
        ))
        OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR EXISTS (
          SELECT 1 FROM public.${q("Licensee")} l WHERE l.${q("id")}=app_rls.current_licensee_id() AND l.${q("orgId")}=${q("Organization")}.${q("id")}
        )))
      )`,
    },
    {
      table: "Batch", name: "full_rls_internal_dashboard_batch", command: "SELECT",
      columns: ["id", "licenseeId", "manufacturerId"],
      predicate: `${dashboardPolicyBase} AND (
        (${manufacturerRoles} AND ${q("manufacturerId")}=app_rls.current_user_id() AND ${operationalLicenseeScope(q("licenseeId"))})
        OR (${tenantAdminRoles} AND ${q("licenseeId")}=app_rls.current_licensee_id())
        OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR ${q("licenseeId")}=app_rls.current_licensee_id()))
      )`,
    },
    {
      table: "QRCode", name: "full_rls_internal_dashboard_qrcode", command: "SELECT",
      columns: ["batchId", "licenseeId", "status"],
      predicate: `${dashboardPolicyBase} AND (
        (${manufacturerRoles} AND ${operationalLicenseeScope(q("licenseeId"))})
        OR (${tenantAdminRoles} AND ${q("licenseeId")}=app_rls.current_licensee_id())
        OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR ${q("licenseeId")}=app_rls.current_licensee_id()))
      )`,
    },
    {
      table: "InventoryStatusRollup", name: "full_rls_internal_dashboard_rollup", command: "SELECT",
      columns: ["licenseeId", "manufacturerId", "totalCodes", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned"],
      predicate: `${dashboardPolicyBase} AND (
        (${manufacturerRoles} AND ${q("manufacturerId")}=app_rls.current_user_id() AND ${operationalLicenseeScope(q("licenseeId"))})
        OR (${tenantAdminRoles} AND ${q("licenseeId")}=app_rls.current_licensee_id())
        OR (${platformRoles} AND (app_rls.current_licensee_id() IS NULL OR ${q("licenseeId")}=app_rls.current_licensee_id()))
      )`,
    },
    ...["SELECT", "INSERT"].map((command) => ({
      table: "AuditLog", name: `full_rls_internal_dashboard_audit_${command.toLowerCase()}`, command,
      columns: ["id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details"],
      predicate: `${dashboardPolicyBase} AND ${q("userId")}=app_rls.current_user_id() AND ${q("action")}='DASHBOARD_SNAPSHOT_READ' AND ${q("entityType")}='DashboardSnapshot' AND ${q("details")}->>'requestId'=app_rls.current_request_id() AND ${q("details")}->>'purposeCode'='dashboard-snapshot-read' AND ${q("details")}->>'route' IN ('GET /api/dashboard/stats','GET /api/events/dashboard')`,
    })),
  ].map((policy) => {
    const predicate = policy.predicate;
    const operationalScopeLoader = policy.name.startsWith("full_rls_internal_operational_scope_");
    return {
      ...policy,
      predicate,
      projectedColumns: policy.columns,
      columns: [],
      sourceCommandRuleIds: operationalScopeLoader
        ? [...new Set([...dashboardRuleIdsFor(policy.table, policy.command), ...batchRuleIdsFor(policy.table, policy.command)])].sort()
        : dashboardRuleIdsFor(policy.table, policy.command),
      actors: ["licensee-admin", "manufacturer", "platform-admin"],
      assurance: "source-rule-specific",
      purpose: operationalScopeLoader ? ["batch-operational-read", "dashboard-snapshot-read"] : ["dashboard-snapshot-read"],
      scopeType: "database-revalidated-dashboard-aggregate",
      scopePredicate: predicate,
      certificationStatus: "pending",
      internalHelperOnly: true,
      roleKey: "authOwner",
    };
  }))
  .concat([
    {
      table: "User", name: "full_rls_internal_batch_user", command: "SELECT",
      columns: ["id", "email", "name", "role", "licenseeId", "orgId", "status", "isActive", "disabledAt", "deletedAt"],
      predicate: `${batchOperationalBase} AND (
        (${q("id")}=app_rls.current_user_id() AND ${q("role")}::text=app_rls.current_role())
        OR ${q("role")} IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
      )`,
    },
    {
      table: "ManufacturerLicenseeLink", name: "full_rls_internal_batch_manufacturer_link", command: "SELECT",
      columns: ["manufacturerId", "licenseeId", "isPrimary", "updatedAt"],
      predicate: `${batchOperationalBase} AND (
        (${manufacturerRoles} AND ${q("manufacturerId")}=app_rls.current_user_id() AND (app_rls.current_licensee_id() IS NULL OR ${q("licenseeId")}=app_rls.current_licensee_id()))
        OR ((${tenantAdminRoles} OR ${platformRoles}) AND ${q("licenseeId")}=app_rls.current_licensee_id())
      )`,
    },
    {
      table: "Licensee", name: "full_rls_internal_batch_licensee", command: "SELECT",
      columns: ["id", "orgId", "name", "prefix", "isActive", "suspendedAt"],
      predicate: `${batchOperationalBase} AND ${q("isActive")}=TRUE AND ${q("suspendedAt")} IS NULL AND (
        ((${tenantAdminRoles} OR ${platformRoles}) AND ${q("id")}=app_rls.current_licensee_id())
        OR ${manufacturerRoles}
      )`,
    },
    {
      table: "Organization", name: "full_rls_internal_batch_organization", command: "SELECT",
      columns: ["id", "isActive"],
      predicate: `${batchOperationalBase} AND ${q("isActive")}=TRUE AND (
        (${tenantAdminRoles} AND ${q("id")}=app_rls.current_organization_id())
        OR ${manufacturerRoles}
        OR ${platformRoles}
      )`,
    },
    {
      table: "Batch", name: "full_rls_internal_batch_rows", command: "SELECT",
      columns: ["createdAt", "endCode", "id", "lifecycleState", "licenseeId", "manufacturerId", "metadata", "name", "parentBatchId", "printPackDownloadedAt", "printPackDownloadedByUserId", "printedAt", "releasedAt", "releasedByUserId", "rootBatchId", "sampleScanPolicy", "startCode", "suspendedAt", "suspendedReason", "totalCodes", "updatedAt"],
      predicate: `${batchOperationalBase} AND (((${tenantAdminRoles} OR ${platformRoles}) AND ${q("licenseeId")}=app_rls.current_licensee_id()) OR ${manufacturerRoles})`,
    },
    {
      table: "QRCode", name: "full_rls_internal_batch_qrcode", command: "SELECT",
      columns: ["id", "batchId", "licenseeId", "status", "code", "displayCode", "printJobId"],
      predicate: `${batchOperationalBase} AND (((${tenantAdminRoles} OR ${platformRoles}) AND ${q("licenseeId")}=app_rls.current_licensee_id()) OR ${manufacturerRoles})`,
    },
    {
      table: "InventoryStatusRollup", name: "full_rls_internal_batch_rollup", command: "SELECT",
      columns: ["batchId", "licenseeId", "manufacturerId", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned"],
      predicate: `${batchOperationalBase} AND (((${tenantAdminRoles} OR ${platformRoles}) AND ${q("licenseeId")}=app_rls.current_licensee_id()) OR ${manufacturerRoles})`,
    },
    {
      table: "PrintItem", name: "full_rls_internal_batch_print_item", command: "SELECT",
      columns: ["id", "qrCodeId", "printSessionId", "state", "agentAckedAt", "dispatchedAt", "printConfirmedAt", "confirmationEvidence", "deviceJobRef", "deadLetterReason", "failureReason"],
      predicate: batchOperationalBase,
    },
    {
      table: "PrintSession", name: "full_rls_internal_batch_print_session", command: "SELECT",
      columns: ["id", "printJobId", "batchId", "status"],
      predicate: batchOperationalBase,
    },
    {
      table: "PrintJob", name: "full_rls_internal_batch_print_job", command: "SELECT",
      columns: ["id", "batchId", "status"],
      predicate: batchOperationalBase,
    },
    ...["SELECT", "INSERT"].map((command) => ({
      table: "AuditLog", name: `full_rls_internal_batch_audit_${command.toLowerCase()}`, command,
      columns: ["id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details"],
      predicate: `${batchOperationalBase} AND ${q("userId")}=app_rls.current_user_id() AND ${q("action")}='BATCH_OPERATIONAL_READ'
        AND ${q("entityType")}='BatchOperationalRead' AND ${q("details")}->>'requestId'=app_rls.current_request_id()
        AND ${q("details")}->>'purposeCode'='batch-operational-read'
        AND ${q("details")}->>'route' IN ('GET /api/qr/batches','GET /api/qr/batches/:id/allocation-map')`,
    })),
  ].map((policy) => {
    const predicate = policy.predicate;
    return {
      ...policy,
      predicate,
      projectedColumns: policy.columns,
      columns: [],
      sourceCommandRuleIds: batchRuleIdsFor(policy.table, policy.command),
      workflowIds: BATCH_OPERATIONAL_READ_WORKFLOW_IDS,
      actors: ["licensee-admin", "manufacturer", "platform-admin"],
      assurance: "source-rule-specific",
      purpose: ["batch-operational-read"],
      scopeType: "database-revalidated-batch-operational-function",
      scopePredicate: predicate,
      certificationStatus: "pending",
      internalHelperOnly: true,
      roleKey: "authOwner",
    };
  }));

const internalPolicyGroups = new Map();
for (const policy of internalPolicySlices) {
  const key = `${policy.roleKey || "owner"}:${policy.table}:${policy.command}`;
  internalPolicyGroups.set(key, [...(internalPolicyGroups.get(key) || []), policy]);
}
const internalPolicies = [...internalPolicyGroups.values()].map((group) => {
  const sourceCommandRuleIds = [...new Set(group.flatMap((policy) => policy.sourceCommandRuleIds))].sort();
  const workflowIds = [...new Set(group.flatMap((policy) => policy.workflowIds || policy.sourceCommandRuleIds.flatMap((ruleId) => ruleById.get(ruleId)?.supportingWorkflowIds || [])))].sort();
  const predicate = group.length === 1
    ? group[0].predicate
    : `(${group.map((policy) => `(${policy.predicate})`).join(" OR ")})`;
  return {
    table: group[0].table,
    name: shortName(`full_rls_internal_${group[0].roleKey || "owner"}`, group[0].table, group[0].command),
    command: group[0].command,
    predicate,
    projectedColumns: [...new Set(group.flatMap((policy) => policy.projectedColumns || []))].sort(),
    columns: [],
    sourceCommandRuleIds,
    workflowIds,
    actors: [...new Set(group.flatMap((policy) => policy.actors))].sort(),
    assurance: "source-rule-specific",
    purpose: [...new Set(group.flatMap((policy) => policy.purpose))].sort(),
    scopeType: group.length === 1 ? group[0].scopeType : "purpose-dispatched-internal-function-boundary",
    scopePredicate: predicate,
    certificationStatus: "pending",
    internalHelperOnly: true,
    roleKey: group[0].roleKey || "owner",
  };
});

const policyStatements = forceTargets.flatMap((table) => [`ALTER TABLE public.${q(table.physicalTable)} ENABLE ROW LEVEL SECURITY;`, `ALTER TABLE public.${q(table.physicalTable)} FORCE ROW LEVEL SECURITY;`]);
for (const slice of slices) {
  const clause = slice.command === "INSERT" ? `WITH CHECK (${slice.policyPredicate})` : slice.command === "UPDATE" ? `USING (${slice.policyPredicate}) WITH CHECK (${slice.policyPredicate})` : `USING (${slice.policyPredicate})`;
  policyStatements.push(`CREATE POLICY ${q(slice.policyName)} ON public.${q(slice.table)} AS PERMISSIVE FOR ${slice.command} TO ${q(roleNames.app)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(slice.policyName)} ON public.${q(slice.table)} IS ${lit(JSON.stringify({ sourceCommandRuleIds: slice.sourceCommandRuleIds, actors: slice.actors, assurance: slice.minimumAssurance, purpose: slice.purposeCodes, scope: slice.scopeType, workflowId: slice.workflowId }))};`);
}
for (const policy of internalPolicies) {
  const clause = policy.command === "INSERT" ? `WITH CHECK (${policy.predicate})` : `USING (${policy.predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policy.name)} ON public.${q(policy.table)} AS PERMISSIVE FOR ${policy.command} TO ${q(roleNames[policy.roleKey] || roleNames.owner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policy.name)} ON public.${q(policy.table)} IS ${lit(JSON.stringify({ sourceCommandRuleIds: policy.sourceCommandRuleIds, actors: policy.actors, assurance: policy.assurance, purpose: policy.purpose, scope: policy.scopeType, ...(policy.workflowIds ? { workflowIds: policy.workflowIds } : {}) }))};`);
}
for (const [table, command, predicate] of b01TablePolicies) {
  const policyName = shortName("b01", table, command);
  const clause = command === "INSERT" ? `WITH CHECK ${predicate}` : command === "UPDATE" ? `USING ${predicate} WITH CHECK ${predicate}` : `USING ${predicate}`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "b01-refresh-rotation", ownerIdentity: "identity-auth-function-owner", scope: "transaction-local bearer-derived context" }))};`);
}
for (const [table, command, rawPredicate] of preAuthOwnerPolicies) {
  const predicate = rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner));
  const policyName = shortName("b01_preauth", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "b01-preauth-bearer", ownerIdentity: "identity-auth-function-owner", scope: "operation-specific selector rebound to locked token or account" }))};`);
}
for (const [table, command, rawPredicate] of authenticationClosureOwnerPolicies) {
  const predicate = rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner));
  const policyName = shortName("b01_auth_closure", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "b01-authentication-closure", ownerIdentity: "identity-auth-function-owner", scope: "capability-derived actor or live password-login subject" }))};`);
}
if (authenticatedSessionContracts.length) {
  const policyName = shortName("authenticated_session", "RefreshToken", "SELECT_UPDATE");
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q("RefreshToken")} AS PERMISSIVE FOR ALL TO ${q(roleNames.authOwner)} USING ${authenticatedSessionPolicy} WITH CHECK ${authenticatedSessionPolicy};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q("RefreshToken")} IS ${lit(JSON.stringify({ boundary: "authenticated-session-capability", ownerIdentity: "identity-auth-function-owner", scope: "capability hash installed by security definer before protected read" }))};`);
  const userPolicyName = shortName("authenticated_session", "User", "SELECT");
  policyStatements.push(`CREATE POLICY ${q(userPolicyName)} ON public.${q("User")} AS PERMISSIVE FOR SELECT TO ${q(roleNames.authOwner)} USING ${authenticatedSessionUserPolicy};`);
  policyStatements.push(`COMMENT ON POLICY ${q(userPolicyName)} ON public.${q("User")} IS ${lit(JSON.stringify({ boundary: "authenticated-session-capability", ownerIdentity: "identity-auth-function-owner", scope: "locked capability-bound refresh row derives the sole user selector" }))};`);
}
for (const [table, command, rawPredicate] of operationalReadOwnerPolicies) {
  const predicate = rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app));
  const policyName = shortName("tenant_directory", table, command);
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} USING (${predicate});`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "tenant-directory-authenticated-capability", ownerIdentity: "identity-auth-function-owner", scope: "verified session plus live platform, tenant, or manufacturer-link scope" }))};`);
}
for (const [table, command, rawPredicate] of c03OwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
    .replaceAll("{{PREAUTH_ROLE}}", lit(roleNames.preauth))
    .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker));
  const policyName = shortName("c03_capability", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "c03-authenticated-capability", ownerIdentity: "identity-auth-function-owner", scope: "verified session plus operation-specific selector" }))};`);
}
for (const [table, command, rawPredicate] of administrationOwnerPolicies) {
  const predicate = rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app));
  const policyName = shortName("c01_administration", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "c01-administration-capability", ownerIdentity: "identity-auth-function-owner", scope: "verified session plus operation-specific target" }))};`);
}
for (const [table, command, rawPredicate] of qrSystemOwnerPolicies) {
  const predicate = rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)).replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker));
  const policyName = shortName("qr_system", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "qr-system-authenticated-capability", ownerIdentity: "identity-auth-function-owner", scope: "verified session plus operation and row-local QR scope" }))};`);
}
for (const [table, command, rawPredicate] of printingLifecycleOwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
    .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker));
  const policyName = shortName("printing_lifecycle", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "release-fix-5-printing-lifecycle", ownerIdentity: "identity-auth-function-owner", scope: "verified session or exact connector/worker operation plus row-local printing selector" }))};`);
}
for (const [table, command, rawPredicate] of publicVerificationOwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{PREAUTH_ROLE}}", lit(roleNames.preauth));
  const policyName = shortName("public_verification", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "release-fix-6-public-verification", ownerIdentity: "identity-auth-function-owner", scope: "exact pre-auth function plus row-local verification target" }))};`);
}
for (const [table, command, rawPredicate] of scheduledOwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{SCHEDULED_ROLE}}", lit(roleNames.scheduled))
    .replaceAll("{{OPERATOR_ROLE}}", lit(roleNames.operator));
  const policyName = shortName("scheduled_capability", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "scheduled-job-capability", ownerIdentity: "identity-auth-function-owner", scope: "verified scheduled credential plus operation-specific selector" }))};`);
}
for (const [table, command, rawPredicate] of outboxOwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
    .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker));
  const policyName = shortName("b03_outbox", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "b03-durable-outbox", ownerIdentity: "identity-auth-function-owner", scope: "exact worker identity plus immutable row digest" }))};`);
}
for (const [table, command, rawPredicate] of b03AuthenticatedOwnerPolicies) {
  const predicate = rawPredicate
    .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
    .replaceAll("{{APP_ROLE}}", lit(roleNames.app));
  const policyName = shortName("b03_authenticated", table, command);
  const clause = command === "INSERT" ? `WITH CHECK (${predicate})` : command === "UPDATE" ? `USING (${predicate}) WITH CHECK (${predicate})` : `USING (${predicate})`;
  policyStatements.push(`CREATE POLICY ${q(policyName)} ON public.${q(table)} AS PERMISSIVE FOR ${command} TO ${q(roleNames.authOwner)} ${clause};`);
  policyStatements.push(`COMMENT ON POLICY ${q(policyName)} ON public.${q(table)} IS ${lit(JSON.stringify({ boundary: "b03-authenticated-notification-email", ownerIdentity: "identity-auth-function-owner", scope: "live capability plus operation-specific notification or incident selector" }))};`);
}
const policiesSql = `\\set ON_ERROR_STOP on
DO $$ BEGIN
${requirePackagePhaseSql("runtime-grants-installed", "policy package")}
END $$;
${setRole(roleNames.owner)}
${policyStatements.join("\n")}
${resetRole}
INSERT INTO mscqr_rls_install.expected_policy(
  schema_name,table_name,policy_name,permissive,command_name,role_names,using_tree,with_check_tree,policy_comment
)
SELECT n.nspname,c.relname,p.polname,p.polpermissive,p.polcmd::text,
  ARRAY(SELECT COALESCE(role_name.rolname,'PUBLIC') FROM unnest(p.polroles) role_oid LEFT JOIN pg_roles role_name ON role_name.oid=role_oid ORDER BY COALESCE(role_name.rolname,'PUBLIC')),
  p.polqual::text,p.polwithcheck::text,obj_description(p.oid,'pg_policy')
FROM pg_policy p
JOIN pg_class c ON c.oid=p.polrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public';
UPDATE mscqr_rls_install.state SET phase='policies-installed' WHERE singleton;
`;

const expectedColumnValues = grants.flatMap((grant) => grant.command === "DELETE" ? [] : grant.columns.map((column) => `(${lit(grant.table)},${lit(column)},${lit(grant.command)})`));
const expectedRowsSelect = (rows, columns) => {
  if (!rows.length) return `SELECT ${columns.map(({ name, type }) => `NULL::${type} AS ${name}`).join(",")} WHERE FALSE`;
  const values = rows.map((row) => `(${row.map((value, index) => value === null ? `NULL::${columns[index].type}` : columns[index].type === "boolean" ? String(value) : `${lit(value)}::${columns[index].type}`).join(",")})`).join(",");
  return `SELECT * FROM (VALUES ${values}) expected(${columns.map(({ name }) => name).join(",")})`;
};
const aclColumns = [
  { name: "schema_name", type: "text" }, { name: "object_name", type: "text" },
  { name: "grantee_name", type: "text" }, { name: "grantor_name", type: "text" },
  { name: "privilege_type", type: "text" }, { name: "is_grantable", type: "boolean" },
];
const columnAclColumns = [
  { name: "schema_name", type: "text" }, { name: "object_name", type: "text" }, { name: "column_name", type: "text" },
  { name: "grantee_name", type: "text" }, { name: "grantor_name", type: "text" },
  { name: "privilege_type", type: "text" }, { name: "is_grantable", type: "boolean" },
];
const expectedTableAclSelect = expectedRowsSelect([
  ...grants.filter((grant) => grant.command === "DELETE").map((grant) => ["public", grant.table, roleNames.app, roleNames.owner, "DELETE", false]),
  ...authenticationClosureOwnerPrivileges.filter(([, command]) => command === "DELETE").map(([table]) => ["public", table, roleNames.authOwner, roleNames.owner, "DELETE", false]),
  ...administrationOwnerPrivileges.filter(([, command]) => command === "DELETE").map(([table]) => ["public", table, roleNames.authOwner, roleNames.owner, "DELETE", false]),
  ...qrSystemOwnerPrivileges.filter(([, command]) => command === "DELETE").map(([table]) => ["public", table, roleNames.authOwner, roleNames.owner, "DELETE", false]),
  ...printingLifecycleOwnerPrivileges.filter(([, command]) => command === "DELETE").map(([table]) => ["public", table, roleNames.authOwner, roleNames.owner, "DELETE", false]),
  ...publicVerificationOwnerPrivileges.filter(([, command]) => command === "DELETE").map(([table]) => ["public", table, roleNames.authOwner, roleNames.owner, "DELETE", false]),
], aclColumns);
const expectedColumnAclSelect = expectedRowsSelect([
  ...grants.flatMap((grant) => grant.command === "DELETE" ? [] : grant.columns.map((column) => ["public", grant.table, column, roleNames.app, roleNames.owner, grant.command, false])),
  ...b01FunctionOwnerGrants.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...preAuthOwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...authenticationClosureOwnerPrivileges.flatMap(([table, command, columns]) => command === "DELETE" ? [] : columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...c03OwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...administrationOwnerPrivileges.flatMap(([table, command, columns]) => command === "DELETE" ? [] : columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...qrSystemOwnerPrivileges.flatMap(([table, command, columns]) => command === "DELETE" ? [] : columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...printingLifecycleOwnerPrivileges.flatMap(([table, command, columns]) => command === "DELETE" ? [] : columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...publicVerificationOwnerPrivileges.flatMap(([table, command, columns]) => command === "DELETE" ? [] : columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...scheduledOwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...outboxOwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...b03AuthenticatedOwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
  ...operationalReadOwnerPrivileges.flatMap(([table, command, columns]) => columns.map((column) => ["public", table, column, roleNames.authOwner, roleNames.owner, command, false])),
], columnAclColumns);
const expectedTypeAclSelect = expectedRowsSelect(appTypeGrantNames.map((type) => ["public", type, roleNames.app, roleNames.owner, "USAGE", false]), aclColumns);
const expectedDatabaseAclSelect = expectedRowsSelect([
  ...loginRoleNames.map((role) => ["CURRENT_DATABASE", "database", role, administrativeExecutorRole, "CONNECT", false]),
  ["CURRENT_DATABASE", "database", roleNames.migration, administrativeExecutorRole, "TEMPORARY", false],
], aclColumns);
const expectedRoutineIdentities = [
  ["app_rls", "actor_scope_valid", ""],
  ["app_rls", "attributed_request", ""],
  ["app_rls", "authorize_dashboard_snapshot", "audit_id text, requested_licensee_id text, route_surface text"],
  ["app_rls", "authorize_batch_operational_read", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text"],
  ["app_rls", "batch_inventory_rollups", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]"],
  ["app_rls", "batch_operational_batch_allowed", "candidate_batch_id text, focus_batch_id text"],
  ["app_rls", "batch_operational_rows", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, page_limit integer, page_offset integer"],
  ["app_rls", "batch_operational_scope", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text"],
  ["app_rls", "batch_operational_total", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text"],
  ["app_rls", "batch_reservable_qr_summaries", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]"],
  ["app_rls", "batch_scope_fingerprint", "requested_licensee_id text, route_surface text, focus_batch_id text"],
  ["app_rls", "batch_status_fallback", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]"],
  ["app_rls", "batch_unassigned_ranges", "audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]"],
  ["app_rls", "current_assurance", ""],
  ["app_rls", "current_licensee_id", ""],
  ["app_rls", "current_manufacturer_id", ""],
  ["app_rls", "current_organization_id", ""],
  ["app_rls", "current_purpose", ""],
  ["app_rls", "current_request_id", ""],
  ["app_rls", "current_role", ""],
  ["app_rls", "current_user_id", ""],
  ["app_rls", "dashboard_scope_fingerprint", "requested_licensee_id text"],
  ["app_rls", "dashboard_snapshot_data", "audit_id text, requested_licensee_id text, route_surface text, expected_scope_fingerprint text"],
  ["app_rls", "dashboard_snapshot_scope", "audit_id text, requested_licensee_id text, route_surface text"],
  ["app_rls", "install_actor_context", "user_id text, actor_role text, organization_id text, licensee_id text, manufacturer_id text, assurance text, request_id text, purpose_code text"],
  ["app_rls", "manufacturer_scope_valid", "target_manufacturer_id text"],
  ["app_rls", "setting", "setting_name text"],
  ["app_rls", "uuid_setting", "setting_name text"],
  ["app_auth", "b01_audit", "p_action text, p_token_id text, p_at timestamp without time zone"],
  ["app_auth", "b01_bind_bearer", "p_hashes text[], p_request_id text"],
  ["app_auth", "b01_bind_predecessor", "p_token_id text, p_user_id text, p_organization_id text, p_operation text"],
  ["app_auth", "auth_session_prepare", "p_capability text, p_purpose text, p_request_id text"],
  ["app_rls", "c03_require_authenticated_actor", "p_capability text, p_purpose text, p_request_id text"],
  ["app_rls", "c03_assert_live_licensee_scope", "p_selector text, p_actor_role text, p_actor_organization_id text, p_actor_licensee_id text"],
  ["app_rls", "c03_bind_operation", "p_operation text, p_licensee_id text, p_job_id text, p_incident_id text, p_storage_key text"],
  ["app_rls", "c03_compliance_job_projection", "p_job_id text"],
  ["app_rls", "c03_validate_compliance_result", "p_result jsonb"],
  ["app_rls", "c03_queue_audit", "p_action text, p_entity_type text, p_entity_id text, p_details jsonb"],
  ["app_rls", "c03_build_compliance_report", "p_licensee_id text, p_from timestamp with time zone, p_to timestamp with time zone"],
  ["app_rls", "c03_revalidate_actor_scope", "target_licensee_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_platform_actor_scope", "allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_incident_actor_scope", "incident_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_policy_rule_actor_scope", "policy_rule_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_compliance_pack_job_actor_scope", "compliance_pack_job_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_incident_evidence_actor_scope", "incident_evidence_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_incident_evidence_storage_actor_scope", "storage_key text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_revalidate_sensitive_approval_actor_scope", "approval_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text"],
  ["app_rls", "c03_require_policy_actor", "target_licensee_id text, purpose_code text"],
  ["app_rls", "c03_require_platform_policy_actor", "purpose_code text"],
  ["app_rls", "c03_policy_context_valid", ""],
  ["app_rls", "c03_policy_replay", "command_name text, command_payload jsonb"],
  ["app_rls", "c03_complete_policy_command", "command_name text, command_result jsonb"],
  ["app_rls", "c03_require_governance_actor", "allowed_purposes text[]"],
  ["app_rls", "c03_governance_row_visible", "target_licensee_id text, allowed_purposes text[]"],
  ["app_rls", "c03_governance_replay", "command_name text, payload jsonb"],
  ["app_rls", "c03_complete_governance_command", "command_name text, response jsonb"],
  ["app_rls", "c03_governance_audit", "action_name text, entity_type text, entity_id text, details jsonb"],
  ["app_rls", "c03_require_governance_approval", "action_key text, expected_payload jsonb"],
  ["app_rls", "c03_mark_governance_approval_executed", "approval_id text"],
  ["app_rls", "c03_require_approval_actor", "p_purpose text"],
  ["app_rls", "c03_review_sensitive_action_approval", "p_approval_id text, p_decision text, p_review_note text"],
  ["app_rls", "c03_public_incident_qr", "qr_proof text"],
  ["app_rls", "c03_require_incident_actor", "p_incident_id text, p_purpose text, p_assurance text"],
  ["app_rls", "c02_audit_trace_actor_valid", "target_licensee_id text"],
  ["app_rls", "c02_audit_trace_session_valid", ""],
  ["app_rls", "c03_session_valid", ""],
  ["app_rls", "b03_authenticated_context_valid", ""],
  ["app_rls", "risk_analytics_session_valid", ""],
  ["app_rls", "session_c_bind_admin", "p_capability text, p_purpose text, p_request_id text, p_allow_tenant boolean"],
  ["app_rls", "session_c_set_target", "p_licensee_id text, p_organization_id text, p_user_id text, p_email text, p_prefix text"],
  ["app_rls", "session_c_user_projection", "p_target_id text"],
  ["app_rls", "session_c_write_audit", "p_actor_id text, p_organization_id text, p_licensee_id text, p_action text, p_entity_type text, p_entity_id text, p_details jsonb, p_ip_hash text, p_user_agent text"],
  ["app_rls", "session_c_admin_command", "p_capability text, p_purpose text, p_request_id text, p_command text, payload jsonb"],
  ["app_rls", "qr_bind_actor", "p_capability text, p_purpose text, p_request_id text, p_target_licensee_id text"],
  ["app_rls", "qr_write_audit", "p_actor_id text, p_org_id text, p_licensee_id text, p_action text, p_entity_type text, p_entity_id text, p_details jsonb"],
  ["app_rls", "printing_bind_actor", "p_capability text, p_purpose text, p_request_id text, p_batch_id text"],
  ["app_rls", "printing_write_audit", "p_actor_id text, p_actor_role text, p_org_id text, p_licensee_id text, p_action text, p_entity_type text, p_entity_id text, p_details jsonb"],
  ["app_rls", "scheduled_job_prepare", "p_capability text, p_schedule_id text, p_operation text, p_request_id text"],
  ["app_rls", "scheduled_job_queue_audit", "p_action text, p_job_id text, p_licensee_id text, p_details jsonb"],
  ["app_rls", "b03_bind_outbox_operation", "p_operation text, p_row_id text, p_payload_digest text"],
  ["app_rls", "b03_require_authenticated_actor", "p_request_id text"],
  ["app_rls", "b03_assert_requested_scope", "p_licensee_id text, p_organization_id text"],
  ["app_rls", "operational_read_bind_actor", "p_capability text, p_purpose text, p_request_id text, p_requested_licensee_id text"],
  ["app_rls", "operational_read_session_valid", ""],
  ["app_auth", "b01_preauth_audit", "p_action text, p_entity_type text, p_entity_id text, p_at timestamp without time zone, p_details jsonb"],
  ["app_rls", "b01_authenticated_actor", "p_expected_user_id text, p_expected_session_id text, p_request_id text"],
  ["app_public", "public_verify_bind", "p_operation text, p_request_id text, p_qr_id text, p_code text, p_decision_id text, p_session_id text, p_idempotency_hash text"],
  ["app_public", "public_verify_execute", "p_qr_id text, p_proof_source text, p_checked_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_actor_device_hash text, p_session_start_token_hash text, p_signed_token_digest text"],
  ["app_public", "require_customer_auth_session", "p_capability text, p_checked_at timestamp without time zone, p_request_id text, p_operation text"],
  ["app_public", "public_verify_write_evidence", "p_action text, p_entity_type text, p_entity_id text, p_licensee_id text, p_details jsonb, p_recorded_at timestamp without time zone, p_request_id text"],
  ["app_public", "record_qr_verification", "p_qr_id text, p_proof_class text, p_outcome_code text, p_scanned_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_actor_device_hash text"],
  ...[...b01Contracts, ...preAuthContracts, ...authenticatedSessionContracts, ...authenticationClosureContracts, ...c03Contracts, ...administrationContracts, ...qrSystemContracts, ...printingLifecycleContracts, ...publicVerificationContracts, ...scheduledContracts, ...outboxContracts, ...b03AuthenticatedContracts, ...operationalReadContracts].map((contract) => [contract.schema, contract.name, contract.identityArguments]),
];
const routineIdentityColumns = [{ name: "schema_name", type: "text" }, { name: "routine_name", type: "text" }, { name: "identity_arguments", type: "text" }];
const expectedRoutineIdentitySelect = expectedRowsSelect(expectedRoutineIdentities, routineIdentityColumns);
const policyInventory = [
  ...slices.map((slice) => ({
    tableId: slice.tableId,
    table: slice.table,
    policyName: slice.policyName,
    command: slice.command,
    actors: slice.actors,
    assurance: slice.minimumAssurance,
    purpose: slice.purposeCodes,
    scopeType: slice.scopeType,
    scopePredicate: slice.scopePredicate,
    columns: slice.columns,
    sourceCommandRuleIds: slice.sourceCommandRuleIds,
    workflowId: slice.workflowId,
    route: slice.route,
    certificationStatus: slice.certificationStatus,
    internalHelperOnly: false,
  })),
  ...internalPolicies.map((policy) => ({
    tableId: tables.find((table) => table.physicalTable === policy.table)?.id,
    table: policy.table,
    policyName: policy.name,
    ...policy,
  })),
  ...b01TablePolicies.map(([table, command, predicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("b01", table, command),
    command,
    actors: ["pre-auth"],
    assurance: "source-rule-specific",
    purpose: ["b01-refresh-rotation"],
    scopeType: "security-definer-owner-and-bearer-derived-transaction-context",
    scopePredicate: predicate,
    columns: [],
    sourceCommandRuleIds: [b01SourceRuleIds.get(`${table}:${command}`)],
    workflowId: "workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session",
    route: "POST /auth/refresh",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...preAuthOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("b01_preauth", table, command),
    command,
    actors: ["pre-auth"],
    assurance: "source-rule-specific",
    purpose: ["b01-preauth-reviewed-boundary"],
    scopeType: "security-definer-owner-and-locked-bearer-derived-context",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(preAuthContracts, table, command),
    workflowId: null,
    route: "B01 exact pre-auth SQL boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...authenticationClosureOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("b01_auth_closure", table, command),
    command,
    actors: ["pre-auth", "authenticated-user"],
    assurance: "source-rule-specific",
    purpose: ["authentication-release-boundary"],
    scopeType: "security-definer-owner-and-capability-or-live-login-subject",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(authenticationClosureContracts, table, command),
    workflowId: null,
    route: "POST /auth/login, POST /auth/logout, GET /auth/me",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...operationalReadOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("tenant_directory", table, command),
    command,
    actors: ["licensee-admin", "manufacturer", "platform-admin"],
    assurance: "source-rule-specific",
    purpose: ["tenant-directory-licensees", "tenant-directory-users"],
    scopeType: "security-definer-owner-capability-and-live-directory-scope",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)).replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(operationalReadContracts, table, command),
    workflowId: null,
    route: "GET /licensees, GET /licensees/:id, GET /users",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...(authenticatedSessionContracts.length ? [{
    tableId: "table-refresh-token", table: "RefreshToken", policyName: shortName("authenticated_session", "RefreshToken", "SELECT_UPDATE"), command: "ALL",
    actors: ["authenticated-user"], assurance: "source-rule-specific", purpose: ["capability-verified"],
    scopeType: "security-definer-owner-and-capability-hash-derived-transaction-context", scopePredicate: authenticatedSessionPolicy,
    columns: [], sourceCommandRuleIds: [b01SourceRuleIds.get("RefreshToken:SELECT"), b01SourceRuleIds.get("RefreshToken:UPDATE")], workflowId: null, route: "authenticated session capability", certificationStatus: "pending", internalHelperOnly: true,
  }, {
    tableId: "table-user", table: "User", policyName: shortName("authenticated_session", "User", "SELECT"), command: "SELECT",
    actors: ["authenticated-user"], assurance: "source-rule-specific", purpose: ["capability-verified"],
    scopeType: "security-definer-owner-and-capability-bound-user-derived-transaction-context", scopePredicate: authenticatedSessionUserPolicy,
    columns: [], sourceCommandRuleIds: [b01SourceRuleIds.get("User:SELECT")], workflowId: null, route: "authenticated session capability", certificationStatus: "pending", internalHelperOnly: true,
  }] : []),
  ...c03OwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("c03_capability", table, command),
    command,
    actors: ["authenticated-user"],
    assurance: "source-rule-specific",
    purpose: ["c03-reviewed-boundary"],
    scopeType: "security-definer-owner-capability-and-resource-derived-context",
    scopePredicate: rawPredicate
      .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
      .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
      .replaceAll("{{PREAUTH_ROLE}}", lit(roleNames.preauth))
      .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker)),
    columns: [],
    sourceCommandRuleIds: c03PolicyEvidenceFor(table, command),
    workflowId: null,
    route: "C03 exact SQL boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...administrationOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("c01_administration", table, command),
    command,
    actors: ["licensee-admin", "platform-admin"],
    assurance: "source-rule-specific",
    purpose: ["c01-administration-mutation"],
    scopeType: "security-definer-owner-capability-and-operation-target",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)).replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(administrationContracts, table, command),
    workflowId: null,
    route: "C01 administration exact SQL boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...qrSystemOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("qr_system", table, command),
    command,
    actors: ["platform-admin","licensee-admin","manufacturer"],
    assurance: "source-rule-specific",
    purpose: ["release-fix-4-qr-system"],
    scopeType: "security-definer-owner-capability-and-row-local-qr-scope",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(qrSystemContracts, table, command),
    workflowId: null,
    route: "Release Fix 4 exact QR boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...printingLifecycleOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("printing_lifecycle", table, command),
    command,
    actors: ["platform-admin","licensee-admin","manufacturer","connector","background-worker"],
    assurance: "source-rule-specific",
    purpose: ["release-fix-5-printing-lifecycle"],
    scopeType: "security-definer-owner-capability-or-exact-runtime-and-row-local-printing-scope",
    scopePredicate: rawPredicate
      .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
      .replaceAll("{{APP_ROLE}}", lit(roleNames.app))
      .replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(printingLifecycleContracts, table, command),
    workflowId: null,
    route: "Release Fix 5 exact printing boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...publicVerificationOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("public_verification", table, command),
    command,
    actors: ["anonymous"],
    assurance: "source-rule-specific",
    purpose: ["release-fix-6-public-verification"],
    scopeType: "security-definer-owner-and-row-local-public-verification-target",
    scopePredicate: rawPredicate
      .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
      .replaceAll("{{PREAUTH_ROLE}}", lit(roleNames.preauth)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(publicVerificationContracts, table, command),
    workflowId: null,
    route: "Release Fix 6 exact public verification boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...scheduledOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("scheduled_capability", table, command),
    command,
    actors: ["scheduled-job"],
    assurance: "source-rule-specific",
    purpose: ["scheduled-compliance-pack"],
    scopeType: "security-definer-owner-and-durable-scheduled-capability",
    scopePredicate: rawPredicate
      .replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner))
      .replaceAll("{{SCHEDULED_ROLE}}", lit(roleNames.scheduled))
      .replaceAll("{{OPERATOR_ROLE}}", lit(roleNames.operator)),
    columns: [],
    sourceCommandRuleIds: commandSemantics.rules.filter((rule) =>
      rule.tableId === tables.find((entry) => entry.physicalTable === table)?.id &&
      rule.command === command && rule.authorizationBoundary !== "prohibited"
    ).map((rule) => rule.id).sort(),
    workflowId: scheduledComplianceWorkflow,
    route: "scheduled compliance exact SQL boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...outboxOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("b03_outbox", table, command),
    command,
    actors: ["worker"],
    assurance: "source-rule-specific",
    purpose: ["durable-outbox-delivery"],
    scopeType: "security-definer-owner-exact-worker-and-immutable-digest",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)).replaceAll("{{WORKER_ROLE}}", lit(roleNames.worker)),
    columns: [],
    sourceCommandRuleIds: commandSemantics.rules.filter((rule) => rule.tableId === tables.find((entry) => entry.physicalTable === table)?.id && rule.command === command && rule.authorizationBoundary !== "prohibited").map((rule) => rule.id).sort(),
    workflowId: null,
    route: "B03 durable outbox exact SQL boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
  ...b03AuthenticatedOwnerPolicies.map(([table, command, rawPredicate]) => ({
    tableId: tables.find((entry) => entry.physicalTable === table)?.id,
    table,
    policyName: shortName("b03_authenticated", table, command),
    command,
    actors: ["authenticated-application"],
    assurance: "source-rule-specific",
    purpose: ["notification-and-incident-email"],
    scopeType: "security-definer-owner-capability-and-operation-selector",
    scopePredicate: rawPredicate.replaceAll("{{AUTH_OWNER}}", lit(roleNames.authOwner)).replaceAll("{{APP_ROLE}}", lit(roleNames.app)),
    columns: [],
    sourceCommandRuleIds: contractEvidenceFor(b03AuthenticatedContracts, table, command),
    workflowId: null,
    route: "B03 authenticated notification and incident email boundary",
    certificationStatus: "pending",
    internalHelperOnly: true,
  })),
].sort((left, right) => `${left.table}:${left.policyName}`.localeCompare(`${right.table}:${right.policyName}`));
const expectedPolicyValues = policyInventory.map((policy) => `(${lit(policy.table)},${lit(policy.policyName)},${lit(policy.command)})`).join(",");
const expectedSchemaAclRows = [
  ...[roleNames.app, roleNames.read, roleNames.worker, roleNames.scheduled, roleNames.operator, roleNames.migration].map((grantee) => ["public", grantee, roleNames.owner, "USAGE", false]),
  ["public", roleNames.authOwner, roleNames.owner, "USAGE", false],
  ...[roleNames.app, roleNames.read, roleNames.worker, roleNames.scheduled, roleNames.operator].map((grantee) => ["app_rls", grantee, roleNames.owner, "USAGE", false]),
  ["app_rls", roleNames.preauth, roleNames.owner, "USAGE", false],
  ["app_rls", roleNames.authOwner, roleNames.owner, "USAGE", false],
  ["app_auth", roleNames.preauth, roleNames.authOwner, "USAGE", false],
  ["app_auth", roleNames.app, roleNames.authOwner, "USAGE", false],
  ["app_public", roleNames.preauth, roleNames.authOwner, "USAGE", false],
];
const schemaAclColumns = aclColumns.filter(({ name }) => name !== "object_name");
const expectedSchemaAclSelect = expectedRowsSelect(expectedSchemaAclRows, schemaAclColumns);
const currentSchemaAclSelect = `SELECT n.nspname AS schema_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
FROM pg_namespace n
CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl
LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
JOIN pg_roles grantor ON grantor.oid=acl.grantor
WHERE n.nspname IN ('public','app_rls','app_auth','app_public','mscqr_rls_install') AND acl.grantee<>n.nspowner`;
const currentTableAclSelect = `SELECT n.nspname AS schema_name,c.relname AS object_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
JOIN pg_roles grantor ON grantor.oid=acl.grantor
WHERE n.nspname='public' AND c.relkind IN ('r','p') AND acl.grantee<>c.relowner`;
const currentColumnAclSelect = `SELECT n.nspname AS schema_name,c.relname AS object_name,a.attname AS column_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
CROSS JOIN LATERAL aclexplode(a.attacl) acl
LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
JOIN pg_roles grantor ON grantor.oid=acl.grantor
WHERE n.nspname='public' AND c.relkind IN ('r','p') AND acl.grantee<>c.relowner`;
const currentTypeAclSelect = `SELECT n.nspname AS schema_name,t.typname AS object_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
FROM pg_type t
JOIN pg_namespace n ON n.oid=t.typnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(t.typacl,acldefault('T',t.typowner))) acl
LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
JOIN pg_roles grantor ON grantor.oid=acl.grantor
WHERE n.nspname='public' AND t.typtype='e' AND acl.grantee<>t.typowner`;
const currentDatabaseAclSelect = `SELECT 'CURRENT_DATABASE'::text AS schema_name,'database'::text AS object_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
FROM pg_database d
CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) acl
LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
JOIN pg_roles grantor ON grantor.oid=acl.grantor
WHERE d.datname=current_database() AND acl.grantee<>d.datdba`;
const currentRoutineSelect = `SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_function_result(p.oid),p.prokind::text,
  owner_role.rolname,l.lanname,p.provolatile::text,p.prosecdef,p.proleakproof,p.proisstrict,p.proparallel::text,
  p.proconfig,p.prosrc,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_array(COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      ORDER BY COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
    FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
    JOIN pg_roles grantor ON grantor.oid=acl.grantor
  ),'[]'::jsonb)
FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace
JOIN pg_roles owner_role ON owner_role.oid=p.proowner
JOIN pg_language l ON l.oid=p.prolang
WHERE n.nspname IN ('app_rls','app_auth','app_public')`;
const currentPolicySelect = `SELECT n.nspname,c.relname,p.polname,p.polpermissive,p.polcmd::text,
  ARRAY(SELECT COALESCE(role_name.rolname,'PUBLIC') FROM unnest(p.polroles) role_oid LEFT JOIN pg_roles role_name ON role_name.oid=role_oid ORDER BY COALESCE(role_name.rolname,'PUBLIC')),
  p.polqual::text,p.polwithcheck::text,obj_description(p.oid,'pg_policy')
FROM pg_policy p
JOIN pg_class c ON c.oid=p.polrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public'`;
const defaultAclScopeRows = [
  ...[roleNames.migration, roleNames.owner, roleNames.authOwner].flatMap((ownerName) => ["r", "S", "f", "T", "n", "L"].map((objectType) => [ownerName, null, objectType])),
  ...["public", "app_rls"].flatMap((schema) => ["r", "S", "f", "T"].map((objectType) => [roleNames.owner, schema, objectType])),
  ...["r", "S", "f", "T"].flatMap((objectType) => [[roleNames.authOwner, "app_auth", objectType],[roleNames.authOwner, "app_public", objectType]]),
];
const defaultAclScopeColumns = [{ name: "owner_name", type: "text" }, { name: "schema_name", type: "text" }, { name: "object_type", type: "text" }];
const expectedDefaultAclScopeSelect = expectedRowsSelect(defaultAclScopeRows, defaultAclScopeColumns);
const verificationSql = `\\set ON_ERROR_STOP on
DO $$ DECLARE failures integer; BEGIN
${requirePackagePhaseSql("policies-installed", "verification")}
  ${postMigrationInventorySql}
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN (${targetTableList}) AND r.rolname<>${lit(roleNames.owner)}) THEN RAISE EXCEPTION 'application table ownership drifted'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname='_prisma_migrations' AND r.rolname<>${lit(roleNames.migration)}) THEN RAISE EXCEPTION 'Prisma migration ledger ownership drifted'; END IF;
  IF EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_roles r ON r.oid=t.typowner WHERE n.nspname='public' AND t.typtype='e' AND r.rolname<>${lit(roleNames.owner)}) THEN RAISE EXCEPTION 'Prisma enum ownership drifted'; END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE (n.nspname IN ('public','app_rls') AND r.rolname<>${lit(roleNames.owner)}) OR (n.nspname IN ('app_auth','app_public') AND r.rolname<>${lit(roleNames.authOwner)}) OR (n.nspname='mscqr_rls_install' AND r.rolname<>${lit(administrativeExecutorRole)})) THEN RAISE EXCEPTION 'clean-room schema ownership drifted'; END IF;
  IF EXISTS (
    (SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mscqr_rls_install' AND c.relkind='r' EXCEPT SELECT * FROM (VALUES ('expected_policy'),('expected_routine'),('state')) expected(table_name))
    UNION ALL
    (SELECT * FROM (VALUES ('expected_policy'),('expected_routine'),('state')) expected(table_name) EXCEPT SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mscqr_rls_install' AND c.relkind='r')
  ) OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='mscqr_rls_install' AND c.relkind='r' AND r.rolname<>${lit(administrativeExecutorRole)})
    OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE n.nspname='mscqr_rls_install' AND c.relkind='r' AND acl.grantee<>c.relowner)
  THEN RAISE EXCEPTION 'private install-state inventory or privileges drifted'; END IF;
  SELECT count(*) INTO failures FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN (${forceTargets.map((table) => lit(table.physicalTable)).join(",")}) AND c.relkind IN ('r','p') AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity); IF failures<>0 THEN RAISE EXCEPTION 'FORCE RLS verification failed for % tables',failures; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN (${migrationOnly.map((table) => lit(table.physicalTable)).join(",")}) AND (c.relrowsecurity OR c.relforcerowsecurity)) THEN RAISE EXCEPTION 'migration-only table unexpectedly has RLS state'; END IF;
  IF EXISTS (
    (SELECT tablename,policyname,cmd FROM pg_policies WHERE schemaname='public' EXCEPT SELECT * FROM (VALUES ${expectedPolicyValues}) expected(table_name,policy_name,command_name))
    UNION ALL
    (SELECT * FROM (VALUES ${expectedPolicyValues}) expected(table_name,policy_name,command_name) EXCEPT SELECT tablename,policyname,cmd FROM pg_policies WHERE schemaname='public')
  ) THEN RAISE EXCEPTION 'policy inventory differs from the generated contract'; END IF;
  IF EXISTS (
    (SELECT * FROM (${currentPolicySelect}) current_policy EXCEPT SELECT * FROM mscqr_rls_install.expected_policy)
    UNION ALL
    (SELECT * FROM mscqr_rls_install.expected_policy EXCEPT SELECT * FROM (${currentPolicySelect}) current_policy)
  ) THEN RAISE EXCEPTION 'policy definition differs from the sealed generated contract'; END IF;
  IF EXISTS (
    (SELECT * FROM (${currentRoutineSelect}) current_routine EXCEPT SELECT * FROM mscqr_rls_install.expected_routine)
    UNION ALL
    (SELECT * FROM mscqr_rls_install.expected_routine EXCEPT SELECT * FROM (${currentRoutineSelect}) current_routine)
  ) THEN RAISE EXCEPTION 'routine definition or privilege inventory differs from the sealed generated contract'; END IF;
  IF EXISTS (
    (SELECT schema_name,routine_name,identity_arguments FROM mscqr_rls_install.expected_routine EXCEPT ${expectedRoutineIdentitySelect})
    UNION ALL
    (${expectedRoutineIdentitySelect} EXCEPT SELECT schema_name,routine_name,identity_arguments FROM mscqr_rls_install.expected_routine)
  ) THEN
    RAISE EXCEPTION 'routine identity inventory differs from the generated contract'
      USING DETAIL = concat(
        'unexpected=',
        COALESCE((SELECT jsonb_agg(row_to_json(r)) FROM (
          SELECT schema_name,routine_name,identity_arguments
            FROM mscqr_rls_install.expected_routine
          EXCEPT ${expectedRoutineIdentitySelect}
        ) r), '[]'::jsonb),
        '; missing=',
        COALESCE((SELECT jsonb_agg(row_to_json(r)) FROM (
          ${expectedRoutineIdentitySelect}
          EXCEPT SELECT schema_name,routine_name,identity_arguments
            FROM mscqr_rls_install.expected_routine
        ) r), '[]'::jsonb)
      );
  END IF;
  IF EXISTS (
    (SELECT * FROM (${currentSchemaAclSelect}) current_acl EXCEPT ${expectedSchemaAclSelect})
    UNION ALL
    (${expectedSchemaAclSelect} EXCEPT SELECT * FROM (${currentSchemaAclSelect}) current_acl)
  ) THEN RAISE EXCEPTION 'schema privilege inventory differs from the generated contract'; END IF;
  IF EXISTS (
    (SELECT * FROM (${currentTableAclSelect}) current_acl EXCEPT ${expectedTableAclSelect})
    UNION ALL
    (${expectedTableAclSelect} EXCEPT SELECT * FROM (${currentTableAclSelect}) current_acl)
  ) THEN RAISE EXCEPTION 'table privilege inventory differs from the generated contract'; END IF;
  IF EXISTS (
    (SELECT * FROM (${currentColumnAclSelect}) current_acl EXCEPT ${expectedColumnAclSelect})
    UNION ALL
    (${expectedColumnAclSelect} EXCEPT SELECT * FROM (${currentColumnAclSelect}) current_acl)
  ) THEN
    RAISE EXCEPTION 'column privilege inventory differs from the generated contract'
      USING DETAIL = concat(
        'unexpected=',
        COALESCE((SELECT jsonb_agg(row_to_json(r)) FROM (
          SELECT * FROM (${currentColumnAclSelect}) current_acl EXCEPT ${expectedColumnAclSelect}
        ) r), '[]'::jsonb),
        '; missing=',
        COALESCE((SELECT jsonb_agg(row_to_json(r)) FROM (
          ${expectedColumnAclSelect} EXCEPT SELECT * FROM (${currentColumnAclSelect}) current_acl
        ) r), '[]'::jsonb)
      );
  END IF;
  IF EXISTS (
    (SELECT * FROM (${currentTypeAclSelect}) current_acl EXCEPT ${expectedTypeAclSelect})
    UNION ALL
    (${expectedTypeAclSelect} EXCEPT SELECT * FROM (${currentTypeAclSelect}) current_acl)
  ) THEN RAISE EXCEPTION 'type privilege inventory differs from the generated contract'; END IF;
  IF EXISTS (
    (SELECT * FROM (${currentDatabaseAclSelect}) current_acl EXCEPT ${expectedDatabaseAclSelect})
    UNION ALL
    (${expectedDatabaseAclSelect} EXCEPT SELECT * FROM (${currentDatabaseAclSelect}) current_acl)
  ) THEN RAISE EXCEPTION 'database privilege inventory differs from the generated contract'; END IF;
  IF EXISTS (
    WITH expected_scope AS (${expectedDefaultAclScopeSelect}), resolved_scope AS (
      SELECT scope.owner_name,scope.schema_name,scope.object_type,owner_role.oid AS owner_oid,COALESCE(namespace.oid,0) AS namespace_oid
      FROM expected_scope scope JOIN pg_roles owner_role ON owner_role.rolname=scope.owner_name
      LEFT JOIN pg_namespace namespace ON namespace.nspname=scope.schema_name
    )
    SELECT 1 FROM pg_default_acl actual
    WHERE NOT EXISTS (SELECT 1 FROM resolved_scope expected WHERE expected.owner_oid=actual.defaclrole AND expected.namespace_oid=actual.defaclnamespace AND expected.object_type::"char"=actual.defaclobjtype)
  ) THEN RAISE EXCEPTION 'default privilege scope inventory differs from the generated contract'; END IF;
  IF EXISTS (
    WITH expected_scope AS (${expectedDefaultAclScopeSelect}), resolved_scope AS (
      SELECT scope.owner_name,scope.schema_name,scope.object_type,owner_role.oid AS owner_oid,COALESCE(namespace.oid,0) AS namespace_oid
      FROM expected_scope scope JOIN pg_roles owner_role ON owner_role.rolname=scope.owner_name
      LEFT JOIN pg_namespace namespace ON namespace.nspname=scope.schema_name
    ), expected_acl AS (
      SELECT scope.owner_name,scope.schema_name,scope.object_type,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
      FROM resolved_scope scope CROSS JOIN LATERAL aclexplode(acldefault(scope.object_type::"char",scope.owner_oid)) acl
      LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee JOIN pg_roles grantor ON grantor.oid=acl.grantor WHERE acl.grantee<>0
    ), current_acl AS (
      SELECT scope.owner_name,scope.schema_name,scope.object_type,COALESCE(grantee.rolname,'PUBLIC') AS grantee_name,grantor.rolname AS grantor_name,acl.privilege_type,acl.is_grantable
      FROM resolved_scope scope LEFT JOIN pg_default_acl actual ON actual.defaclrole=scope.owner_oid AND actual.defaclnamespace=scope.namespace_oid AND actual.defaclobjtype=scope.object_type::"char"
      CROSS JOIN LATERAL aclexplode(COALESCE(actual.defaclacl,acldefault(scope.object_type::"char",scope.owner_oid))) acl
      LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee JOIN pg_roles grantor ON grantor.oid=acl.grantor WHERE acl.grantee<>0
    )
    SELECT 1 FROM ((SELECT * FROM current_acl EXCEPT SELECT * FROM expected_acl) UNION ALL (SELECT * FROM expected_acl EXCEPT SELECT * FROM current_acl)) drift
  ) THEN RAISE EXCEPTION 'default privilege definition differs from the generated contract'; END IF;
END $$;
`;

const cleanupSql = `\\set ON_ERROR_STOP on
\\if :{?candidate_database}
\\else
  \\echo 'candidate_database psql variable is required after the green database has been dropped'
  \\quit 3
\\endif
SELECT set_config('mscqr.cleanup_candidate_database',:'candidate_database',false);
DO $$ DECLARE existing_count integer; rec record; BEGIN
  IF current_database()=current_setting('mscqr.cleanup_candidate_database') THEN RAISE EXCEPTION 'role cleanup must run from the green cluster maintenance database'; END IF;
  IF current_setting('mscqr.cleanup_candidate_database') !~ ${lit(candidateDatabasePattern)} THEN RAISE EXCEPTION 'role cleanup candidate name is outside the reviewed green boundary'; END IF;
  IF EXISTS (SELECT 1 FROM pg_database WHERE datname=current_setting('mscqr.cleanup_candidate_database')) THEN RAISE EXCEPTION 'green database must be dropped before package-role cleanup'; END IF;
  SELECT count(*) INTO existing_count FROM pg_roles WHERE rolname IN (${managedRoleList});
  IF existing_count NOT IN (0,${roleSpecs.length}) THEN RAISE EXCEPTION 'partial managed-role set is not a package-created clean-room state'; END IF;
  IF existing_count=0 THEN RETURN; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ${roleValuesSql}) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>${lit(roleMarker)}) THEN RAISE EXCEPTION 'role cleanup refuses an unmarked or drifted role'; END IF;
  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN (${managedRoleList}))<>${roleSpecs.length * 2}
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN (${managedRoleList}) AND (member.rolname<>current_user OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN (${managedRoleList}) AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname=current_user AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname=current_user AND grantor.rolname=current_user AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN (${managedRoleList}))
  THEN RAISE EXCEPTION 'role cleanup refuses unexpected managed-role membership'; END IF;
  FOR rec IN SELECT rolname FROM pg_roles WHERE rolname IN (${managedRoleList}) ORDER BY rolname LOOP EXECUTE format('REVOKE %I FROM %I',rec.rolname,current_user); END LOOP;
  FOR rec IN SELECT rolname FROM pg_roles WHERE rolname IN (${managedRoleList}) ORDER BY CASE WHEN rolname IN (${lit(roleNames.owner)},${lit(roleNames.authOwner)}) THEN 1 ELSE 0 END,rolname LOOP EXECUTE format('DROP ROLE %I',rec.rolname); END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN (${managedRoleList})) THEN RAISE EXCEPTION 'package-created managed-role cleanup left residue'; END IF;
END $$;
`;

const ids = {
  orgA: "00000000-0000-4000-8000-000000000101", orgB: "00000000-0000-4000-8000-000000000102",
  licenseeA: "00000000-0000-4000-8000-000000000201", licenseeB: "00000000-0000-4000-8000-000000000202",
  adminA: "00000000-0000-4000-8000-000000000301", adminB: "00000000-0000-4000-8000-000000000302",
  manufacturerA: "00000000-0000-4000-8000-000000000303", manufacturerB: "00000000-0000-4000-8000-000000000304",
  manufacturerLegacyALinkB: "00000000-0000-4000-8000-000000000305", manufacturerLegacyBUnlinked: "00000000-0000-4000-8000-000000000306",
  platformA: "00000000-0000-4000-8000-000000000307",
  batchA: "00000000-0000-4000-8000-000000000401", batchB: "00000000-0000-4000-8000-000000000402",
  qrA: "00000000-0000-4000-8000-000000000501", qrB: "00000000-0000-4000-8000-000000000502",
  scanA: "00000000-0000-4000-8000-000000000601", scanB: "00000000-0000-4000-8000-000000000602",
  incidentA: "00000000-0000-4000-8000-000000000701", incidentB: "00000000-0000-4000-8000-000000000702",
  ruleA: "00000000-0000-4000-8000-000000000801", ruleB: "00000000-0000-4000-8000-000000000802",
  ruleOrgA: "00000000-0000-4000-8000-000000000803", ruleManA: "00000000-0000-4000-8000-000000000804", ruleConflict: "00000000-0000-4000-8000-000000000805",
  alertA: "00000000-0000-4000-8000-000000000901", alertB: "00000000-0000-4000-8000-000000000902",
  policyA: "00000000-0000-4000-8000-000000001001", policyB: "00000000-0000-4000-8000-000000001002",
  auditA: "00000000-0000-4000-8000-000000001101", auditB: "00000000-0000-4000-8000-000000001102", auditAOther: "00000000-0000-4000-8000-000000001103",
  traceA: "00000000-0000-4000-8000-000000001201", traceB: "00000000-0000-4000-8000-000000001202",
  refreshA: "00000000-0000-4000-8000-000000001301", refreshRollback: "00000000-0000-4000-8000-000000001302",
};
const fixtureSql = `\\set ON_ERROR_STOP on
INSERT INTO public.${q("Organization")} (${q("id")},${q("name")},${q("updatedAt")}) VALUES ('${ids.orgA}','Cert Org A',now()),('${ids.orgB}','Cert Org B',now());
INSERT INTO public.${q("Licensee")} (${q("id")},${q("orgId")},${q("name")},${q("prefix")},${q("updatedAt")}) VALUES ('${ids.licenseeA}','${ids.orgA}','Cert Licensee A','FRLCA',now()),('${ids.licenseeB}','${ids.orgB}','Cert Licensee B','FRLCB',now());
INSERT INTO public.${q("User")} (${q("id")},${q("email")},${q("name")},${q("role")},${q("orgId")},${q("licenseeId")},${q("status")},${q("isActive")},${q("updatedAt")}) VALUES ('${ids.adminA}','admin-a@example.invalid','Admin A','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),('${ids.adminB}','admin-b@example.invalid','Admin B','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now()),('${ids.manufacturerA}','manufacturer-a@example.invalid','Manufacturer A','MANUFACTURER','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),('${ids.manufacturerB}','manufacturer-b@example.invalid','Manufacturer B','MANUFACTURER','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now()),('${ids.manufacturerLegacyALinkB}','manufacturer-linked-b@example.invalid','Manufacturer Linked B','MANUFACTURER','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),('${ids.manufacturerLegacyBUnlinked}','manufacturer-unlinked-b@example.invalid','Manufacturer Unlinked B','MANUFACTURER','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now()),('${ids.platformA}','platform-a@example.invalid','Platform A','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now());
INSERT INTO public.${q("ManufacturerLicenseeLink")} (${q("manufacturerId")},${q("licenseeId")},${q("isPrimary")},${q("updatedAt")}) VALUES ('${ids.manufacturerA}','${ids.licenseeA}',true,now()),('${ids.manufacturerB}','${ids.licenseeB}',true,now()),('${ids.manufacturerLegacyALinkB}','${ids.licenseeB}',false,now());
INSERT INTO public.${q("RefreshToken")} (${q("id")},${q("orgId")},${q("userId")},${q("tokenHash")},${q("expiresAt")},${q("createdAt")}) VALUES ('${ids.refreshA}','${ids.orgA}','${ids.adminA}','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',now()+interval '1 day',now()),('${ids.refreshRollback}','${ids.orgA}','${ids.adminA}','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',now()+interval '1 day',now());
INSERT INTO public.${q("Batch")} (${q("id")},${q("name")},${q("licenseeId")},${q("manufacturerId")},${q("startCode")},${q("endCode")},${q("totalCodes")},${q("updatedAt")}) VALUES ('${ids.batchA}','Batch A','${ids.licenseeA}','${ids.manufacturerA}','A1','A1',1,now()),('${ids.batchB}','Batch B','${ids.licenseeB}','${ids.manufacturerB}','B1','B1',1,now());
INSERT INTO public.${q("QRCode")} (${q("id")},${q("code")},${q("licenseeId")},${q("batchId")},${q("status")},${q("updatedAt")}) VALUES ('${ids.qrA}','A1','${ids.licenseeA}','${ids.batchA}','ACTIVE',now()),('${ids.qrB}','B1','${ids.licenseeB}','${ids.batchB}','ACTIVE',now());
INSERT INTO public.${q("QrScanLog")} (${q("id")},${q("code")},${q("qrCodeId")},${q("licenseeId")},${q("batchId")},${q("status")}) VALUES ('${ids.scanA}','A1','${ids.qrA}','${ids.licenseeA}','${ids.batchA}','SCANNED'),('${ids.scanB}','B1','${ids.qrB}','${ids.licenseeB}','${ids.batchB}','SCANNED');
INSERT INTO public.${q("Incident")} (${q("id")},${q("qrCodeId")},${q("qrCodeValue")},${q("scanEventId")},${q("licenseeId")},${q("incidentType")},${q("description")},${q("photos")},${q("tags")},${q("updatedAt")}) VALUES ('${ids.incidentA}','${ids.qrA}','A1','${ids.scanA}','${ids.licenseeA}','DUPLICATE_SCAN','A',ARRAY[]::text[],ARRAY[]::text[],now()),('${ids.incidentB}','${ids.qrB}','B1','${ids.scanB}','${ids.licenseeB}','DUPLICATE_SCAN','B',ARRAY[]::text[],ARRAY[]::text[],now());
INSERT INTO public.${q("PolicyRule")} (${q("id")},${q("orgId")},${q("licenseeId")},${q("manufacturerId")},${q("createdByUserId")},${q("name")},${q("ruleType")},${q("threshold")},${q("windowMinutes")},${q("isActive")},${q("updatedAt")}) VALUES
('${ids.ruleA}','${ids.orgA}','${ids.licenseeA}','${ids.manufacturerA}','${ids.adminA}','Rule A','DISTINCT_DEVICES',2,60,true,now()),('${ids.ruleB}','${ids.orgB}','${ids.licenseeB}','${ids.manufacturerB}','${ids.adminB}','Rule B','DISTINCT_DEVICES',2,60,true,now()),
('${ids.ruleOrgA}','${ids.orgA}',NULL,NULL,'${ids.adminA}','Org Rule A','DISTINCT_DEVICES',2,60,true,now()),('${ids.ruleManA}',NULL,NULL,'${ids.manufacturerA}','${ids.adminA}','Manufacturer Rule A','DISTINCT_DEVICES',2,60,true,now()),
('${ids.ruleConflict}','${ids.orgB}','${ids.licenseeA}',NULL,'${ids.adminA}','Conflict Rule','DISTINCT_DEVICES',2,60,true,now());
INSERT INTO public.${q("PolicyAlert")} (${q("id")},${q("licenseeId")},${q("alertType")},${q("message")},${q("policyRuleId")},${q("incidentId")},${q("batchId")},${q("qrCodeId")},${q("manufacturerId")}) VALUES ('${ids.alertA}','${ids.licenseeA}','POLICY_RULE','Alert A','${ids.ruleA}','${ids.incidentA}','${ids.batchA}','${ids.qrA}','${ids.manufacturerA}'),('${ids.alertB}','${ids.licenseeB}','POLICY_RULE','Alert B','${ids.ruleB}','${ids.incidentB}','${ids.batchB}','${ids.qrB}','${ids.manufacturerB}');
INSERT INTO public.${q("SecurityPolicy")} (${q("id")},${q("licenseeId")},${q("updatedAt")}) VALUES ('${ids.policyA}','${ids.licenseeA}',now()),('${ids.policyB}','${ids.licenseeB}',now());
INSERT INTO public.${q("AuditLog")} (${q("id")},${q("userId")},${q("orgId")},${q("licenseeId")},${q("action")},${q("entityType")},${q("entityId")},${q("ipAddress")},${q("userAgent")}) VALUES ('${ids.auditA}','${ids.adminA}','${ids.orgA}','${ids.licenseeA}','CERT','Batch','${ids.batchA}','192.0.2.10','cert-admin-a'),('${ids.auditAOther}','${ids.manufacturerA}','${ids.orgA}','${ids.licenseeA}','CERT_OTHER','Batch','${ids.batchA}','192.0.2.11','cert-manufacturer-a'),('${ids.auditB}','${ids.adminB}','${ids.orgB}','${ids.licenseeB}','CERT','Batch','${ids.batchB}','192.0.2.20','cert-admin-b');
INSERT INTO public.${q("TraceEvent")} (${q("id")},${q("eventType")},${q("licenseeId")},${q("batchId")},${q("qrCodeId")},${q("manufacturerId")},${q("userId")}) VALUES ('${ids.traceA}','COMMISSIONED','${ids.licenseeA}','${ids.batchA}','${ids.qrA}','${ids.manufacturerA}','${ids.adminA}'),('${ids.traceB}','COMMISSIONED','${ids.licenseeB}','${ids.batchB}','${ids.qrB}','${ids.manufacturerB}','${ids.adminB}');
`;

const files = new Map([
  ["00-preflight.sql", transactionalPhase(preflightSql)],
  ["10-roles.sql", transactionalPhase(roleCreationSql)],
  ["15-migration-preflight.sql", transactionalPhase(migrationPreflightSql)],
  ["11-ownership-grants.sql", transactionalPhase(roleOwnershipSql)],
  ["20-context-helpers.sql", transactionalPhase(contextHelpersSql)],
  ["21-runtime-grants.sql", transactionalPhase(runtimeGrantsSql)],
  ["30-policies.sql", transactionalPhase(policiesSql)],
  ["40-post-apply-verification.sql", transactionalPhase(verificationSql)],
  ["50-certification-fixtures.sql", transactionalPhase(fixtureSql)],
  ["90-clean-room-role-cleanup.sql", transactionalPhase(cleanupSql)],
]);
files.set("admin-bootstrap.sql", "\\set ON_ERROR_STOP on\n\\ir 00-preflight.sql\n\\ir 10-roles.sql\n");
files.set("migration.sql", "\\set ON_ERROR_STOP on\n\\ir 15-migration-preflight.sql\n");
files.set("admin-ownership.sql", "\\set ON_ERROR_STOP on\n\\ir 11-ownership-grants.sql\n");
files.set("runtime-policy.sql", "\\set ON_ERROR_STOP on\n\\ir 20-context-helpers.sql\n\\ir 21-runtime-grants.sql\n\\ir 30-policies.sql\n");
files.set("verification.sql", "\\set ON_ERROR_STOP on\n\\ir 40-post-apply-verification.sql\n");
files.set("clean-room-cleanup.sql", "\\set ON_ERROR_STOP on\n\\ir 90-clean-room-role-cleanup.sql\n");

const phaseDefinitions = [
  {
    id: "admin-bootstrap", order: 1, executorClass: "green-cluster-database-administrator", executorRole: administrativeExecutorRole,
    mutating: true, entrypoint: "admin-bootstrap.sql", files: ["admin-bootstrap.sql", "00-preflight.sql", "10-roles.sql"],
    requiredCapabilities: ["exact-green-database-owner", "CREATEDB", "CREATEROLE", "zero-managed-roles", "template0-clean-catalog"],
    failureDisposition: "drop-green-database-then-clean-marked-roles",
  },
  {
    id: "migration", order: 2, executorClass: "restricted-migration", executorRole: roleNames.migration,
    mutating: true, entrypoint: "migration.sql", files: ["migration.sql", "15-migration-preflight.sql"],
    externalCommand: "npx prisma migrate deploy --schema prisma/schema.prisma",
    requiredCapabilities: ["green-database-CONNECT", "initial-public-USAGE-CREATE", "no-owner-membership", "zero-migration-ledger"],
    failureDisposition: "drop-green-database-then-clean-marked-roles",
  },
  {
    id: "admin-ownership", order: 3, executorClass: "green-cluster-database-administrator", executorRole: administrativeExecutorRole,
    mutating: true, entrypoint: "admin-ownership.sql", files: ["admin-ownership.sql", "11-ownership-grants.sql"],
    requiredCapabilities: ["exact-post-migration-catalog", "SET-migration", "SET-NOLOGIN-owners"],
    failureDisposition: "drop-green-database-then-clean-marked-roles",
  },
  {
    id: "runtime-policy", order: 4, executorClass: "green-cluster-database-administrator", executorRole: administrativeExecutorRole,
    mutating: true, entrypoint: "runtime-policy.sql", files: ["runtime-policy.sql", "20-context-helpers.sql", "21-runtime-grants.sql", "30-policies.sql"],
    requiredCapabilities: ["SET-NOLOGIN-owners", "exact-column-grants", "FORCE-RLS"],
    failureDisposition: "drop-green-database-then-clean-marked-roles",
  },
  {
    id: "verification", order: 5, executorClass: "green-cluster-database-administrator", executorRole: administrativeExecutorRole,
    mutating: false, entrypoint: "verification.sql", files: ["verification.sql", "40-post-apply-verification.sql"],
    requiredCapabilities: ["catalog-read", "package-marker-read"],
    failureDisposition: "drop-green-database-then-clean-marked-roles",
  },
  {
    id: "clean-room-destroy", order: 6, executorClass: "green-cluster-maintenance-administrator", executorRole: administrativeExecutorRole,
    mutating: true, entrypoint: "clean-room-cleanup.sql", files: ["clean-room-cleanup.sql", "90-clean-room-role-cleanup.sql"],
    externalPrerequisites: ["green-consumers-stopped", "no-required-data-accepted", "green-database-dropped-from-maintenance-database", "blue-routing-restored-if-cut-over"],
    requiredCapabilities: ["CREATEDB", "CREATEROLE", "exact-role-marker-verification"],
    failureDisposition: "retry-transactional-role-cleanup-after-green-database-absence-proof",
  },
];
const packageExecutionReport = {
  schemaVersion: 2,
  deploymentModel: "clean-room-blue-green",
  targetEnvironment,
  deploymentId,
  greenDatabasePattern: candidateDatabasePattern,
  sourceContractSha256,
  sourceContractInputs,
  prismaMigrations,
  roleMarker,
  blueDatabaseMutationAllowed: false,
  greenInfrastructureBoundary: "separate encrypted RDS instance or cluster; never the current blue database",
  certificationOnlyFiles: ["50-certification-fixtures.sql"],
  phases: phaseDefinitions.map((phase) => ({
    ...phase,
    fileChecksums: Object.fromEntries(phase.files.map((name) => [name, sha256(files.get(name))])),
  })),
};
const implementationManifest = {
  schemaVersion: 4,
  generatedFrom: ["tables.json", "workflows.json", "command-semantics.json", "runtime-identities.json", "object-ownership-chain.json", "essential-workflow-allowlist.json", "context-boundary-families.json", "backend/prisma/schema.prisma", "backend/prisma/migrations/*/migration.sql"],
  generatedAt: "deterministic-no-wall-clock",
  deploymentModel: "clean-room-blue-green",
  targetEnvironment,
  deploymentId,
  sourceContractSha256,
  sourceContractInputs,
  greenDatabasePattern: candidateDatabasePattern,
  counts: {
    tables: tables.length,
    forceRlsTargets: forceTargets.length,
    migrationOnly: migrationOnly.length,
    certificationCandidateWorkflows: candidateWorkflowIds.size,
    directPolicySlices: slices.length,
    generatedPolicies: policyInventory.length,
    columnPrivilegeCells: grants.reduce((sum, grant) => sum + grant.columns.length, 0),
    prismaMigrations: prismaMigrations.length,
    prismaEnums: prismaEnumNames.length,
    registeredWorkflowCallPaths: registeredCallPathEvidence.workflowCount,
    applicationPathCertifiedWorkflows: registeredCallPathEvidence.summary.applicationPathCertified,
  },
  roles: roleNames,
  roleMarker,
  administrativeExecutor: {
    role: administrativeExecutorRole,
    brokered: true,
    runtimeUseProhibited: true,
    productionActivationBlocked: targetEnvironment === "production",
  },
  roleLifecycle: {
    preExistingManagedRoles: "refuse-before-mutation",
    packageCreation: "unconditional-transactional-create-with-checksum-bound-role-comments",
    cleanup: "only-after-green-database-absence; drop-exact-marked-package-roles",
    legacyStateRestorationSupported: false,
    inPlaceRollbackSupported: false,
  },
  databaseLifecycle: {
    installTarget: "fresh-template0-green-database-only",
    blueMutationAllowed: false,
    failureRollback: ["stop-green-consumers", "prove-no-required-data-accepted", "drop-green-database", "drop-marked-green-roles", "restore-blue-routing-if-needed"],
  },
  prismaMigrations,
  prohibitions: runtimeIdentities.prohibitions,
  ownerModel: ownership.logicalOwnerIdentities,
  blockedDirectProfiles: blockedProfiles,
  workflowCertificationStatus: "pending-application-path-implementation",
  tables: dispositions,
};
const expectedCatalog = {
  schemaVersion: 3,
  deploymentModel: "clean-room-blue-green",
  sourceContractSha256,
  sourceContractInputs,
  forceRls: forceTargets.map((table) => table.physicalTable),
  ownership: tables.map((table) => ({ table: table.physicalTable, expectedOwner: roleNames.owner })),
  prismaMigrationLedgerOwner: roleNames.migration,
  prismaMigrations,
  enumOwnership: prismaEnumNames.map((type) => ({ type, expectedOwner: roleNames.owner })),
  columnPrivileges: grants,
  policies: policyInventory,
  roles: roleSpecs.map((role) => ({ ...role, marker: roleMarker })),
};
const contractOnlyInventory = familiesManifest.families
  .filter((family) => family.automationEligibility === "contract-only")
  .map((family) => ({ familyId: family.id, boundaryClass: family.category, implementationStatus: family.implementationStatus, workflowIds: family.workflowIds || [], sourceCommandRuleIds: family.readWriteCommandRuleIds || [] }));
const contractOnlyWorkflowRows = contractOnlyInventory.flatMap((family) => family.workflowIds.map((workflowId) => ({
  workflowId,
  familyId: family.familyId,
  boundaryClass: family.boundaryClass,
  implementationStatus: family.implementationStatus,
  sourceCommandRuleIds: family.sourceCommandRuleIds,
})));
if (contractOnlyWorkflowRows.length !== EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT || new Set(contractOnlyWorkflowRows.map((row) => row.workflowId)).size !== EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT) throw new Error(`Expected ${EXPECTED_CONTRACT_ONLY_WORKFLOW_COUNT} unique contract-only workflows, found ${contractOnlyWorkflowRows.length}/${new Set(contractOnlyWorkflowRows.map((row) => row.workflowId)).size}`);
const contractOnlyGroups = Object.fromEntries([...new Set(contractOnlyWorkflowRows.map((row) => row.boundaryClass))].sort().map((boundaryClass) => [boundaryClass, contractOnlyWorkflowRows.filter((row) => row.boundaryClass === boundaryClass)]));
const generatedReports = new Map([
  ["full-rls-implementation-manifest.json", implementationManifest],
  ["package-execution-report.json", packageExecutionReport],
  ["contract-only-implementation-inventory.json", { schemaVersion: 2, workflowCount: contractOnlyWorkflowRows.length, groups: contractOnlyGroups, families: contractOnlyInventory }],
  ["workflow-call-path-evidence.json", registeredCallPathEvidence],
  ["expected-catalog-snapshot.json", expectedCatalog],
  ["column-privilege-report.json", { schemaVersion: 2, rows: grants, cells: implementationManifest.counts.columnPrivilegeCells, functionOwnerRows }],
  ["privilege-diff-report.json", { schemaVersion: 3, mode: "clean-room-expected-after-apply", rows: grants, functionOwnerRows: functionOwnerRows.map(({ contracts: _contracts, ...row }) => row), legacyAclRestoration: false }],
  ["ownership-diff-report.json", { schemaVersion: 2, mode: "clean-room-expected-after-apply", rows: expectedCatalog.ownership, legacyOwnershipRestoration: false }],
  ["force-rls-report.json", { schemaVersion: 1, count: forceTargets.length, tables: forceTargets.map((table) => table.physicalTable) }],
  ["policy-inventory-report.json", { schemaVersion: 1, count: policyInventory.length, rows: policyInventory }],
  ["role-lifecycle-report.json", {
    schemaVersion: 5,
    deploymentModel: "clean-room-blue-green",
    sourceContractSha256,
    deploymentId,
    greenDatabasePattern: candidateDatabasePattern,
    roles: roleSpecs.map((role) => ({ ...role, marker: roleMarker })),
    preflight: {
      mutationAllowed: false,
      requires: ["PostgreSQL 18", "exact green database", "zero managed roles", "zero application objects", "zero policies", "zero unexpected grants", "zero default ACLs", "zero other sessions"],
    },
    creation: "all nine roles are created transactionally and marked by this package; reuse is prohibited",
    failureCleanup: "drop the green database from the maintenance database, then transactionally drop only exact marked roles",
    blueDatabase: "never connected to or mutated by the package",
    legacyRoleRestoration: false,
    legacyAclRestoration: false,
    legacyDefaultAclRestoration: false,
    legacyOwnershipRestoration: false,
    dropOwnedAllowed: false,
  }],
]);

fs.rmSync(sqlRoot, { recursive: true, force: true });
fs.mkdirSync(sqlRoot, { recursive: true });
fs.mkdirSync(generatedRoot, { recursive: true });
for (const [name, contents] of files) fs.writeFileSync(path.join(sqlRoot, name), contents);
for (const [name, contents] of generatedReports) fs.writeFileSync(path.join(generatedRoot, name), stable(contents));
const checksumFiles = {
  ...Object.fromEntries([...files].map(([name, contents]) => [name, sha256(contents)])),
  ...Object.fromEntries([...generatedReports].map(([name, contents]) => [name, sha256(stable(contents))])),
};
fs.writeFileSync(path.join(generatedRoot, "checksums.json"), stable({ schemaVersion: 3, algorithm: "sha256", deploymentModel: "clean-room-blue-green", sourceContractSha256, sourceContractInputs, files: checksumFiles }));

console.log(stable({
  targetEnvironment,
  deploymentId,
  deploymentModel: "clean-room-blue-green",
  sourceContractSha256,
  tables: tables.length,
  forceRlsTargets: forceTargets.length,
  directPolicySlices: slices.length,
  generatedPolicies: policyInventory.length,
  columnPrivilegeCells: implementationManifest.counts.columnPrivilegeCells,
  sqlFiles: files.size,
}).trim());
