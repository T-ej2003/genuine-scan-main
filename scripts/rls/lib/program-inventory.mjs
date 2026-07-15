import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import assert from "node:assert/strict";

export const repoRoot = path.resolve(new URL("../../..", import.meta.url).pathname);
export const programDir = path.join(repoRoot, "documents/security/rls-program");
export const schemaPath = path.join(repoRoot, "backend/prisma/schema.prisma");
export const tableManifestPath = path.join(programDir, "tables.json");
export const workflowManifestPath = path.join(programDir, "workflows.json");
export const identityManifestPath = path.join(programDir, "runtime-identities.json");
export const decisionManifestPath = path.join(programDir, "decisions.json");
export const blockedApplyPath = "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql";

export const commands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT", "COUNT", "RAW_SQL"]);
export const surfaces = new Set(["http", "worker", "scheduled", "startup", "cli", "internal"]);
export const boundaries = new Set(["authenticated-context", "pre-auth-security-function", "tenant-admin", "platform-admin", "actor-owned", "restricted-worker", "append-only", "migration-owner", "operator-break-glass", "unresolved"]);
export const categories = new Set(["tenant-owned", "actor-owned", "parent-inherited", "platform-reference", "security-sensitive", "append-only-audit", "operational-system", "migration-only", "intentionally-non-rls"]);

export const readJson = (file, fallback = null) => fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback;
export const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
};
export const rel = (file) => path.relative(repoRoot, file).split(path.sep).join("/");
export const slug = (value) => value.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase();
export const hashId = (prefix, value) => `${prefix}-${crypto.createHash("sha256").update(value).digest("hex").slice(0, 16)}`;

const stripComments = (value) => value.replace(/\/\/.*$/gm, "");
export const parseSchema = (source = fs.readFileSync(schemaPath, "utf8")) => {
  const models = [];
  const modelPattern = /^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm;
  for (const match of stripComments(source).matchAll(modelPattern)) {
    const [, name, body] = match;
    const fields = [];
    let physicalTable = name;
    for (const raw of body.split("\n")) {
      const line = raw.trim();
      const map = line.match(/^@@map\("([^"]+)"\)/);
      if (map) { physicalTable = map[1]; continue; }
      const field = line.match(/^(\w+)\s+([^\s]+)(?:\s+.*)?$/);
      if (!field || line.startsWith("@@")) continue;
      const [, fieldName, rawType] = field;
      const type = rawType.replace(/[?\[\]]/g, "");
      fields.push({ name: fieldName, type, optional: rawType.includes("?"), list: rawType.includes("[]"), relation: /@relation\b/.test(line), attributes: line.slice(field[0].indexOf(rawType) + rawType.length).trim() });
    }
    models.push({ name, physicalTable, fields });
  }
  return models;
};

const scalarTypes = new Set(["String", "Int", "BigInt", "Float", "Decimal", "Boolean", "DateTime", "Json", "Bytes"]);
const securityNames = /(?:User|Credential|Challenge|Token|Invite|Password|Approval|Security|Access|SessionRisk)/;
const auditNames = /(?:Audit|Event|Log|Evidence|Trace|Forensic)/;
const operationalNames = /(?:Job|Checkpoint|Metric|Rollup|Notification|Outbox)/;

const categoryFor = (model) => {
  const names = new Set(model.fields.map((field) => field.name));
  if (securityNames.test(model.name)) return "security-sensitive";
  if (auditNames.test(model.name)) return "append-only-audit";
  if (names.has("userId") && !names.has("licenseeId") && !names.has("orgId")) return "actor-owned";
  if (names.has("licenseeId") || names.has("orgId")) return "tenant-owned";
  if (model.fields.some((field) => field.relation && !field.list)) return "parent-inherited";
  if (operationalNames.test(model.name)) return "operational-system";
  return "platform-reference";
};
const sensitivityFor = (model, category) => category === "security-sensitive" ? "restricted"
  : category === "append-only-audit" ? "high"
    : model.fields.some((field) => /email|phone|ip|address|secret|token|hash|credential/i.test(field.name)) ? "high" : "internal";

export const buildTableManifest = () => {
  const existing = readJson(tableManifestPath, { schemaVersion: 1, tables: [] });
  const previous = new Map(existing.tables.map((table) => [table.id, table]));
  const models = parseSchema();
  const modelNames = new Set(models.map((model) => model.name));
  const tables = models.map((model) => {
    const id = `table-${slug(model.physicalTable)}`;
    const old = previous.get(id) || {};
    const fieldNames = new Set(model.fields.map((field) => field.name));
    const relations = model.fields.filter((field) => field.relation && modelNames.has(field.type)).map((field) => ({ field: field.name, model: field.type }));
    const likelyParents = relations.filter((relation) => !model.fields.find((field) => field.name === relation.field)?.list).map((relation) => `table-${slug(models.find((item) => item.name === relation.model)?.physicalTable || relation.model)}`);
    const category = old.category || categoryFor(model);
    const tenantColumns = ["orgId", "licenseeId", "manufacturerId"].filter((name) => fieldNames.has(name));
    const uncertainOwnership = tenantColumns.length === 0 && !["actor-owned", "append-only-audit", "security-sensitive"].includes(category);
    return {
      ...old,
      id,
      prismaModel: model.name,
      physicalTable: model.physicalTable,
      category,
      sensitivity: old.sensitivity || sensitivityFor(model, category),
      tenantOwnershipColumns: old.tenantOwnershipColumns || tenantColumns,
      parentAuthorizationTable: old.parentAuthorizationTable ?? (category === "parent-inherited" && likelyParents.length === 1 ? likelyParents[0] : null),
      actorOwnershipColumn: old.actorOwnershipColumn ?? (["userId", "actorId", "ownerUserId"].find((name) => fieldNames.has(name)) || null),
      productionRuntimeReaders: old.productionRuntimeReaders || [],
      productionRuntimeWriters: old.productionRuntimeWriters || [],
      requiredCommands: old.requiredCommands || [],
      intendedDatabaseRoles: old.intendedDatabaseRoles || [],
      rlsApplicability: old.rlsApplicability || (category === "intentionally-non-rls" ? "not-applicable" : "candidate-unresolved"),
      currentRlsState: old.currentRlsState || "not-verified-for-production",
      currentForceRlsState: old.currentForceRlsState || "not-verified-for-production",
      policyStatus: old.policyStatus || "not-designed",
      recursionDependencies: old.recursionDependencies || likelyParents,
      unresolvedDecisions: old.unresolvedDecisions || (uncertainOwnership ? ["decision-table-ownership-classification"] : ["decision-policy-command-semantics"]),
      implementationStatus: old.implementationStatus || "inventory-only",
      verificationStatus: old.verificationStatus || "schema-represented-only",
      nonRlsSecurityJustification: category === "intentionally-non-rls" ? (old.nonRlsSecurityJustification || "") : null,
      schemaEvidence: { fields: model.fields, likelyParentChains: likelyParents },
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const result = { schemaVersion: 1, generatedFrom: "backend/prisma/schema.prisma", generatedModelCount: models.length, tables };
  writeJson(tableManifestPath, result);
  return result;
};

const require = createRequire(import.meta.url);
const methodNames = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "create", "createMany", "createManyAndReturn", "update", "updateMany", "updateManyAndReturn", "delete", "deleteMany", "upsert", "count", "aggregate", "groupBy"]);
const rawMethods = new Set(["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"]);
const excludedDirs = new Set(["dist", "node_modules", "tests", "__tests__", "coverage", ".terraform", "generated"]);
const sourceExtensions = /\.(?:[cm]?js|ts)$/;

const walk = (directory, result = []) => {
  if (!fs.existsSync(directory)) return result;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirs.has(entry.name)) continue;
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(file, result);
    else if (sourceExtensions.test(entry.name)) result.push(file);
  }
  return result;
};
const resolveImport = (from, specifier) => {
  if (!specifier.startsWith(".")) return null;
  const base = path.resolve(path.dirname(from), specifier);
  for (const candidate of [base, ...[".ts", ".js", ".mjs", ".cjs"].map((extension) => base + extension), ...["index.ts", "index.js", "index.mjs"].map((name) => path.join(base, name))]) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
};
const scriptEntrypoints = () => {
  const entries = new Set([path.join(repoRoot, "backend/prisma/seed.ts")]);
  for (const [prefix, packageFile] of [[repoRoot, "package.json"], [path.join(repoRoot, "backend"), "backend/package.json"]]) {
    const pkg = readJson(path.join(repoRoot, packageFile), {});
    for (const command of Object.values(pkg.scripts || {})) {
      for (const match of command.matchAll(/(?:^|[\s;])(?:node|tsx)\s+([^\s"']+\.(?:[cm]?js|ts))/g)) {
        const file = path.resolve(prefix, match[1]);
        if (fs.existsSync(file) && !/(?:^|[\\/])tests?(?:[\\/]|$)/.test(file)) entries.add(file);
      }
    }
  }
  return entries;
};
const reachableSourceFiles = () => {
  const all = walk(path.join(repoRoot, "backend/src"));
  const allowed = new Set(all);
  const roots = [path.join(repoRoot, "backend/src/index.ts"), path.join(repoRoot, "backend/src/worker.ts"), ...scriptEntrypoints()];
  const reachable = new Set();
  const visit = (file) => {
    if (!file || reachable.has(file) || !fs.existsSync(file)) return;
    reachable.add(file);
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(/(?:import[\s\S]*?from\s*|import\s*\(|require\s*\()\s*["']([^"']+)["']/g)) {
      const resolved = resolveImport(file, match[1]);
      if (resolved && (allowed.has(resolved) || scriptEntrypoints().has(resolved))) visit(resolved);
    }
  };
  roots.forEach(visit);
  return { reachable, all, roots: new Set(roots) };
};
const detectRegistrations = () => {
  const routes = [];
  for (const file of [...walk(path.join(repoRoot, "backend/src/routes")), path.join(repoRoot, "backend/src/app.ts")]) {
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(/\b(?:router|app)\.(get|post|put|patch|delete|use)\s*\(\s*(["'`])([^"'`]+)\2/g)) {
      routes.push({ method: match[1].toUpperCase(), path: match[3], source: `${rel(file)}:${source.slice(0, match.index).split("\n").length}` });
    }
  }
  const packageScripts = [];
  for (const packageFile of ["package.json", "backend/package.json"]) {
    const pkg = readJson(path.join(repoRoot, packageFile), {});
    for (const [name, command] of Object.entries(pkg.scripts || {})) packageScripts.push({ packageFile, name, command });
  }
  return { routes: routes.sort((a, b) => a.source.localeCompare(b.source) || a.method.localeCompare(b.method)), packageScripts: packageScripts.sort((a, b) => `${a.packageFile}:${a.name}`.localeCompare(`${b.packageFile}:${b.name}`)), startupEntrypoints: ["backend/src/index.ts", "backend/src/worker.ts"] };
};
const functionName = (ts, node) => {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionDeclaration(current) && current.name) return current.name.text;
    if ((ts.isArrowFunction(current) || ts.isFunctionExpression(current)) && ts.isVariableDeclaration(current.parent)) return current.parent.name.getText();
    if (ts.isMethodDeclaration(current) && current.name) return current.name.getText();
  }
  return "module";
};
const operationFor = (method) => method === "upsert" ? "UPSERT" : method === "count" ? "COUNT" : method.startsWith("create") ? "INSERT" : method.startsWith("update") ? "UPDATE" : method.startsWith("delete") ? "DELETE" : "SELECT";
const surfaceFor = (file, fn) => {
  const value = `${rel(file)}:${fn}`;
  if (file === path.join(repoRoot, "backend/src/worker.ts") || /(?:worker|processor|consumer|queue)/i.test(value)) return "worker";
  if (/(?:scheduler|scheduled|cron|startCompliancePackScheduler)/i.test(value)) return "scheduled";
  if (file === path.join(repoRoot, "backend/src/index.ts") || /(?:bootstrap|startup|superAdminBootstrap)/i.test(value)) return "startup";
  if (rel(file).startsWith("backend/scripts/") || rel(file) === "backend/prisma/seed.ts" || rel(file).startsWith("scripts/")) return "cli";
  if (/backend\/src\/(?:controllers|routes|middleware)\//.test(rel(file))) return "http";
  return "internal";
};
const boundaryFor = (file, fn, surface) => {
  const value = `${rel(file)}:${fn}`;
  if (/(?:login|passwordReset|emailVerification|acceptInvite|getInvitePreview|authBootstrap)/i.test(value)) return "pre-auth-security-function";
  if (surface === "worker" || surface === "scheduled") return "restricted-worker";
  if (surface === "startup") return "migration-owner";
  if (surface === "cli" && /(?:break-glass|repair|reset|create-super-admin)/i.test(value)) return "operator-break-glass";
  if (/(?:platform|superAdmin|licenseeController)/i.test(value)) return "platform-admin";
  if (/(?:account|self|My)/i.test(value)) return "actor-owned";
  if (surface === "http") return "authenticated-context";
  return "unresolved";
};

export const scanProductionAccess = () => {
  const ts = require(path.join(repoRoot, "backend/node_modules/typescript"));
  const models = parseSchema();
  const delegates = new Map(models.map((model) => [model.name[0].toLowerCase() + model.name.slice(1), model]));
  const physical = new Map(models.map((model) => [model.physicalTable.toLowerCase(), model]));
  const { reachable, all, roots } = reachableSourceFiles();
  const active = [...new Set([...reachable, ...scriptEntrypoints()])].sort();
  const accesses = [];
  const scanFile = (file, production) => {
    const source = fs.readFileSync(file, "utf8");
    const ast = ts.createSourceFile(rel(file), source, ts.ScriptTarget.Latest, true);
    const record = (node, model, method, command, evidence) => {
      const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
      const fn = functionName(ts, node);
      const surface = surfaceFor(file, fn);
      const locator = `${rel(file)}:${line}:${model.name}:${method}`;
      accesses.push({ id: hashId("access", locator), sourceFile: rel(file), line, function: fn, tableId: `table-${slug(model.physicalTable)}`, prismaModel: model.name, command, method, executionSurface: surface, production, registrationEvidence: roots.has(file) ? "registered-entrypoint" : reachable.has(file) ? "reachable-from-registered-entrypoint" : "unregistered", evidence: evidence.replace(/\s+/g, " ").slice(0, 350) });
    };
    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const target = node.expression.expression;
        if (methodNames.has(method) && ts.isPropertyAccessExpression(target) && delegates.has(target.name.text)) record(node, delegates.get(target.name.text), method, operationFor(method), node.getText(ast));
        if (rawMethods.has(method)) {
          const raw = node.getText(ast);
          for (const [name, model] of physical) if (new RegExp(`(?:\\b|[\"'])${name}(?:\\b|[\"'])`, "i").test(raw)) record(node, model, method, "RAW_SQL", raw);
        }
      }
      if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) && rawMethods.has(node.tag.name.text)) {
        const raw = node.getText(ast);
        for (const [name, model] of physical) if (new RegExp(`(?:\\b|[\"'])${name}(?:\\b|[\"'])`, "i").test(raw)) record(node, model, node.tag.name.text, "RAW_SQL", raw);
      }
      ts.forEachChild(node, visit);
    };
    visit(ast);
  };
  active.forEach((file) => scanFile(file, true));
  const unregistered = all.filter((file) => !reachable.has(file));
  unregistered.forEach((file) => scanFile(file, false));
  return { accesses: accesses.filter((item) => item.production).sort((a, b) => a.id.localeCompare(b.id)), unregisteredAccesses: accesses.filter((item) => !item.production).sort((a, b) => a.id.localeCompare(b.id)), activeFiles: active.map(rel), unregisteredFiles: unregistered.map(rel), registrations: detectRegistrations() };
};

const displayName = (fn) => fn === "module" ? "Module database access" : fn.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/^./, (letter) => letter.toUpperCase());
export const buildWorkflowManifest = () => {
  const scan = scanProductionAccess();
  const existing = readJson(workflowManifestPath, { schemaVersion: 1, workflows: [] });
  const previous = new Map(existing.workflows.map((workflow) => [workflow.id, workflow]));
  const groups = new Map();
  for (const access of scan.accesses) {
    const key = `${access.executionSurface}:${access.sourceFile}:${access.function}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(access);
  }
  const workflows = [...groups.entries()].map(([key, accesses]) => {
    const first = accesses[0];
    const id = `workflow-${slug(key)}`;
    const old = previous.get(id) || {};
    const boundary = old.authorizationBoundaryType || boundaryFor(path.join(repoRoot, first.sourceFile), first.function, first.executionSurface);
    const tableCommands = [...new Set(accesses.map((access) => `${access.tableId}:${access.command}`))].sort().map((value) => { const index = value.lastIndexOf(":"); return { tableId: value.slice(0, index), commands: [value.slice(index + 1)] }; });
    const mergedCommands = [...new Map(tableCommands.map((item) => [item.tableId, { tableId: item.tableId, commands: tableCommands.filter((candidate) => candidate.tableId === item.tableId).flatMap((candidate) => candidate.commands).sort() }])).values()];
    const preAuth = boundary === "pre-auth-security-function";
    const background = ["worker", "scheduled"].includes(first.executionSurface);
    const systemSurface = ["startup", "cli"].includes(first.executionSurface);
    return {
      ...old,
      id,
      name: old.name || displayName(first.function),
      entryPoint: old.entryPoint || `${first.executionSurface}:${first.function}`,
      executionSurface: first.executionSurface,
      authenticationStage: old.authenticationStage || (preAuth ? "pre-authentication" : background || ["cli", "startup"].includes(first.executionSurface) ? "system" : "authenticated"),
      actorClasses: old.actorClasses || (background ? ["system-job"] : preAuth ? ["anonymous-or-partially-authenticated"] : first.executionSurface === "cli" ? ["operator"] : ["authenticated-user"]),
      canonicalSourceFiles: [...new Set(accesses.map((access) => access.sourceFile))].sort(),
      tablesTouched: mergedCommands.map((item) => item.tableId),
      commandsPerTable: mergedCommands,
      tenantScopeRule: old.tenantScopeRule || "unresolved; must be approved before implementation",
      contextRequirements: old.contextRequirementsSource === "human-reviewed" ? old.contextRequirements : (preAuth ? ["named narrow SECURITY DEFINER function or approved empty-context denial"] : background ? ["approved restricted system identity", "job-bound tenant scope"] : systemSurface ? ["approved non-owning system or operator identity", "command-bound scope"] : ["transaction-local canonical actor context"]),
      contextRequirementsSource: old.contextRequirementsSource || "generated-conservative",
      authorizationBoundaryType: boundary,
      expectedAllowedScenarios: old.expectedAllowedScenarios || ["Approved actor or system identity performs the named command within its recorded scope."],
      expectedDeniedScenarios: old.expectedDeniedScenarios || ["Missing, forged, stale, or cross-tenant context is denied."],
      preAuthSystemRequirements: old.preAuthSystemRequirements || (preAuth ? ["No direct table fallback; exact function grants and owner must be certified."] : background || systemSurface ? ["No superuser, ownership execution, or BYPASSRLS."] : []),
      currentDirectPrismaUsage: accesses.map((access) => access.id),
      currentCompatibilityStatus: old.currentCompatibilityStatus || "blocked-until-context-and-policy-proof",
      implementationStatus: old.implementationStatus || "inventory-only",
      requiredUnitTests: old.requiredUnitTests || ["Allowed and denied command contract for this canonical workflow."],
      requiredDisposablePostgresqlTests: old.requiredDisposablePostgresqlTests || ["Exact role, context, command, cross-tenant denial, and empty-context denial."],
      unresolvedDecisions: old.unresolvedDecisions || [background ? "decision-worker-identity-model" : preAuth ? "decision-pre-auth-boundary" : "decision-policy-command-semantics"],
      supportingEvidence: accesses.map((access) => ({ accessId: access.id, source: `${access.sourceFile}:${access.line}`, registration: access.registrationEvidence })),
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const result = { schemaVersion: 1, groupingRule: "One workflow per execution surface, canonical source file, and containing function; repeated table calls within that function remain one functional workflow.", generatedEvidence: { productionAccessSites: scan.accesses.length, testPathsExcluded: ["backend/tests", "scripts/tests"], registrations: scan.registrations, unregisteredPotentiallyDeadAccesses: scan.unregisteredAccesses, unregisteredFiles: scan.unregisteredFiles }, workflows };
  writeJson(workflowManifestPath, result);

  const tableManifest = readJson(tableManifestPath);
  for (const table of tableManifest.tables) {
    const touching = workflows.filter((workflow) => workflow.tablesTouched.includes(table.id));
    table.productionRuntimeReaders = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.some((command) => ["SELECT", "COUNT", "RAW_SQL"].includes(command))).map((workflow) => workflow.id);
    table.productionRuntimeWriters = touching.filter((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands.some((command) => ["INSERT", "UPDATE", "DELETE", "UPSERT", "RAW_SQL"].includes(command))).map((workflow) => workflow.id);
    table.requiredCommands = [...new Set(touching.flatMap((workflow) => workflow.commandsPerTable.find((item) => item.tableId === table.id)?.commands || []))].sort();
  }
  writeJson(tableManifestPath, tableManifest);

  const decisionManifest = readJson(decisionManifestPath);
  if (decisionManifest) {
    for (const decision of decisionManifest.decisions) {
      decision.affectedWorkflows = workflows.filter((workflow) => workflow.unresolvedDecisions.includes(decision.id)
        || decision.id === "decision-runtime-role-split"
        || (decision.id === "decision-operator-administration" && workflow.authorizationBoundaryType === "operator-break-glass")).map((workflow) => workflow.id);
      decision.affectedTables = tableManifest.tables.filter((table) => table.unresolvedDecisions.includes(decision.id)
        || decision.id === "decision-object-ownership-chain"
        || decision.affectedWorkflows.some((workflowId) => table.productionRuntimeReaders.includes(workflowId) || table.productionRuntimeWriters.includes(workflowId))).map((table) => table.id);
    }
    writeJson(decisionManifestPath, decisionManifest);
  }
  return result;
};

export const manifests = () => ({ tables: readJson(tableManifestPath), workflows: readJson(workflowManifestPath), identities: readJson(identityManifestPath), decisions: readJson(decisionManifestPath) });
export const validateRuntimeIdentities = (manifest, decisionManifest) => {
  const identities = manifest.identities;
  const byId = new Map(identities.map((identity) => [identity.id, identity]));
  const suffixes = new Map([
    ["identity-authenticated-app", "app"],
    ["identity-restricted-read", "rls_read"],
    ["identity-pre-auth-app", "preauth"],
    ["identity-worker", "worker"],
    ["identity-scheduled-job", "scheduled"],
    ["identity-migration", "migration"],
    ["identity-table-owner", "owner"],
    ["identity-auth-function-owner", "auth_owner"],
    ["identity-staging-operator-admin", "operator"],
  ]);
  assert.equal(identities.length, 10, "exactly ten logical runtime identities are required");
  for (const [id, suffix] of suffixes) {
    const identity = byId.get(id);
    assert(identity, `${id} is missing`);
    assert.equal(identity.environmentRoleNames?.development, `mscqr_dev_${suffix}`, `${id} development role name is invalid`);
    assert.equal(identity.environmentRoleNames?.staging, `mscqr_staging_${suffix}`, `${id} staging role name is invalid`);
    assert.equal(identity.environmentRoleNames?.production, `mscqr_prod_${suffix}`, `${id} production role name is invalid`);
  }
  for (const identity of identities) {
    assert.equal(identity.superuser, false, `${identity.id} requests superuser`);
    assert.equal(identity.mayUseBypassRls, false, `${identity.id} requests BYPASSRLS`);
    assert.equal(identity.maySetRole, false, `${identity.id} may SET ROLE`);
    assert(identity.credentialSource?.trim(), `${identity.id} credential source is missing`);
    assert(identity.rotationExpectation?.trim(), `${identity.id} rotation expectation is missing`);
    assert(identity.securityDefinerExecution?.trim(), `${identity.id} SECURITY DEFINER rule is missing`);
    assert(identity.environmentRoleNames && ["development", "staging", "production"].every((environment) => identity.environmentRoleNames[environment]?.trim()), `${identity.id} environment role-name patterns are incomplete`);
    if (identity.loginExpectation !== "NOLOGIN") assert.equal(identity.mayOwnProtectedTables, false, `${identity.id} runtime identity may own protected tables`);
  }
  for (const id of ["identity-table-owner", "identity-auth-function-owner"]) assert.equal(byId.get(id).loginExpectation, "NOLOGIN", `${id} owner role must be NOLOGIN`);
  assert.equal(byId.get("identity-table-owner").mayOwnProtectedTables, true, "table owner must own protected tables");
  assert.equal(byId.get("identity-auth-function-owner").mayOwnProtectedTables, false, "auth_owner must not own application tables");

  const credentialIds = ["identity-authenticated-app", "identity-pre-auth-app", "identity-worker", "identity-migration"];
  assert.equal(new Set(credentialIds.map((id) => byId.get(id).credentialSource)).size, credentialIds.length, "app, pre-auth, worker, and migration must not share credential sources");
  assert.notEqual(byId.get("identity-worker").credentialSource, byId.get("identity-scheduled-job").credentialSource, "worker and scheduled credentials must remain distinct");

  const preauth = byId.get("identity-pre-auth-app");
  assert.equal(preauth.tablePrivilegeMode, "none", "pre-auth must have no direct table privileges");
  assert.deepEqual([...preauth.allowedCommands].sort(), ["CONNECT", "EXECUTE", "USAGE"], "pre-auth may only CONNECT, use app_auth, and execute exact functions");
  assert.deepEqual(preauth.allowedSchemas, ["app_auth"], "pre-auth may not receive unrestricted public schema access");
  const restrictedRead = byId.get("identity-restricted-read");
  assert(!restrictedRead.allowedCommands.some((command) => ["INSERT", "UPDATE", "DELETE", "UPSERT", "CREATE", "ALTER", "DROP"].includes(command)), "restricted read has write or DDL privileges");

  const app = byId.get("identity-authenticated-app");
  assert(!app.allowedSchemas.includes("app_auth"), "authenticated app must not receive unrestricted app_auth access");
  assert.match(app.securityDefinerExecution, /authenticated helper signatures only/i, "authenticated app helper execution is too broad");

  const breakGlass = byId.get("identity-production-break-glass");
  assert(breakGlass, "production break-glass identity is missing");
  assert.equal(breakGlass.environmentRoleNames.development, "not-applicable-production-only");
  assert.equal(breakGlass.environmentRoleNames.staging, "not-applicable-production-only");
  assert.match(breakGlass.environmentRoleNames.production, /^mscqr_prod_breakglass_<incident>_<nonce>$/, "production break-glass must use an ephemeral role-name pattern");
  assert.equal(breakGlass.loginExpectation, "EPHEMERAL_LOGIN", "production break-glass must not be a standing LOGIN role");
  assert.equal(breakGlass.standingCredential, false, "production break-glass must not have a standing credential");
  assert.match(breakGlass.credentialSource, /ephemeral.*broker/i, "production break-glass must be broker-issued and ephemeral");
  for (const requirement of ["dual approval", "strong MFA", "incident or ticket", "explicit expiry", "command allowlist", "immutable audit transcript", "automatic revocation"]) assert(breakGlass.approvalRequirements.includes(requirement), `production break-glass lacks ${requirement}`);

  const decision = decisionManifest.decisions.find((item) => item.id === "decision-runtime-role-split");
  assert.equal(decision?.status, "resolved", "decision-runtime-role-split may be resolved only after the complete role model validates");
};
export const sharedApplyIsBlocked = () => {
  const source = fs.readFileSync(path.join(repoRoot, blockedApplyPath), "utf8");
  return source.indexOf("RAISE EXCEPTION 'Shared batch RLS apply blocked") >= 0 && source.indexOf("RAISE EXCEPTION 'Shared batch RLS apply blocked") < source.indexOf("BEGIN;");
};
