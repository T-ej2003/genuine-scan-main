#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { manifests, programDir, repoRoot } from "./lib/program-inventory.mjs";

export const contextBoundaryFamiliesPath = path.join(programDir, "context-boundary-families.json");
export const contextBoundaryReportPath = path.join(programDir, "CONTEXT_BOUNDARY_MIGRATION_REPORT.md");
export const contextBoundaryReadBatchPath = path.join(programDir, "context-boundary-read-batch.json");
export const canonicalContextKeys = [
  "app.user_id",
  "app.role",
  "app.organization_id",
  "app.licensee_id",
  "app.manufacturer_id",
  "app.auth_assurance",
  "app.request_id",
  "app.purpose",
];

const categoryOrder = [
  "simple tenant-scoped reads",
  "simple actor-scoped reads",
  "platform-admin bounded reads",
  "tenant-scoped creates",
  "tenant-scoped updates",
  "lifecycle/state transitions",
  "append-only audit writes",
  "multi-table atomic mutations",
  "batch/QR lifecycle",
  "print lifecycle",
  "account and security mutations",
  "incident/governance workflows",
  "public or anonymous workflows",
  "pre-auth function-backed workflows",
  "worker/scheduled workflows",
  "operator-boundary workflows",
  "CLI/manual workflows",
  "startup/bootstrap workflows",
  "migration-only workflows",
  "prohibited or legacy workflows",
];
const order = new Map(categoryOrder.map((value, index) => [value, index]));
const unique = (values) => [...new Set(values.filter(Boolean))].sort();
const slug = (value) => String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex").slice(0, 10);
const sourceKind = (files, segment) => unique(files.filter((file) => file.includes(segment)));
const allCommands = (workflow) => unique(workflow.commandsPerTable.flatMap((item) => item.commands));

const governingBoundary = (workflow) => {
  if (workflow.preAuthBoundary?.boundaryMode === "exact-security-definer-function") return workflow.preAuthBoundary.functionId;
  if (workflow.workerBoundaryId) return workflow.workerBoundaryId;
  if (workflow.operatorBoundaryId) return workflow.operatorBoundaryId;
  if (workflow.systemBoundaryId) return workflow.systemBoundaryId;
  if (workflow.authorizationBoundaryType === "migration-owner") return "identity-migration";
  return null;
};

const categoryFor = (workflow, rules, tables) => {
  const text = `${workflow.id} ${workflow.canonicalSourceFiles.join(" ")}`.toLowerCase();
  const commands = allCommands(workflow);
  const touched = workflow.tablesTouched.map((id) => tables.get(id)).filter(Boolean);
  const mutation = commands.some((command) => command !== "SELECT");
  if (workflow.operatorBoundaryId) return /prohibited/.test(workflow.operatorBoundaryId) ? "prohibited or legacy workflows" : "operator-boundary workflows";
  if (workflow.preAuthBoundary?.boundaryMode === "exact-security-definer-function") return "pre-auth function-backed workflows";
  if (workflow.workerBoundaryId || ["worker", "scheduled"].includes(workflow.executionSurface)) return "worker/scheduled workflows";
  if (workflow.authorizationBoundaryType === "migration-owner") return "migration-only workflows";
  if (workflow.executionSurface === "startup") return "startup/bootstrap workflows";
  if (workflow.executionSurface === "cli") return "CLI/manual workflows";
  if (/batch|qr|allocation|verification|scan/.test(text)) return "batch/QR lifecycle";
  if (/print|printer|zebra|label/.test(text)) return "print lifecycle";
  if (/auth|account|password|session|mfa|webauthn|invite|user/.test(text) || touched.some((table) => table.primaryCategory === "security-sensitive")) return "account and security mutations";
  if (/incident|governance|audit|forensic|compliance|retention|policy/.test(text)) return mutation ? "incident/governance workflows" : "simple tenant-scoped reads";
  if (workflow.authenticationStage === "pre-authentication" || workflow.commandActorClasses?.includes("anonymous")) return "public or anonymous workflows";
  if (!mutation) {
    if (workflow.commandActorClasses?.every((actor) => actor === "platform-admin")) return "platform-admin bounded reads";
    if (workflow.authorizationBoundaryType === "actor-owned" || touched.every((table) => table.primaryCategory === "actor-owned")) return "simple actor-scoped reads";
    return "simple tenant-scoped reads";
  }
  if (touched.some((table) => table.appendOnly) && commands.every((command) => ["INSERT", "SELECT"].includes(command))) return "append-only audit writes";
  if (rules.some((rule) => rule.lifecycleColumns?.length)) return "lifecycle/state transitions";
  if (workflow.tablesTouched.length > 1 || commands.length > 1) return "multi-table atomic mutations";
  if (commands.every((command) => command === "INSERT")) return "tenant-scoped creates";
  if (commands.every((command) => command === "UPDATE")) return "tenant-scoped updates";
  return "multi-table atomic mutations";
};

const riskFor = (category, workflow, rules) => {
  if (["pre-auth function-backed workflows", "operator-boundary workflows", "migration-only workflows", "account and security mutations", "prohibited or legacy workflows"].includes(category)) return "critical";
  if (["worker/scheduled workflows", "batch/QR lifecycle", "print lifecycle", "lifecycle/state transitions", "multi-table atomic mutations"].includes(category) || rules.some((rule) => rule.requiresNamedFunction)) return "high";
  if (workflow.commandActorClasses?.includes("platform-admin") || allCommands(workflow).some((command) => command !== "SELECT")) return "medium";
  return "low";
};

const workflowDisposition = (workflow, rules) => {
  if (workflow.contextBoundaryStatus === "implemented") return { eligibility: "implemented", status: "implemented", blockers: [] };
  const boundaryId = governingBoundary(workflow);
  if (boundaryId) return { eligibility: "contract-only", status: "contract-ready", blockers: [] };
  if (workflow.contextBoundaryBlockers?.length) return { eligibility: "blocked", status: "blocked", blockers: workflow.contextBoundaryBlockers };
  const evidence = workflow.contextBoundaryPlanningEvidence || {};
  const blockers = [];
  if (/unresolved/i.test(workflow.tenantScopeRule || "")) blockers.push({ code: "unreviewed-scope", reason: "The workflow tenant-scope rule remains generated/unreviewed.", remediation: "Trace the registered caller and record a human-reviewed tenant, actor or bounded platform scope before editing code." });
  if (workflow.authorizationBoundaryType === "unresolved") blockers.push({ code: "unresolved-boundary", reason: "The workflow authorization-boundary type is unresolved.", remediation: "Reconcile middleware, actor classes and command rules into one approved boundary type." });
  if (workflow.executionSurface === "internal" && evidence.registeredRootCallChainVerified !== true) blockers.push({ code: "unverified-root-call-chain", reason: "The internal function is not linked to one verified root transaction in the manifest.", remediation: "Trace every registered caller and group it with the owning HTTP/system transaction before propagating a transaction client." });
  if (rules.some((rule) => rule.requiresNamedFunction)) blockers.push({ code: "named-function-prerequisite", reason: "At least one command rule requires a named function boundary.", remediation: "Implement and certify the exact approved function contract before replacing ordinary Prisma access." });
  if (allCommands(workflow).some((command) => command !== "SELECT") && evidence.databaseConcurrencyVerified !== true) blockers.push({ code: "mutation-concurrency-proof", reason: "The mutation lacks family-level database concurrency and replay proof.", remediation: "Trace lifecycle, immutable columns, idempotency and row-lock/CAS/unique-constraint behavior before implementation." });
  if (["startup", "cli", "worker", "scheduled"].includes(workflow.executionSurface)) blockers.push({ code: "noninteractive-identity-boundary", reason: "The non-interactive workflow has no exact governing boundary ID.", remediation: "Map it to the approved migration, operator, worker or scheduled identity contract; never synthesize human context." });
  if (evidence.protectedQueryTraceComplete !== true || evidence.sameTransactionFeasible !== true || evidence.focusedTestsDeterministic !== true) blockers.push({ code: "unverified-execution-path", reason: "Canonical access sites exist, but protected-query coverage, same-transaction propagation and deterministic testability are not all proven.", remediation: "Trace middleware, controller, service and repository callers; record the complete query trace and add focused ordering/global-client tests." });
  return blockers.length
    ? { eligibility: "blocked", status: "blocked", blockers }
    : { eligibility: "auto-implementable", status: "planned", blockers: [] };
};

const implementationStrategy = (category, disposition, boundaryIds) => {
  if (disposition === "implemented") return "Retain the reviewed transaction-client-only service and focused contract tests; do not broaden the boundary.";
  if (disposition === "contract-only") return `Use only the governing ${boundaryIds.join(", ")} contract; do not install ordinary authenticated context.`;
  if (category.includes("reads")) return "After blocker resolution, install canonical context once and move bounded count/list/enrichment reads into one explicit-projection transaction service.";
  return "After blocker resolution, move the exact mutation, concurrency guard and immutable attribution into one canonical transaction without changing ownership or lifecycle semantics.";
};

const testStrategy = (category, disposition) => disposition === "contract-only"
  ? "Run the governing boundary's existing contract and mutation tests; PostgreSQL implementation remains separately certified."
  : category.includes("reads")
    ? "Exercise own/foreign/blank scope, assurance, filter narrowing, shared transaction/snapshot, explicit projection, redaction and global-client rejection."
    : "Exercise own/foreign/blank scope, immutable columns, lifecycle denial, database concurrency, idempotent replay, atomic attribution and global-client rejection.";

const writeReport = (manifest) => {
  const count = (predicate) => manifest.families.filter(predicate).reduce((total, family) => total + family.workflowIds.length, 0);
  const baseline = new Set(manifest.baselineImplementedWorkflowIds);
  const newlyImplemented = manifest.families.filter((family) => family.implementationStatus === "implemented").flatMap((family) => family.workflowIds).filter((id) => !baseline.has(id)).length;
  const blockerCounts = {};
  for (const family of manifest.families) for (const blocker of family.blockers) blockerCounts[blocker.code] = (blockerCounts[blocker.code] || 0) + family.workflowIds.length;
  const lines = [
    "# Context Boundary Migration Report",
    "",
    "This deterministic pass groups every canonical workflow and fails closed where execution-path evidence is insufficient. It changes no RLS state, SQL policy, role, database or infrastructure.",
    "",
    "## Outcome",
    "",
    `- Canonical workflows: ${manifest.workflowCount}`,
    `- Families: ${manifest.familyCount}`,
    `- Already implemented: ${manifest.baselineImplementedWorkflowIds.length}`,
    `- Newly implemented in this pass: ${newlyImplemented}`,
    `- Contract-only: ${count((family) => family.automationEligibility === "contract-only")}`,
    `- Blocked: ${count((family) => family.automationEligibility === "blocked")}`,
    `- Auto-implementable but pending: ${count((family) => family.automationEligibility === "auto-implementable")}`,
    `- PostgreSQL certification pending: ${manifest.families.filter((family) => family.implementationStatus === "implemented").reduce((total, family) => total + family.workflowIds.length, 0)}`,
    "",
    "No remaining ordinary workflow was auto-edited: the inventory does not yet prove both a human-reviewed scope and complete root-to-repository transaction propagation. That is a safety stop, not a compatibility claim.",
    "",
    "## Blockers",
    "",
    "| Blocker code | Affected workflows | Required remediation |",
    "|---|---:|---|",
  ];
  for (const code of Object.keys(blockerCounts).sort()) {
    const blocker = manifest.families.flatMap((family) => family.blockers).find((item) => item.code === code);
    lines.push(`| ${code} | ${blockerCounts[code]} | ${blocker.remediation} |`);
  }
  lines.push("", "## Families", "", "| Family | Category | Workflows | Risk | Eligibility | Status | Governing boundary/blocker |", "|---|---|---:|---|---|---|---|");
  for (const family of manifest.families) lines.push(`| ${family.id} | ${family.category} | ${family.workflowIds.length} | ${family.riskLevel} | ${family.automationEligibility} | ${family.implementationStatus} | ${[...family.governingBoundaryIds, ...family.blockers.map((item) => item.id)].join(", ") || "none"} |`);
  if (fs.existsSync(contextBoundaryReadBatchPath)) {
    const batch = JSON.parse(fs.readFileSync(contextBoundaryReadBatchPath, "utf8"));
    lines.push(
      "",
      "## Bounded read-only batch",
      "",
      `- Families considered: ${batch.selectionTotals.familiesConsidered}`,
      `- Workflows considered: ${batch.selectionTotals.workflowsConsidered}`,
      `- Families reclassified: ${batch.selectionTotals.reclassifiedFamilies}`,
      `- Families split: ${batch.selectionTotals.splitFamilies}`,
      `- Child families created: ${batch.selectionTotals.childFamiliesCreated}`,
      `- Workflows implemented: ${batch.selectionTotals.newlyImplementedWorkflows}`,
      `- Workflows retained as blocked: ${batch.selectionTotals.blockedWorkflows}`,
      "- Special identities remain contract-only; no human context was synthesized.",
      "- Split and blocked entries retain exact root, scope, command and product-decision evidence.",
      "- The four implemented programme workflows remain pending disposable PostgreSQL certification.",
    );
  }
  lines.push(
    "",
    "## Shared primitives",
    "",
    "- `withCanonicalDbContext`: validated transaction-local context and optional Prisma isolation level.",
    "- Transaction-client-only service pattern: completed audit CSV, fraud-report and audit-log services.",
    "- `redactAuditDetails`: bounded recursive secret-key redaction.",
    "- Focused fake-transaction tests: ordering, same-client enforcement and global-client rejection.",
    "",
    "## Recommended implementation and commit groups",
    "",
    "1. Resolve and implement simple tenant/actor reads by registered HTTP root and shared transaction service.",
    "2. Implement bounded platform-admin reads only after purpose and scope evidence is attached.",
    "3. Implement append-only writes and simple creates/updates with immutable attribution and database concurrency proof.",
    "4. Review batch/QR and print lifecycle families separately; do not combine their state machines.",
    "5. Keep pre-auth, worker/scheduled, operator and migration contracts in separate implementation groups.",
    "6. Certify each completed group against disposable PostgreSQL before any staging activation work.",
    "",
    "No giant repository, service factory, generated application rewrite, policy SQL or database action was introduced.",
    ""
  );
  fs.writeFileSync(contextBoundaryReportPath, lines.join("\n"));
};

export const buildContextBoundaryPlan = () => {
  const { workflows, commandSemantics, tables, workerBoundaries, operatorBoundaries, preAuthFunctions, systemBoundaries, manufacturerBootstrapBoundary, platformReadScopeBoundary, policyAlertActorCeiling } = manifests();
  const existing = fs.existsSync(contextBoundaryFamiliesPath) ? JSON.parse(fs.readFileSync(contextBoundaryFamiliesPath, "utf8")) : null;
  const baselineImplementedWorkflowIds = existing?.baselineImplementedWorkflowIds || workflows.workflows.filter((workflow) => workflow.contextBoundaryStatus === "implemented").map((workflow) => workflow.id).sort();
  const rules = new Map(commandSemantics.rules.map((rule) => [rule.id, rule]));
  const tableMap = new Map(tables.tables.map((table) => [table.id, table]));
  const systemBoundaryMap = new Map(systemBoundaries.boundaries.map((boundary) => [boundary.id, boundary]));
  const groups = new Map();
  for (const workflow of workflows.workflows) {
    const workflowRules = workflow.commandRuleIds.map((id) => rules.get(id)).filter(Boolean);
    const baseCategory = categoryFor(workflow, workflowRules, tableMap);
    const split = workflow.contextBoundaryFamilySplit || null;
    const disposition = workflowDisposition(workflow, workflowRules);
    const boundaryId = governingBoundary(workflow);
    const systemBoundary = systemBoundaryMap.get(boundaryId);
    const category = split?.category || systemBoundary?.familyCategory || baseCategory;
    const implementedFamily = workflow.implementationFamilyId || (workflow.id.includes("export-logs-csv") || workflow.id.endsWith("get-logs") ? "family-audit-read-context" : workflow.id.endsWith("get-fraud-reports") ? "family-fraud-report-read" : null);
    const source = workflow.canonicalSourceFiles[0] || "manifest-only";
    const signature = [baseCategory, source, workflow.authorizationBoundaryType, allCommands(workflow).join("+"), unique(workflow.commandActorClasses || []).join("+"), unique(workflow.requiredAssurance || []).join("+"), ...(workflow.platformReadScopeBoundaryId ? [workflow.platformReadScopeClass, workflow.platformReadExecutionBoundary] : []), ...(workflow.policyAlertActorCeilingBoundaryId ? [workflow.policyAlertClass, workflow.policyAlertExecutionBoundary] : [])].join("|");
    const defaultFamilyId = implementedFamily || (boundaryId ? `family-contract-${slug(boundaryId)}` : `family-${slug(baseCategory).slice(0, 32)}-${slug(path.basename(source, path.extname(source))).slice(0, 32)}-${digest(signature)}`);
    const key = split ? `family-split-${slug(path.basename(source, path.extname(source))).slice(0, 24)}-${slug(split.semanticKey).slice(0, 36)}-${digest(`${split.parentFamilyId}|${split.semanticKey}`)}` : defaultFamilyId;
    if (!groups.has(key)) groups.set(key, { category, workflows: [], dispositions: [], split });
    groups.get(key).workflows.push(workflow);
    groups.get(key).dispositions.push(disposition);
  }
  const families = [...groups.entries()].map(([id, group]) => {
    const familyWorkflows = group.workflows.sort((a, b) => a.id.localeCompare(b.id));
    const files = unique(familyWorkflows.flatMap((workflow) => workflow.canonicalSourceFiles));
    const ruleIds = unique(familyWorkflows.flatMap((workflow) => workflow.commandRuleIds));
    const familyRules = ruleIds.map((id) => rules.get(id)).filter(Boolean);
    const eligibility = unique(group.dispositions.map((item) => item.eligibility));
    const automationEligibility = eligibility.length === 1 ? eligibility[0] : "blocked";
    const rawBlockers = group.dispositions.flatMap((item) => item.blockers);
    const blockerByCode = new Map(rawBlockers.map((item) => [item.code, item]));
    const blockers = [...blockerByCode.values()].sort((a, b) => a.code.localeCompare(b.code)).map((item) => ({ ...item, id: `blocker-${id}-${item.code}` }));
    if (eligibility.length > 1) blockers.push({ id: `blocker-${id}-mixed-disposition`, code: "mixed-disposition", reason: "Grouped workflows do not share one implementation disposition.", remediation: "Split the family before implementation." });
    const governingBoundaryIds = unique(familyWorkflows.map(governingBoundary));
    const approvedBoundaryIds = unique(familyWorkflows.flatMap((workflow) => [workflow.manufacturerBootstrapBoundaryId, workflow.platformReadScopeBoundaryId, workflow.policyAlertActorCeilingBoundaryId]));
    const systemBoundary = governingBoundaryIds.length === 1 ? systemBoundaryMap.get(governingBoundaryIds[0]) : null;
    const lifecycle = familyRules.filter((rule) => rule.lifecycleColumns?.length).map((rule) => ({ commandRuleId: rule.id, columns: rule.lifecycleColumns, allowed: rule.allowedLifecycleStates, forbidden: rule.forbiddenLifecycleStates }));
    const runtimeIdentities = unique(familyWorkflows.flatMap((workflow) => workflow.runtimeIdentities || []));
    const implementationStatus = automationEligibility === "implemented" ? "implemented" : automationEligibility === "contract-only" ? "contract-ready" : automationEligibility === "auto-implementable" ? "planned" : "blocked";
    return {
      id,
      category: group.category,
      workflowIds: familyWorkflows.map((workflow) => workflow.id),
      reclassifiedFromFamilyIds: unique(familyWorkflows.map((workflow) => workflow.contextBoundaryReclassification?.fromFamilyId)),
      ...(group.split ? {
        parentFamilyId: group.split.parentFamilyId,
        splitReason: group.split.reason,
        semanticEvidence: group.split.evidence,
        routeRoots: group.split.routeRoots,
        protectedTableBoundary: group.split.protectedTableBoundary,
        commandSemantics: group.split.commandSemantics,
      } : {}),
      executionSurfaces: group.split ? [group.split.executionSurface] : systemBoundary?.executionSurfaces || unique(familyWorkflows.map((workflow) => workflow.executionSurface)),
      controllerFiles: sourceKind(files, "/controllers/"),
      serviceFiles: sourceKind(files, "/services/"),
      repositoryFiles: unique(files.filter((file) => /repository/i.test(file))),
      protectedTables: unique(familyWorkflows.flatMap((workflow) => workflow.tablesTouched)),
      actorClasses: group.split ? group.split.actorClasses : systemBoundary?.actorClasses || unique(familyWorkflows.flatMap((workflow) => workflow.commandActorClasses || [])),
      runtimeIdentity: systemBoundary?.familyRuntimeIdentity || (runtimeIdentities.length === 1 ? runtimeIdentities[0] : runtimeIdentities.length ? "mixed" : "none"),
      requiredAssurance: systemBoundary?.requiredAssurance || unique(familyWorkflows.flatMap((workflow) => workflow.requiredAssurance || [])),
      canonicalContextKeys: automationEligibility === "contract-only" ? [] : canonicalContextKeys,
      readWriteCommandRuleIds: ruleIds,
      tenantScopeModel: group.split ? [group.split.scopeModel] : systemBoundary ? [systemBoundary.authoritativeScopeSource] : unique(familyRules.map((rule) => rule.scopeRule)),
      lifecycleStateRequirements: lifecycle,
      transactionIsolationRequirement: allCommands(familyWorkflows[0]).every((command) => command === "SELECT") ? "REPEATABLE READ when count/list consistency is required; otherwise one canonical transaction" : "One atomic canonical transaction with database-enforced concurrency",
      expectedReusableHelper: automationEligibility === "contract-only" ? governingBoundaryIds.join(", ") : "withCanonicalDbContext plus a transaction-client-only service",
      implementationStrategy: implementationStrategy(group.category, automationEligibility, governingBoundaryIds),
      testStrategy: testStrategy(group.category, automationEligibility),
      riskLevel: group.split?.risk || systemBoundary?.riskLevel || unique(familyWorkflows.map((workflow) => riskFor(group.category, workflow, workflow.commandRuleIds.map((ruleId) => rules.get(ruleId)).filter(Boolean)))).sort((a, b) => ["low", "medium", "high", "critical"].indexOf(b) - ["low", "medium", "high", "critical"].indexOf(a))[0],
      automationEligibility,
      governingBoundaryIds,
      ...(approvedBoundaryIds.length ? { approvedBoundaryIds } : {}),
      blockers,
      implementationStatus,
      ...(automationEligibility === "implemented" && familyWorkflows.some((workflow) => workflow.resolvedContextBlockerIds?.length) ? {
        resolvedBlockerIds: unique(familyWorkflows.flatMap((workflow) => workflow.resolvedContextBlockerIds || [])),
        rootCallChainEvidence: unique(familyWorkflows.flatMap((workflow) => workflow.rootCallChainEvidence || [])),
        scopeEvidence: unique(familyWorkflows.flatMap((workflow) => workflow.scopeEvidence || [])),
        implementationFiles: unique(familyWorkflows.flatMap((workflow) => workflow.implementationFiles || [])),
        testFiles: unique(familyWorkflows.flatMap((workflow) => workflow.testFiles || [])),
        contextKeys: unique(familyWorkflows.flatMap((workflow) => workflow.canonicalContextKeys || [])),
        sameTransactionGuarantee: familyWorkflows.every((workflow) => workflow.sameTransactionGuarantee === true),
        responseProjection: unique(familyWorkflows.flatMap((workflow) => workflow.responseProjection || [])),
        allowScenarios: unique(familyWorkflows.flatMap((workflow) => workflow.expectedAllowedScenarios || [])),
        denyScenarios: unique(familyWorkflows.flatMap((workflow) => workflow.expectedDeniedScenarios || [])),
        postgresqlCertificationStatus: unique(familyWorkflows.map((workflow) => workflow.postgresqlCertificationStatus)),
      } : {}),
      changeSizeGuard: { maximumProductionFiles: 15, maximumTestFiles: 10, maximumNetChangedLines: 2500 },
    };
  }).sort((a, b) => (order.get(a.category) ?? 99) - (order.get(b.category) ?? 99) || a.id.localeCompare(b.id));
  const manifest = {
    schemaVersion: 1,
    generatedFrom: ["documents/security/rls-program/workflows.json", "documents/security/rls-program/command-semantics.json", "documents/security/rls-program/tables.json", "documents/security/rls-program/runtime-identities.json", "documents/security/rls-program/pre-auth-functions.json", "documents/security/rls-program/worker-boundaries.json", "documents/security/rls-program/operator-boundaries.json", "documents/security/rls-program/system-boundaries.json", "documents/security/rls-program/manufacturer-bootstrap-boundary.json", "documents/security/rls-program/platform-read-scope-boundary.json", "documents/security/rls-program/policy-alert-actor-ceiling.json", "documents/security/rls-program/policy-dependency-graph.json", "documents/security/rls-program/ARCHITECTURE.md", "backend/prisma/schema.prisma"],
    workflowCount: workflows.workflows.length,
    familyCount: families.length,
    baselineImplementedWorkflowIds,
    approvedBoundaryCounts: { preAuthFunctions: preAuthFunctions.functions.length, workerBoundaries: workerBoundaries.boundaries.length, operatorBoundaries: operatorBoundaries.boundaries.length, systemBoundaries: systemBoundaries.boundaries.length, manufacturerBootstrapBoundaries: 1, platformReadScopeBoundaries: 1, policyAlertActorCeilings: 1 },
    systemBoundaryContracts: systemBoundaries.boundaries,
    familyOrder: categoryOrder,
    families,
  };
  validateContextBoundaryPlan(manifest, workflows, commandSemantics, tables, systemBoundaries, manufacturerBootstrapBoundary, platformReadScopeBoundary, policyAlertActorCeiling);
  fs.writeFileSync(contextBoundaryFamiliesPath, `${JSON.stringify(manifest, null, 2)}\n`);
  writeReport(manifest);
  return manifest;
};

export const validateSystemBoundaryContracts = (manifest, workflowManifest) => {
  assert.equal(manifest?.schemaVersion, 1, "system boundary schema version");
  assert.equal(manifest.boundaryCount, manifest.boundaries.length, "system boundary count drifted");
  assert.equal(new Set(manifest.boundaries.map((boundary) => boundary.id)).size, manifest.boundaries.length, "system boundary IDs are duplicated");
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const boundary of manifest.boundaries) {
    assert(/^system-boundary-[a-z0-9-]+$/.test(boundary.id), `${boundary.id} is unstable`);
    assert(["worker-boundary", "device-authenticated-internal-system-path"].includes(boundary.classification), `${boundary.id} has an invalid classification`);
    assert(categoryOrder.includes(boundary.familyCategory), `${boundary.id} has an invalid family category`);
    assert(["low", "medium", "high", "critical"].includes(boundary.riskLevel), `${boundary.id} has an invalid risk`);
    assert(boundary.actorClasses?.length && boundary.familyRuntimeIdentity?.trim() && boundary.requiredAssurance?.length && boundary.executionSurfaces?.length, `${boundary.id} lacks explicit execution identity metadata`);
    assert(boundary.registeredRoots?.length && boundary.credentialRuntimeIdentity?.trim() && boundary.authoritativeScopeSource?.trim(), `${boundary.id} lacks root, identity or scope evidence`);
    assert.equal(boundary.humanActorContextExists, false, `${boundary.id} installs fake human context`);
    assert.equal(boundary.ordinaryAuthenticatedContextAllowed, false, `${boundary.id} permits ordinary context`);
    assert.equal(boundary.implementationStatus, "contract-only", `${boundary.id} is falsely implemented`);
    assert(boundary.activationBlockers?.length && boundary.requiredTests?.length, `${boundary.id} lacks activation blockers or tests`);
    for (const workflowId of boundary.workflowIds) {
      const workflow = workflows.get(workflowId);
      assert(workflow, `${boundary.id} references unknown workflow ${workflowId}`);
      assert.equal(workflow.systemBoundaryId, boundary.id, `${workflowId} lacks its system boundary`);
      assert.notEqual(workflow.contextBoundaryStatus, "implemented", `${workflowId} is falsely context implemented`);
    }
  }
  return true;
};

export const validateContextBoundaryPlan = (manifest, workflowManifest, commandManifest, tableManifest, systemBoundaryManifest = { boundaries: [] }, manufacturerBootstrapBoundary = null, platformReadScopeBoundary = null, policyAlertActorCeiling = null) => {
  assert.equal(manifest.schemaVersion, 1, "context family schema version");
  assert.equal(manifest.workflowCount, workflowManifest.workflows.length, "context family workflow count drifted");
  assert.equal(manifest.familyCount, manifest.families.length, "context family count drifted");
  assert.equal(new Set(manifest.families.map((family) => family.id)).size, manifest.families.length, "context family IDs are not unique");
  const workflowIds = new Set(workflowManifest.workflows.map((workflow) => workflow.id));
  const ruleIds = new Set(commandManifest.rules.map((rule) => rule.id));
  const ruleById = new Map(commandManifest.rules.map((rule) => [rule.id, rule]));
  const tableIds = new Set(tableManifest.tables.map((table) => table.id));
  const systemBoundaryIds = new Set(systemBoundaryManifest.boundaries.map((boundary) => boundary.id));
  const covered = manifest.families.flatMap((family) => family.workflowIds);
  assert.deepEqual([...covered].sort(), [...workflowIds].sort(), "context families do not cover every workflow exactly once");
  assert.equal(new Set(covered).size, covered.length, "a workflow appears in multiple context families");
  const lineage = new Map(manifest.families.filter((family) => family.parentFamilyId).map((family) => [family.id, family.parentFamilyId]));
  for (const familyId of lineage.keys()) {
    const seen = new Set([familyId]);
    let parent = lineage.get(familyId);
    while (parent && lineage.has(parent)) {
      assert(!seen.has(parent), `${familyId} has circular parent lineage`);
      seen.add(parent);
      parent = lineage.get(parent);
    }
  }
  for (const family of manifest.families) {
    assert(/^family-[a-z0-9-]+$/.test(family.id), `${family.id} is unstable`);
    assert(categoryOrder.includes(family.category), `${family.id} category is invalid`);
    assert(family.workflowIds.length && family.protectedTables.length && family.readWriteCommandRuleIds.length, `${family.id} lacks workflow/table/rule evidence`);
    if (family.parentFamilyId) {
      assert(/^family-[a-z0-9-]+$/.test(family.parentFamilyId) && family.parentFamilyId !== family.id, `${family.id} has invalid parent lineage`);
      assert(family.splitReason?.trim() && family.semanticEvidence?.length && family.routeRoots?.length, `${family.id} split lacks semantic evidence`);
      assert(family.actorClasses.length && family.tenantScopeModel.length === 1 && family.executionSurfaces.length === 1 && family.protectedTableBoundary?.trim() && family.commandSemantics?.trim(), `${family.id} split is not semantically uniform`);
      const splitDefinitions = family.workflowIds.map((id) => workflowManifest.workflows.find((workflow) => workflow.id === id)?.contextBoundaryFamilySplit);
      assert(splitDefinitions.every(Boolean), `${family.id} split workflow lacks lineage metadata`);
      const compatibility = splitDefinitions.map((split) => JSON.stringify([split.semanticKey, split.actorClasses, split.scopeModel, split.executionSurface, split.protectedTableBoundary, split.commandSemantics]));
      assert.equal(new Set(compatibility).size, 1, `${family.id} retains incompatible actor or scope models`);
      assert(splitDefinitions.every((split) => split.parentFamilyId === family.parentFamilyId), `${family.id} parent lineage drifted`);
    }
    family.protectedTables.forEach((id) => assert(tableIds.has(id), `${family.id} references missing table ${id}`));
    family.readWriteCommandRuleIds.forEach((id) => assert(ruleIds.has(id), `${family.id} references missing rule ${id}`));
    const expected = family.workflowIds.map((id) => {
      const workflow = workflowManifest.workflows.find((item) => item.id === id);
      return workflowDisposition(workflow, workflow.commandRuleIds.map((ruleId) => ruleById.get(ruleId)).filter(Boolean));
    });
    const expectedDispositions = unique(expected.map((item) => item.eligibility));
    assert.equal(expectedDispositions.length, 1, `${family.id} mixes implementation dispositions`);
    assert.equal(family.automationEligibility, expectedDispositions[0], `${family.id} eligibility does not match workflow evidence`);
    const expectedBlockerCodes = unique(expected.flatMap((item) => item.blockers.map((blocker) => blocker.code)));
    assert.deepEqual(family.blockers.map((blocker) => blocker.code).sort(), expectedBlockerCodes, `${family.id} blocker evidence drifted`);
    family.blockers.forEach((blocker) => assert.equal(blocker.id, `blocker-${family.id}-${blocker.code}`, `${family.id} blocker ID drifted`));
    assert(["implemented", "contract-only", "auto-implementable", "blocked"].includes(family.automationEligibility), `${family.id} eligibility is invalid`);
    assert(["low", "medium", "high", "critical"].includes(family.riskLevel), `${family.id} risk is invalid`);
    assert(family.implementationStrategy && family.testStrategy && family.transactionIsolationRequirement && family.expectedReusableHelper, `${family.id} lacks strategy`);
    assert.deepEqual(family.changeSizeGuard, { maximumProductionFiles: 15, maximumTestFiles: 10, maximumNetChangedLines: 2500 }, `${family.id} weakens the change-size guard`);
    if (family.automationEligibility === "blocked") assert(family.blockers.length && family.implementationStatus === "blocked", `${family.id} lacks exact blockers`);
    if (family.automationEligibility === "contract-only") assert(family.governingBoundaryIds.length && family.implementationStatus === "contract-ready" && family.canonicalContextKeys.length === 0, `${family.id} contract boundary is invalid`);
    const manufacturerBootstrapWorkflows = family.workflowIds.filter((id) => workflowManifest.workflows.find((workflow) => workflow.id === id)?.manufacturerBootstrapBoundaryId);
    if (manufacturerBootstrapWorkflows.length) {
      assert(manufacturerBootstrapBoundary, `${family.id} lacks manufacturer bootstrap contract`);
      assert.deepEqual(family.approvedBoundaryIds, [manufacturerBootstrapBoundary.id], `${family.id} lacks manufacturer bootstrap boundary ID`);
    }
    const platformReadWorkflows = family.workflowIds.filter((id) => workflowManifest.workflows.find((workflow) => workflow.id === id)?.platformReadScopeBoundaryId);
    if (platformReadWorkflows.length) {
      assert(platformReadScopeBoundary, `${family.id} lacks platform read-scope contract`);
      assert(family.approvedBoundaryIds.includes(platformReadScopeBoundary.id), `${family.id} lacks platform read-scope boundary ID`);
    }
    const policyAlertWorkflows = family.workflowIds.filter((id) => workflowManifest.workflows.find((workflow) => workflow.id === id)?.policyAlertActorCeilingBoundaryId);
    if (policyAlertWorkflows.length) {
      assert(policyAlertActorCeiling, `${family.id} lacks policy alert actor-ceiling contract`);
      assert(family.approvedBoundaryIds.includes(policyAlertActorCeiling.id), `${family.id} lacks policy alert actor-ceiling boundary ID`);
    }
    for (const boundaryId of family.governingBoundaryIds.filter((id) => id.startsWith("system-boundary-"))) {
      assert(systemBoundaryIds.has(boundaryId), `${family.id} references unknown system boundary ${boundaryId}`);
      const boundary = systemBoundaryManifest.boundaries.find((item) => item.id === boundaryId);
      assert.deepEqual(family.actorClasses, boundary.actorClasses, `${family.id} retains an ordinary actor class`);
      assert.equal(family.runtimeIdentity, boundary.familyRuntimeIdentity, `${family.id} retains an ordinary runtime identity`);
    }
    if (family.automationEligibility === "implemented") {
      assert(family.implementationStatus === "implemented" && family.blockers.length === 0, `${family.id} implemented family is blocked`);
      for (const workflowId of family.workflowIds) {
        const workflow = workflowManifest.workflows.find((item) => item.id === workflowId);
        assert.equal(workflow.contextBoundaryStatus, "implemented", `${workflowId} is falsely implemented`);
        assert.equal(workflow.implementationFamilyId, family.id, `${workflowId} lacks its implementation family`);
        assert.equal(workflow.postgresqlCertificationStatus, "pending", `${workflowId} is falsely PostgreSQL-certified`);
      }
    }
    if (family.automationEligibility === "auto-implementable") {
      assert.equal(family.blockers.length, 0, `${family.id} auto family has blockers`);
      assert.equal(family.governingBoundaryIds.length, 0, `${family.id} special boundary is treated as ordinary context`);
    }
  }
  return true;
};

export const validateContextBoundaryReadBatch = (batch, familyManifest, workflowManifest, commandManifest, tableManifest) => {
  assert.equal(batch.schemaVersion, 2, "read batch schema version");
  assert.deepEqual(batch.limits, {
    maximumFamilies: 20,
    maximumWorkflows: 40,
    maximumProductionFiles: 12,
    maximumTestFiles: 12,
    maximumNetProductionTestLines: 3000,
  }, "read batch weakens its hard limits");
  assert.equal(batch.selectionTotals.familiesConsidered, batch.selectedFamilies.length, "read batch family total drifted");
  const selectedWorkflowIds = batch.selectedFamilies.flatMap((family) => family.workflowIds);
  assert.equal(new Set(batch.selectedFamilies.map((family) => family.familyId)).size, batch.selectedFamilies.length, "read batch family IDs are duplicated");
  assert.equal(new Set(selectedWorkflowIds).size, selectedWorkflowIds.length, "read batch workflows are duplicated");
  assert.equal(batch.selectionTotals.workflowsConsidered, selectedWorkflowIds.length, "read batch workflow total drifted");
  assert(batch.selectedFamilies.length <= batch.limits.maximumFamilies, "read batch exceeds family limit");
  assert(selectedWorkflowIds.length <= batch.limits.maximumWorkflows, "read batch exceeds workflow limit");
  assert(batch.actualChanges.productionFiles <= batch.limits.maximumProductionFiles, "read batch exceeds production-file limit");
  assert(batch.actualChanges.testFiles <= batch.limits.maximumTestFiles, "read batch exceeds test-file limit");
  assert(batch.actualChanges.netProductionTestChangedLines <= batch.limits.maximumNetProductionTestLines, "read batch exceeds changed-line limit");

  const familyById = new Map(familyManifest.families.map((family) => [family.id, family]));
  const workflowById = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  const ruleById = new Map(commandManifest.rules.map((rule) => [rule.id, rule]));
  const tableIds = new Set(tableManifest.tables.map((table) => table.id));
  let reclassifiedFamilies = 0;
  let splitFamilies = 0;
  let childFamilies = 0;
  let contractOnlyWorkflows = 0;
  let blockedWorkflows = 0;

  for (const selected of batch.selectedFamilies) {
    assert(["low", "medium"].includes(selected.reviewedRisk), `${selected.familyId} is outside the reviewed risk ceiling`);
    assert(["blocked", "reclassified-contract-only", "split-blocked"].includes(selected.resolution), `${selected.familyId} has an invalid resolution`);
    assert(selected.canonicalFiles?.length && selected.routeRoots?.length && selected.actorClasses?.length && selected.commandRuleIds?.length && selected.protectedTables?.length, `${selected.familyId} lacks selection evidence`);
    assert(selected.scopeSource?.trim() && selected.assuranceSource?.trim() && selected.rootCallChainEvidence?.length, `${selected.familyId} lacks scope/root evidence`);
    assert(selected.transactionStrategy?.trim() && selected.testPlan?.length && selected.blockerResolutionEvidence?.length, `${selected.familyId} lacks implementation/test evidence`);
    assert(selected.resultingFamilyIds?.length, `${selected.familyId} lacks resulting families`);
    const resulting = selected.resultingFamilyIds.map((id) => familyById.get(id));
    assert(resulting.every(Boolean), `${selected.familyId} resulting family is absent from the plan`);
    assert.deepEqual(resulting.flatMap((family) => family.workflowIds).sort(), [...selected.workflowIds].sort(), `${selected.familyId} workflow membership drifted`);
    selected.commandRuleIds.forEach((id) => {
      const rule = ruleById.get(id);
      assert(rule, `${selected.familyId} references unknown command rule ${id}`);
      assert.equal(rule.command, "SELECT", `${selected.familyId} includes a mutation command`);
    });
    selected.protectedTables.forEach((id) => assert(tableIds.has(id), `${selected.familyId} references unknown table ${id}`));
    selected.workflowIds.forEach((id) => assert(workflowById.has(id), `${selected.familyId} references unknown workflow ${id}`));
    if (selected.resolution === "reclassified-contract-only") {
      reclassifiedFamilies += 1;
      contractOnlyWorkflows += selected.workflowIds.length;
      assert(resulting.every((family) => family.automationEligibility === "contract-only" && family.governingBoundaryIds.some((id) => id.startsWith("system-boundary-"))), `${selected.familyId} special boundary became ordinary context`);
      assert(selected.workflowIds.every((id) => workflowById.get(id).contextBoundaryStatus !== "implemented"), `${selected.familyId} is falsely implemented`);
    } else {
      blockedWorkflows += selected.workflowIds.length;
      assert(resulting.every((family) => family.automationEligibility === "blocked" && family.blockers.length), `${selected.familyId} blocker was silently cleared`);
    }
    if (selected.resolution === "split-blocked") {
      splitFamilies += 1;
      childFamilies += resulting.length;
      assert(resulting.length > 1 && resulting.every((family) => family.parentFamilyId === selected.familyId), `${selected.familyId} lacks stable split lineage`);
    }
  }
  assert.equal(batch.selectionTotals.reclassifiedFamilies, reclassifiedFamilies, "read batch reclassified-family total drifted");
  assert.equal(batch.selectionTotals.splitFamilies, splitFamilies, "read batch split-family total drifted");
  assert.equal(batch.selectionTotals.childFamiliesCreated, childFamilies, "read batch child-family total drifted");
  assert.equal(batch.selectionTotals.contractOnlyWorkflows, contractOnlyWorkflows, "read batch contract-only workflow total drifted");
  assert.equal(batch.selectionTotals.blockedWorkflows, blockedWorkflows, "read batch blocked-workflow total drifted");
  assert.equal(batch.selectionTotals.newlyImplementedWorkflows, 0, "read batch falsely reports implementation");
  return true;
};

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const manifest = buildContextBoundaryPlan();
  console.log(JSON.stringify({ output: path.relative(repoRoot, contextBoundaryFamiliesPath), report: path.relative(repoRoot, contextBoundaryReportPath), workflows: manifest.workflowCount, families: manifest.familyCount }));
}
