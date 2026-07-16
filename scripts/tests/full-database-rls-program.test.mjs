import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { buildTableManifest, buildWorkflowManifest, commandSemanticsPath, commandSemanticsReviewPath, decisionManifestPath, identityManifestPath, manufacturerBootstrapBoundaryPath, manifests, objectOwnershipChainPath, objectOwnershipReviewPath, operatorAdministrationReviewPath, operatorBoundariesPath, parseSchema, platformReadScopeBoundaryPath, policyAlertActorCeilingPath, policyDependencyGraphPath, preAuthBoundaryReviewPath, preAuthFunctionsPath, repoRoot, scanProductionAccess, sharedApplyIsBlocked, systemBoundariesPath, tableManifestPath, tableOwnershipReviewPath, validateManufacturerBootstrapBoundary, validateObjectOwnershipChain, validateOperatorBoundaries, validatePlatformReadScopeBoundary, validatePolicyAlertActorCeiling, validatePreAuthFunctions, validateRuntimeIdentities, validateWorkerBoundaries, workerBoundariesPath, workerIdentityReviewPath, workflowManifestPath } from "../rls/lib/program-inventory.mjs";
import { buildContextBoundaryPlan, contextBoundaryFamiliesPath, contextBoundaryReadBatchPath, contextBoundaryReportPath, validateContextBoundaryPlan, validateContextBoundaryReadBatch, validateSystemBoundaryContracts } from "../rls/context-boundary-plan.mjs";

const snapshot = () => [tableManifestPath, workflowManifestPath, commandSemanticsPath, commandSemanticsReviewPath, preAuthFunctionsPath, preAuthBoundaryReviewPath, workerBoundariesPath, workerIdentityReviewPath, objectOwnershipChainPath, objectOwnershipReviewPath, operatorBoundariesPath, operatorAdministrationReviewPath, decisionManifestPath, identityManifestPath, policyDependencyGraphPath, tableOwnershipReviewPath, systemBoundariesPath, manufacturerBootstrapBoundaryPath, platformReadScopeBoundaryPath, policyAlertActorCeilingPath, contextBoundaryFamiliesPath, contextBoundaryReportPath].map((file) => fs.readFileSync(file, "utf8"));

test("all Prisma models and production access sites are represented exactly and deterministically", () => {
  const before = snapshot();
  buildTableManifest();
  buildWorkflowManifest();
  assert.deepEqual(snapshot(), before, "generated manifests changed on a second run");
  const { tables, workflows } = manifests();
  const models = parseSchema().map((model) => model.name).sort();
  assert.deepEqual(tables.tables.map((table) => table.prismaModel).sort(), models);
  assert.equal(new Set(tables.tables.map((table) => table.prismaModel)).size, models.length, "a model was duplicated or silently skipped");
  const mapped = new Set(workflows.workflows.flatMap((workflow) => workflow.supportingEvidence.map((item) => item.accessId)));
  const detected = scanProductionAccess().accesses;
  assert.deepEqual([...mapped].sort(), detected.map((item) => item.id).sort());
});

test("stable IDs and references are unique and valid", () => {
  const { tables, workflows, identities, decisions, commandSemantics } = manifests();
  for (const items of [tables.tables, workflows.workflows, identities.identities, decisions.decisions, commandSemantics.rules]) assert.equal(new Set(items.map((item) => item.id)).size, items.length);
  const tableIds = new Set(tables.tables.map((table) => table.id));
  const workflowIds = new Set(workflows.workflows.map((workflow) => workflow.id));
  const decisionIds = new Set(decisions.decisions.map((decision) => decision.id));
  const ruleIds = new Set(commandSemantics.rules.map((rule) => rule.id));
  for (const workflow of workflows.workflows) {
    workflow.tablesTouched.forEach((id) => assert(tableIds.has(id), `${workflow.id} -> ${id}`));
    workflow.unresolvedDecisions.forEach((id) => assert(decisionIds.has(id), `${workflow.id} -> ${id}`));
    workflow.commandRuleIds.forEach((id) => assert(ruleIds.has(id), `${workflow.id} -> ${id}`));
  }
  for (const table of tables.tables) {
    [...table.productionRuntimeReaders, ...table.productionRuntimeWriters].forEach((id) => assert(workflowIds.has(id), `${table.id} -> ${id}`));
    table.unresolvedDecisions.forEach((id) => assert(decisionIds.has(id), `${table.id} -> ${id}`));
    (table.commandRuleIds || []).forEach((id) => assert(ruleIds.has(id), `${table.id} -> ${id}`));
  }
});

test("implemented HTTP context boundaries retain complete certification evidence", () => {
  const requiredKeys = ["app.auth_assurance", "app.licensee_id", "app.manufacturer_id", "app.organization_id", "app.purpose", "app.request_id", "app.role", "app.user_id"];
  const verify = (workflow) => {
    assert.equal(workflow.contextBoundaryStatus, "implemented", "context boundary status");
    assert.equal(workflow.implementationStatus, "context-boundary-implemented", "implementation status");
    assert.match(workflow.implementationFamilyId, /^family-[a-z0-9-]+$/, "implementation family");
    assert(workflow.implementationFiles.length && workflow.testFiles.length, "implementation and test evidence");
    assert(workflow.tablesTouched.length, "protected table evidence");
    assert.deepEqual([...workflow.canonicalContextKeys].sort(), requiredKeys, "canonical context keys");
    assert.equal(workflow.sameTransactionGuarantee, true, "same transaction guarantee");
    assert(["pending", "certified"].includes(workflow.postgresqlCertificationStatus), "PostgreSQL certification status");
    assert(workflow.expectedAllowedScenarios.length && workflow.expectedDeniedScenarios.length, "allow and deny scenarios");
  };
  const implemented = manifests().workflows.workflows.filter((item) => item.contextBoundaryStatus === "implemented");
  assert(implemented.length >= 3, "expected all reviewed context-boundary slices");
  implemented.forEach(verify);
  const workflow = implemented.find((item) => item.id === "workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports");
  assert(workflow, "fraud-report workflow context boundary");
  for (const [field, value, pattern] of [
    ["implementationFiles", [], /implementation and test evidence/],
    ["testFiles", [], /implementation and test evidence/],
    ["tablesTouched", [], /protected table evidence/],
    ["implementationFamilyId", undefined, /implementation family/],
    ["canonicalContextKeys", workflow.canonicalContextKeys.filter((key) => key !== "app.purpose"), /canonical context keys/],
    ["sameTransactionGuarantee", false, /same transaction guarantee/],
    ["postgresqlCertificationStatus", undefined, /PostgreSQL certification status/],
  ]) {
    const candidate = structuredClone(workflow);
    candidate[field] = value;
    assert.throws(() => verify(candidate), pattern);
  }
});

test("context-boundary families are exhaustive, deterministic, and fail closed", () => {
  const beforePlan = fs.readFileSync(contextBoundaryFamiliesPath, "utf8");
  const beforeReport = fs.readFileSync(contextBoundaryReportPath, "utf8");
  const generated = buildContextBoundaryPlan();
  assert.equal(fs.readFileSync(contextBoundaryFamiliesPath, "utf8"), beforePlan, "context family plan changed on a second run");
  assert.equal(fs.readFileSync(contextBoundaryReportPath, "utf8"), beforeReport, "context family report changed on a second run");
  const { workflows, commandSemantics, tables, systemBoundaries, manufacturerBootstrapBoundary, platformReadScopeBoundary, policyAlertActorCeiling } = manifests();
  validateSystemBoundaryContracts(systemBoundaries, workflows);
  validateContextBoundaryPlan(generated, workflows, commandSemantics, tables, systemBoundaries, manufacturerBootstrapBoundary, platformReadScopeBoundary, policyAlertActorCeiling);
  assert.equal(generated.workflowCount, 428);
  assert.equal(generated.familyCount, 321);
  const count = (eligibility) => generated.families.filter((family) => family.automationEligibility === eligibility).reduce((total, family) => total + family.workflowIds.length, 0);
  assert.equal(count("implemented"), 4);
  assert.equal(count("contract-only"), 40);
  assert.equal(count("blocked"), 384);
  assert.equal(count("auto-implementable"), 0);
  assert.equal(new Set(generated.families.flatMap((family) => family.workflowIds)).size, workflows.workflows.length);
  const specialWorkflowIds = new Set([
    ...workflows.workflows.filter((workflow) => workflow.preAuthBoundary?.boundaryMode === "exact-security-definer-function"),
    ...workflows.workflows.filter((workflow) => workflow.workerBoundaryId),
    ...workflows.workflows.filter((workflow) => workflow.operatorBoundaryId),
    ...workflows.workflows.filter((workflow) => workflow.systemBoundaryId),
    ...workflows.workflows.filter((workflow) => workflow.authorizationBoundaryType === "migration-owner"),
  ].map((workflow) => workflow.id));
  for (const family of generated.families.filter((family) => family.workflowIds.some((id) => specialWorkflowIds.has(id)))) assert.equal(family.automationEligibility, "contract-only", family.id);
  for (const family of generated.families.filter((family) => family.governingBoundaryIds.some((id) => id.startsWith("system-boundary-")))) {
    assert(!family.actorClasses.includes("authenticated-user"), `${family.id} retained fake human context`);
    assert.equal(family.canonicalContextKeys.length, 0, `${family.id} retained ordinary context keys`);
  }

  const reject = (mutate, pattern) => {
    const candidate = structuredClone(generated);
    const candidateWorkflows = structuredClone(workflows);
    mutate(candidate, candidateWorkflows);
    assert.throws(() => validateContextBoundaryPlan(candidate, candidateWorkflows, commandSemantics, tables, systemBoundaries, manufacturerBootstrapBoundary, platformReadScopeBoundary, policyAlertActorCeiling), pattern);
  };
  reject((candidate) => candidate.families[1].workflowIds.push(candidate.families[0].workflowIds[0]), /cover every workflow exactly once|multiple context families/);
  reject((candidate) => { const family = candidate.families.find((item) => item.automationEligibility === "blocked"); family.blockers = []; }, /blocker evidence drifted|lacks exact blockers/);
  reject((candidate) => { const family = candidate.families.find((item) => item.automationEligibility === "blocked"); family.automationEligibility = "auto-implementable"; family.implementationStatus = "planned"; family.blockers = []; }, /eligibility does not match workflow evidence/);
  reject((candidate) => { const family = candidate.families.find((item) => item.automationEligibility === "contract-only"); family.canonicalContextKeys = ["app.user_id"]; }, /contract boundary is invalid/);
  reject((candidate, candidateWorkflows) => { const family = candidate.families.find((item) => item.automationEligibility === "implemented"); const workflow = candidateWorkflows.workflows.find((item) => item.id === family.workflowIds[0]); workflow.postgresqlCertificationStatus = "certified"; }, /falsely PostgreSQL-certified/);
  const splitFamilies = generated.families.filter((family) => family.parentFamilyId);
  assert.equal(splitFamilies.length, 10);
  assert.equal(new Set(splitFamilies.flatMap((family) => family.workflowIds)).size, splitFamilies.flatMap((family) => family.workflowIds).length, "split workflows duplicated");
  assert(splitFamilies.every((family) => family.splitReason && family.semanticEvidence.length && family.routeRoots.length), "split evidence missing");
  reject((candidate) => { const family = candidate.families.find((item) => item.parentFamilyId); family.parentFamilyId = family.id; }, /invalid parent lineage|circular parent lineage/);
  reject((candidate) => { const family = candidate.families.find((item) => item.parentFamilyId); family.semanticEvidence = []; }, /split lacks semantic evidence/);
  reject((candidate, candidateWorkflows) => { const family = candidate.families.find((item) => item.workflowIds.length > 1 && item.parentFamilyId); candidateWorkflows.workflows.find((item) => item.id === family.workflowIds[1]).contextBoundaryFamilySplit.scopeModel = "different scope"; }, /incompatible actor or scope models/);
});

test("manufacturer bootstrap is actor-bound, minimal, deterministic, and fail closed", () => {
  const { manufacturerBootstrapBoundary, workflows, commandSemantics, tables, decisions } = manifests();
  validateManufacturerBootstrapBoundary(manufacturerBootstrapBoundary, workflows, commandSemantics, tables, decisions);
  const reject = (mutate, pattern) => {
    const boundary = structuredClone(manufacturerBootstrapBoundary);
    const candidateWorkflows = structuredClone(workflows);
    const candidateRules = structuredClone(commandSemantics);
    const candidateDecisions = structuredClone(decisions);
    mutate(boundary, candidateWorkflows, candidateRules, candidateDecisions);
    assert.throws(() => validateManufacturerBootstrapBoundary(boundary, candidateWorkflows, candidateRules, tables, candidateDecisions), pattern);
  };
  reject((boundary) => { boundary.inputFields.find((field) => field.name === "requestedLicenseeId").establishesAuthority = true; }, /caller-selected licensee becomes authoritative/);
  reject((boundary) => { boundary.membershipSelectionRules.blankLicenseeMeansAll = true; }, /blank manufacturer licensee means all/);
  reject((boundary) => { boundary.trustedInputSources.role = "token.role"; }, /role comes from caller input or token claims/);
  reject((boundary) => { boundary.disabledRevokedBehavior.revokedMembershipAccepted = true; }, /accepts revokedMembershipAccepted/);
  reject((boundary) => { boundary.duplicateHandling.nondeterministicSelectionAllowed = true; }, /duplicate manufacturer memberships do not fail closed/);
  reject((boundary) => { boundary.exactReturnedColumns.push({ name: "passwordHash", source: "User.passwordHash", reason: "unsafe" }); }, /projection is not exact|returns secret/);
  reject((boundary) => { boundary.identityProofChain.intendedRoleCeiling.push("LICENSEE_ADMIN"); }, /grants licensee or platform role visibility/);
  reject((boundary) => { boundary.exactReturnedColumns[0] = { name: "isPlatformAdmin", source: "request.isPlatformAdmin", reason: "unsafe" }; }, /projection is not exact|returns secret/);
  reject((boundary) => { boundary.scopeSwitchRules.requestIdRequired = false; }, /scope switching lacks request attribution/);
  reject((boundary) => { boundary.scopeSwitchRules.auditRequired = false; }, /scope switching lacks request attribution/);
  reject((boundary) => { boundary.implementationForm.actorIdentityVerifiedBeforeRead = false; }, /occurs before actor verification/);
  reject((boundary) => { boundary.contextKeysInstalled.clientValuesInstalledDirectly = true; }, /installs query\/body values directly/);
  reject((_boundary, candidateWorkflows) => { delete candidateWorkflows.workflows.find((workflow) => workflow.manufacturerBootstrapBoundaryId).manufacturerBootstrapBoundaryId; }, /lacks manufacturer bootstrap boundary ID/);
  reject((boundary) => { delete boundary.failureSemantics.blankScope; }, /lacks blankScope failure semantics/);
  reject((_boundary, _workflows, _rules, candidateDecisions) => { candidateDecisions.decisions.find((decision) => decision.id === "decision-context-manufacturer-bootstrap").status = "unresolved"; }, /decision is unresolved/);
});

test("platform read scope is finite, attributed, projected, and fail closed", () => {
  const { platformReadScopeBoundary, workflows, commandSemantics, tables, decisions, operatorBoundaries } = manifests();
  validatePlatformReadScopeBoundary(platformReadScopeBoundary, workflows, commandSemantics, tables, decisions, operatorBoundaries);
  const reject = (mutate, pattern) => {
    const boundary = structuredClone(platformReadScopeBoundary);
    const candidateWorkflows = structuredClone(workflows);
    const candidateRules = structuredClone(commandSemantics);
    const candidateDecisions = structuredClone(decisions);
    const candidateOperators = structuredClone(operatorBoundaries);
    mutate(boundary, candidateWorkflows, candidateRules, candidateDecisions, candidateOperators);
    assert.throws(() => validatePlatformReadScopeBoundary(boundary, candidateWorkflows, candidateRules, tables, candidateDecisions, candidateOperators), pattern);
  };
  reject((boundary) => { boundary.selectorValidation.blankSelectorMeansGlobal = true; }, /blank platform scope becomes global/);
  reject((boundary) => { boundary.actorVerification.roleAloneAuthorizesAccess = true; }, /platform-admin role alone grants access/);
  reject((boundary) => { boundary.approvedScopeClasses.find((item) => item.class === "tenant-bounded-read").requiredAssurance = "password-verified"; }, /sensitive platform read lacks fresh MFA/);
  reject((boundary) => { boundary.purposeRules.required = false; }, /platform read purpose is absent/);
  reject((boundary) => { boundary.purposeRules.freeTextEstablishesAuthority = true; }, /free-text purpose establishes authority/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.primaryClass === "licensee-bounded-read").pagination = null; }, /pagination bounds are missing/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.primaryClass === "platform-aggregate-read").tableProjections[0].allowedColumns.push("details"); }, /secret or raw audit detail/);
  reject((boundary) => { boundary.aggregateRestrictions.tenantPrivateRowsMaterializedInApplicationMemory = true; }, /aggregate exposes tenant-private rows/);
  reject((boundary) => { boundary.incidentReadRestrictions.incidentIdRequired = false; }, /incident read lacks incident binding/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.workflowId.endsWith("get-licensees")).tableProjections[0].allowedColumns.push("suspendedReason"); }, /directory projection exposes security fields/);
  reject((boundary) => { boundary.operatorOnlyMappings[0].ordinaryApplicationRead = true; }, /operator diagnostics are ordinary application reads/);
  reject((boundary) => { boundary.requestAttributionRequirements.required = false; }, /read attribution is missing/);
  reject((boundary) => { boundary.selectorValidation.conflictingSelectorsAccepted = true; }, /conflicting selectors are accepted/);
  reject((boundary) => { boundary.selectorValidation.unsupportedSelectorCombinationsAccepted = true; }, /unsupported selector combinations are accepted/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.primaryClass === "tenant-bounded-read").requiredSelectors = []; }, /raw global listing is approved without a specific class/);
  reject((_boundary, candidateWorkflows) => { delete candidateWorkflows.workflows.find((workflow) => workflow.platformReadScopeBoundaryId).platformReadScopeBoundaryId; }, /lacks platform read-scope boundary ID/);
  reject((_boundary, _workflows, _rules, candidateDecisions) => { candidateDecisions.decisions.find((decision) => decision.id === "decision-context-platform-read-scope").status = "unresolved"; }, /decision is unresolved/);
});

test("policy alert actor ceiling is scoped, stateful, attributed, and fail closed", () => {
  const { policyAlertActorCeiling, workflows, commandSemantics, tables, decisions, operatorBoundaries, workerBoundaries } = manifests();
  validatePolicyAlertActorCeiling(policyAlertActorCeiling, workflows, commandSemantics, tables, decisions, operatorBoundaries, workerBoundaries);
  const reject = (mutate, pattern) => {
    const boundary = structuredClone(policyAlertActorCeiling);
    const candidateWorkflows = structuredClone(workflows);
    const candidateRules = structuredClone(commandSemantics);
    const candidateDecisions = structuredClone(decisions);
    const candidateOperators = structuredClone(operatorBoundaries);
    const candidateWorkers = structuredClone(workerBoundaries);
    mutate(boundary, candidateWorkflows, candidateRules, candidateDecisions, candidateOperators, candidateWorkers);
    assert.throws(() => validatePolicyAlertActorCeiling(boundary, candidateWorkflows, candidateRules, tables, candidateDecisions, candidateOperators, candidateWorkers), pattern);
  };
  reject((boundary) => { boundary.alertClasses[0].actorClasses = ["admin"]; }, /actor class is generic admin/);
  reject((boundary) => { boundary.actorCeilings.licenseeAdmin.foreignTenantAccess = true; }, /tenant admin gains cross-tenant alert access/);
  reject((boundary) => { boundary.actorCeilings.manufacturer.wholeLicenseeVisibility = true; }, /manufacturer gains whole-licensee alert visibility/);
  reject((boundary) => { boundary.actorCeilings.platformAdmin.roleAloneAuthorizesAccess = true; }, /platform role alone grants access/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.primaryClass === "tenant-security-alert-read").requiredAssurance = "password-verified"; }, /lacks required alert assurance/);
  reject((boundary) => { boundary.workflowClassifications.find((item) => item.primaryClass === "tenant-security-alert-read").purposeCodes = []; }, /alert purpose is absent/);
  reject((boundary) => { boundary.actorCeilings.incidentResponse.authorizationExpiryRequired = false; }, /incident alert access lacks expiry/);
  reject((boundary) => { boundary.scopeModels.nullScopeBecomesGlobal = true; }, /alert scope becomes nullable wildcard/);
  reject((boundary) => { boundary.lifecycleTransitions.find((item) => item.class === "alert-acknowledgement").concurrency = "application pre-check"; }, /acknowledgement lacks compare-and-set or lock/);
  reject((boundary) => { const transition = boundary.lifecycleTransitions.find((item) => item.class === "alert-assignment"); transition.targetState = "ASSIGNED"; transition.allowedColumns = ["licenseeId"]; }, /assignment changes tenant ownership/);
  reject((boundary) => { const transition = boundary.lifecycleTransitions.find((item) => item.class === "alert-resolution"); transition.sourceState = "OPEN"; transition.targetState = "RESOLVED"; }, /resolution can occur from an invalid state/);
  reject((boundary) => { boundary.lifecycleTransitions.find((item) => item.class === "alert-suppression").requiredReason = false; }, /suppression lacks reason or audit/);
  reject((boundary) => { boundary.allowedProjections.tenantSecurityAlertRead.push("details"); }, /secret detection payload entered projection/);
  reject((boundary) => { boundary.publicAccessDisposition.allowed = true; }, /public alert access lacks proof binding/);
  reject((boundary) => { boundary.actorCeilings.worker.humanImpersonationAllowed = true; }, /worker becomes human-attributed/);
  reject((boundary) => { boundary.workerOperatorMappings.find((item) => item.alertClass === "operator-alert-procedure").directHumanTableAccess = true; }, /operator boundary is replaced by direct table access/);
  reject((_boundary, candidateWorkflows) => { delete candidateWorkflows.workflows.find((workflow) => workflow.policyAlertActorCeilingBoundaryId).policyAlertActorCeilingBoundaryId; }, /lacks policy alert boundary ID/);
  reject((_boundary, _workflows, _rules, candidateDecisions) => { candidateDecisions.decisions.find((decision) => decision.id === "decision-context-policy-alert-actor-ceiling").status = "unresolved"; }, /decision is unresolved/);
});

test("bounded read-family batch is scoped, evidenced, and fail closed", () => {
  const { workflows, commandSemantics, tables } = manifests();
  const families = JSON.parse(fs.readFileSync(contextBoundaryFamiliesPath, "utf8"));
  const batch = JSON.parse(fs.readFileSync(contextBoundaryReadBatchPath, "utf8"));
  assert(validateContextBoundaryReadBatch(batch, families, workflows, commandSemantics, tables));
  assert.equal(batch.selectedFamilies.length, 17);
  assert.equal(batch.selectionTotals.workflowsConsidered, 24);
  assert.equal(batch.selectionTotals.reclassifiedFamilies, 2);
  assert.equal(batch.selectionTotals.splitFamilies, 4);
  assert.equal(batch.selectionTotals.childFamiliesCreated, 8);
  assert.equal(batch.selectionTotals.contractOnlyWorkflows, 2);
  assert.equal(batch.selectionTotals.newlyImplementedWorkflows, 0);
  assert.equal(batch.selectionTotals.blockedWorkflows, 22);

  const reject = (mutate, pattern) => {
    const candidateBatch = structuredClone(batch);
    const candidateFamilies = structuredClone(families);
    const candidateWorkflows = structuredClone(workflows);
    mutate(candidateBatch, candidateFamilies, candidateWorkflows);
    assert.throws(() => validateContextBoundaryReadBatch(candidateBatch, candidateFamilies, candidateWorkflows, commandSemantics, tables), pattern);
  };
  reject((candidate) => { candidate.actualChanges.productionFiles = 13; }, /production-file limit/);
  reject((candidate) => { candidate.actualChanges.testFiles = 13; }, /test-file limit/);
  reject((candidate) => { candidate.actualChanges.netProductionTestChangedLines = 3001; }, /changed-line limit/);
  reject((candidate) => { candidate.selectedFamilies[0].reviewedRisk = "high"; }, /risk ceiling/);
  reject((candidate) => { candidate.selectedFamilies[0].resolution = "implemented"; }, /invalid resolution/);
  reject((candidateBatch, candidateFamilies) => { const selected = candidateBatch.selectedFamilies.find((family) => family.resolution === "split-blocked"); candidateFamilies.families.find((family) => family.id === selected.resultingFamilyIds[0]).parentFamilyId = "family-wrong-parent"; }, /stable split lineage/);
  reject((candidateBatch, candidateFamilies) => { const selected = candidateBatch.selectedFamilies.find((family) => family.resolution === "reclassified-contract-only"); candidateFamilies.families.find((family) => family.id === selected.resultingFamilyIds[0]).automationEligibility = "blocked"; }, /special boundary became ordinary context/);
});

test("all FORCE-table commands and workflows have exact resolved semantics", () => {
  const { tables, workflows, commandSemantics, decisions } = manifests();
  const byId = new Map(commandSemantics.rules.map((rule) => [rule.id, rule]));
  assert.equal(workflows.workflows.filter((workflow) => workflow.semanticStatus === "mapped").length, workflows.workflows.length);
  for (const workflow of workflows.workflows) {
    assert(workflow.commandRuleIds.length && workflow.requiredAssurance.length && workflow.commandActorClasses.length && workflow.runtimeIdentities.length, workflow.id);
    for (const item of workflow.commandsPerTable) {
      if (!tables.tables.find((table) => table.id === item.tableId).forceRlsTarget) continue;
      for (const command of item.commands) assert(workflow.commandRuleIds.some((id) => byId.get(id)?.tableId === item.tableId && byId.get(id)?.command === command), `${workflow.id}:${item.tableId}:${command}`);
    }
  }
  for (const table of tables.tables.filter((item) => item.forceRlsTarget)) assert(commandSemantics.rules.some((rule) => rule.tableId === table.id && rule.command === "DELETE" && rule.hardDeleteSemantics === "prohibited"), table.id);
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-policy-command-semantics")?.status, "resolved");
});

test("command semantics mutation guards fail closed", () => {
  const { tables, commandSemantics } = manifests();
  const tableById = new Map(tables.tables.map((table) => [table.id, table]));
  const verify = (candidate) => {
    for (const rule of candidate.rules) {
      const table = tableById.get(rule.tableId);
      if (["INSERT", "UPDATE"].includes(rule.command)) for (const column of [...table.tenantKeyColumns, ...table.actorKeyColumns]) assert(rule.protectedColumns.includes(column), "ownership mutable");
      if (table.primaryCategory === "security-sensitive" && rule.command === "SELECT") for (const column of table.sensitiveColumns) assert(!rule.allowedColumns.includes(column), "secret selectable");
      assert(!(table.appendOnly && rule.command === "UPDATE" && rule.authorizationBoundary !== "prohibited"), "append-only update");
      if (rule.actorClasses.includes("licensee-admin") && ["User", "Invite"].includes(table.prismaModel) && ["INSERT", "UPDATE"].includes(rule.command)) assert(rule.protectedColumns.includes("role"), "platform role assignable");
      if (rule.actorClasses.includes("platform-admin")) assert(rule.minimumAssurance !== "none" && rule.requiresAuditEvent, "unconditional platform admin");
      if (rule.requiresNamedFunction) assert.notEqual(rule.authorizationBoundary, "ordinary-rls", "named function degraded");
      if (rule.requiresRestrictedWorkerBoundary) assert.equal(rule.authorizationBoundary, "restricted-worker", "worker boundary degraded");
      if (rule.lifecycleColumns.length && rule.authorizationBoundary !== "prohibited") assert(rule.allowedLifecycleStates.length, "lifecycle omitted");
    }
    for (const table of tables.tables.filter((item) => item.forceRlsTarget)) assert(candidate.rules.some((rule) => rule.tableId === table.id && rule.command === "DELETE" && rule.hardDeleteSemantics === "prohibited"), "general hard delete enabled");
  };
  const rejects = (find, mutate, pattern) => {
    const candidate = structuredClone(commandSemantics);
    const rule = candidate.rules.find(find);
    assert(rule, `missing mutation fixture ${pattern}`);
    mutate(rule, candidate);
    assert.throws(() => verify(candidate), pattern);
  };
  rejects((rule) => rule.command === "INSERT" && tableById.get(rule.tableId).tenantKeyColumns.length, (rule) => { rule.protectedColumns = rule.protectedColumns.filter((column) => !tableById.get(rule.tableId).tenantKeyColumns.includes(column)); }, /ownership mutable/);
  rejects((rule) => rule.command === "SELECT" && tableById.get(rule.tableId).primaryCategory === "security-sensitive" && tableById.get(rule.tableId).sensitiveColumns.length, (rule) => { rule.allowedColumns.push(tableById.get(rule.tableId).sensitiveColumns[0]); }, /secret selectable/);
  rejects((rule) => rule.command === "SELECT" && tableById.get(rule.tableId).appendOnly, (rule) => { rule.command = "UPDATE"; rule.authorizationBoundary = "ordinary-rls"; }, /append-only update/);
  rejects((rule) => rule.actorClasses.includes("licensee-admin") && ["INSERT", "UPDATE"].includes(rule.command) && ["User", "Invite"].includes(tableById.get(rule.tableId).prismaModel), (rule) => { rule.protectedColumns = rule.protectedColumns.filter((column) => column !== "role"); }, /platform role assignable/);
  rejects((rule) => rule.actorClasses.includes("platform-admin"), (rule) => { rule.minimumAssurance = "none"; }, /unconditional platform admin/);
  rejects((rule) => rule.requiresNamedFunction && !rule.requiresRestrictedWorkerBoundary, (rule) => { rule.authorizationBoundary = "ordinary-rls"; }, /named function degraded/);
  rejects((rule) => rule.requiresRestrictedWorkerBoundary && !rule.requiresNamedFunction, (rule) => { rule.authorizationBoundary = "ordinary-rls"; }, /worker boundary degraded/);
  rejects((rule) => rule.lifecycleColumns.length && rule.authorizationBoundary !== "prohibited", (rule) => { rule.allowedLifecycleStates = []; }, /lifecycle omitted/);
  rejects((rule) => rule.command === "DELETE" && rule.hardDeleteSemantics === "prohibited", (rule, candidate) => { candidate.rules.splice(candidate.rules.indexOf(rule), 1); }, /general hard delete enabled/);
});

test("pre-auth workflows reduce to exact functions or actor context", () => {
  const { workflows, commandSemantics, preAuthFunctions, identities, tables, decisions } = manifests();
  const selected = workflows.workflows.filter((workflow) => workflow.preAuthBoundary);
  assert.equal(selected.length, 11);
  assert.equal(preAuthFunctions.functions.length, 7);
  assert.equal(selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "ordinary-authenticated-context").length, 4);
  assert.equal(selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "operator-only").length, 0);
  assert.equal(selected.filter((workflow) => workflow.preAuthBoundary.boundaryMode === "retired").length, 0);
  assert(validatePreAuthFunctions(preAuthFunctions, workflows, commandSemantics, identities, tables));
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-pre-auth-boundary")?.status, "resolved");
});

test("pre-auth function mutation guards fail closed", () => {
  const current = manifests();
  const rejects = (mutate, pattern) => {
    const candidate = structuredClone(current);
    mutate(candidate);
    assert.throws(() => validatePreAuthFunctions(candidate.preAuthFunctions, candidate.workflows, candidate.commandSemantics, candidate.identities, candidate.tables), pattern);
  };
  rejects((candidate) => { candidate.preAuthFunctions.functions[0].arguments.push({ name: "query_json", type: "jsonb", nullable: false }); }, /generic query input/);
  rejects((candidate) => { candidate.preAuthFunctions.functions[0].publicExecutionDenied = false; }, /PUBLIC execute/);
  rejects((candidate) => { candidate.preAuthFunctions.functions[0].restrictedReadExecutionDenied = false; }, /restricted-read execute/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-auth-function-owner").loginExpectation = "LOGIN"; }, /owner may LOGIN/);
  rejects((candidate) => { candidate.preAuthFunctions.functions[0].fixedSearchPath = "pg_catalog, public"; }, /search_path/);
  rejects((candidate) => { candidate.preAuthFunctions.functions.find((fn) => fn.oneTimeToken).expiryRequired = false; }, /lacks expiry/);
  rejects((candidate) => { candidate.preAuthFunctions.functions.find((fn) => fn.oneTimeToken).oneTimeConsumptionBehavior = "not-applicable"; }, /one-time semantics/);
  rejects((candidate) => { candidate.preAuthFunctions.functions.find((fn) => fn.id === "preauth-fn-request-password-reset").externalResponseMode = "account-found"; }, /reveals account existence/);
  rejects((candidate) => { candidate.preAuthFunctions.functions.find((fn) => fn.id === "preauth-fn-consume-invitation").roleCeiling = "any stored invite role"; }, /platform-role ceiling/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-pre-auth-app").directTablePrivileges = ["SELECT public.User"]; }, /direct table privileges/);
  rejects((candidate) => { delete candidate.workflows.workflows.find((workflow) => workflow.authorizationBoundaryType === "pre-auth-security-function").preAuthBoundary; }, /pre-auth workflow lacks a boundary/);
  rejects((candidate) => { candidate.workflows.workflows.find((workflow) => workflow.preAuthBoundary?.boundaryMode === "ordinary-authenticated-context").runtimeIdentities = ["identity-pre-auth-app"]; }, /moved workflow retains pre-auth access/);
  rejects((candidate) => { candidate.preAuthFunctions.functions.find((fn) => fn.secretColumnExposures.length).secretColumnExposures[0].justification = ""; }, /secret without justification/);
});

test("worker and scheduled workflows use exact durable boundaries", () => {
  const { workerBoundaries, workflows, commandSemantics, identities, tables, decisions } = manifests();
  assert.equal(workerBoundaries.boundaries.length, 3);
  assert.equal(workerBoundaries.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-worker").length, 2);
  assert.equal(workerBoundaries.boundaries.filter((boundary) => boundary.runtimeIdentity === "identity-scheduled-job").length, 1);
  assert(validateWorkerBoundaries(workerBoundaries, workflows, commandSemantics, identities, tables));
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-worker-identity-model")?.status, "resolved");
  assert(workflows.workflows.find((workflow) => workflow.id.includes("attention-queue-service-ts-get-attention-queue-snapshot-uncached")).workerClassificationEvidence.includes("Synchronous authenticated"));
});

test("worker boundary mutation guards fail closed", () => {
  const current = manifests();
  const rejects = (mutate, pattern) => {
    const candidate = structuredClone(current);
    mutate(candidate);
    assert.throws(() => validateWorkerBoundaries(candidate.workerBoundaries, candidate.workflows, candidate.commandSemantics, candidate.identities, candidate.tables), pattern);
  };
  rejects((candidate) => { const boundary = candidate.workerBoundaries.boundaries[0]; boundary.scopeVerificationMethod = "Trust the JSON payload"; candidate.workflows.workflows.find((workflow) => workflow.workerBoundaryId === boundary.id).scopeVerificationMethod = boundary.scopeVerificationMethod; }, /unverified payload/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].idempotencyStrategy = null; }, /lacks idempotency/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].concurrencyControl.databaseEnforced = false; }, /concurrency enforcement/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].assurance = "mfa-verified"; }, /human assurance/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].platformAdminContextAllowed = true; }, /platform-admin context/);
  rejects((candidate) => { const boundary = candidate.workerBoundaries.boundaries.find((item) => item.runtimeIdentity === "identity-scheduled-job"); boundary.runtimeIdentity = "identity-worker"; boundary.auditEventRequirement.executorAttribution = "identity-worker"; const workflow = candidate.workflows.workflows.find((item) => item.workerBoundaryId === boundary.id); workflow.runtimeIdentities = ["identity-worker"]; for (const id of boundary.exactCommandRuleIds) candidate.commandSemantics.rules.find((rule) => rule.id === id).runtimeIdentities = ["identity-worker"]; }, /scheduled job uses worker identity/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].auditEventRequirement.fields = candidate.workerBoundaries.boundaries[0].auditEventRequirement.fields.filter((field) => field !== "job_id"); }, /audit lacks job identity/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].maximumJobAgeSeconds = 0; }, /maximum job age/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries.find((boundary) => boundary.namedFunctionRequirement.required).namedFunctionRequirement.genericQueryInputsAllowed = true; }, /generic worker function/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries[0].idempotencyStrategy.conflictingPayloadDenied = false; }, /conflicting replay payloads/);
  rejects((candidate) => { candidate.workerBoundaries.boundaries.find((boundary) => boundary.workerClass === "actor-derived-job").actorFields = ["initiating_user_id"]; }, /initiating actor and executor identity/);
  rejects((candidate) => { delete candidate.workflows.workflows.find((workflow) => workflow.workerBoundaryId).workerBoundaryId; }, /lacks worker-boundary ID/);
});

test("object ownership chain covers every protected class and resolves the architecture decision", () => {
  const { objectOwnershipChain, tables, identities, preAuthFunctions, workerBoundaries, decisions } = manifests();
  assert.equal(objectOwnershipChain.objectClasses.length, 17);
  assert.equal(objectOwnershipChain.migrationCompletionGate.ownershipResidueAllowed, 0);
  assert.equal(objectOwnershipChain.migrationCompletionGate.runtimeOwnedObjectsAllowed, 0);
  assert.equal(objectOwnershipChain.migrationOnlyTables.length, 2);
  assert(validateObjectOwnershipChain(objectOwnershipChain, tables, identities, preAuthFunctions, workerBoundaries));
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-object-ownership-chain")?.status, "resolved");
});

test("object ownership mutation guards fail closed", () => {
  const current = manifests();
  const rejects = (mutate, pattern) => {
    const candidate = structuredClone(current);
    mutate(candidate);
    assert.throws(() => validateObjectOwnershipChain(candidate.objectOwnershipChain, candidate.tables, candidate.identities, candidate.preAuthFunctions, candidate.workerBoundaries), pattern);
  };
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-table-owner").loginExpectation = "LOGIN"; }, /protected table owner is LOGIN/);
  rejects((candidate) => { candidate.objectOwnershipChain.migrationCompletionGate.ownershipResidueAllowed = 1; }, /migration is allowed to remain owner/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-authenticated-app").protectedObjectOwnershipAllowed = true; }, /runtime role receives ownership/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-authenticated-app").ownerRoleMemberships = ["identity-table-owner"]; }, /runtime role is a member of owner role/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-pre-auth-app").ownerRoleMemberships = ["identity-auth-function-owner"]; }, /runtime role is a member of owner role/);
  rejects((candidate) => { candidate.objectOwnershipChain.recommendedTransferModel.executorTemporaryMembership.revokedBeforeSuccess = false; }, /revocation step is removed/);
  rejects((candidate) => { candidate.objectOwnershipChain.schemaOwnershipRules.find((rule) => rule.schema === "public").publicCreate = true; }, /PUBLIC CREATE is restored/);
  rejects((candidate) => { candidate.objectOwnershipChain.schemaOwnershipRules.find((rule) => rule.schema === "app_auth").expectedOwner = "identity-table-owner"; }, /app_auth ownership changes/);
  rejects((candidate) => { candidate.objectOwnershipChain.approvedFunctionOwnerBoundaries.worker[0].securityMode = "DEFINER"; }, /SECURITY INVOKER helper becomes SECURITY DEFINER/);
  rejects((candidate) => { candidate.objectOwnershipChain.defaultPrivilegeRules.runtimeGrants = ["identity-authenticated-app:ALL TABLES"]; }, /default privileges grant table access broadly/);
  rejects((candidate) => { candidate.objectOwnershipChain.migrationCompletionGate.catalogVerificationRequired = false; }, /catalog verification is removed/);
  rejects((candidate) => { candidate.objectOwnershipChain.migrationCompletionGate.revocationFailureReportsSuccess = true; }, /migration failure may leave membership active/);
});

test("operator and break-glass workflows use finite reviewed boundaries", () => {
  const { operatorBoundaries, workflows, commandSemantics, identities, decisions } = manifests();
  const selectedWorkflows = workflows.workflows.filter((workflow) => workflow.commandActorClasses?.some((actor) => ["operator-admin", "break-glass"].includes(actor)));
  const selectedRules = commandSemantics.rules.filter((rule) => rule.actorClasses.some((actor) => ["operator-admin", "break-glass"].includes(actor)));
  assert.equal(operatorBoundaries.boundaries.length, 29);
  assert.equal(selectedWorkflows.length, 27);
  assert.equal(selectedRules.length, 88);
  assert(selectedWorkflows.every((workflow) => workflow.operatorBoundaryId));
  assert(selectedRules.every((rule) => rule.operatorBoundaryIds?.length));
  assert(validateOperatorBoundaries(operatorBoundaries, workflows, commandSemantics, identities));
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-operator-administration")?.status, "resolved");
});

test("operator boundary mutation guards fail closed", () => {
  const current = manifests();
  const rejects = (mutate, pattern) => {
    const candidate = structuredClone(current);
    mutate(candidate);
    assert.throws(() => validateOperatorBoundaries(candidate.operatorBoundaries, candidate.workflows, candidate.commandSemantics, candidate.identities), pattern);
  };
  rejects((candidate) => { candidate.operatorBoundaries.arbitrarySqlAllowed = true; }, /arbitrary SQL is allowed/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-operator").mayOwnProtectedObjects = true; }, /operator owns an object/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-operator").ownerRoleMemberships = ["identity-table-owner"]; }, /owner-role membership/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-operator").maySetRole = true; }, /SET ROLE is enabled/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-operator").mayUseBypassRls = true; }, /BYPASSRLS is enabled/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.environmentAvailability.includes("production") && boundary.actionClass !== "prohibited").ticketRequirement = false; }, /production ticket requirement is removed/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.approvalRequirement.required).approvalRequirement.required = false; }, /sensitive action approval requirement is removed/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.id === "operator-boundary-breakglass-issuance").maximumDurationMinutes = 0; }, /break-glass expiry is removed|lacks action expiry/);
  rejects((candidate) => { candidate.identities.identities.find((identity) => identity.id === "identity-production-break-glass").sharedCredential = true; }, /break-glass becomes shared/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "account-recovery").roleElevationAllowed = true; }, /platform-admin promotion/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "mfa-repair").tenantReassignmentAllowed = true; }, /tenant reassignment/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "data-retention-redaction").auditDeletionAllowed = true; }, /audit deletion/);
  rejects((candidate) => { delete candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "RLS-activation-control").rollbackBoundaryId; }, /activation lacks rollback/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "read-diagnostics").returnedFields.push("passwordHash"); }, /diagnostics expose password\/token hashes/);
  rejects((candidate) => { candidate.operatorBoundaries.boundaries.find((boundary) => boundary.actionClass === "incident-containment").unrestrictedCrossTenantScope = true; }, /cross-tenant scope is unbounded/);
});

test("tests do not inflate production totals and repeated technical calls remain one functional workflow", () => {
  const { accesses } = scanProductionAccess();
  assert(accesses.every((item) => !/(?:^|\/)tests?\//.test(item.sourceFile)), "test-only access leaked into production totals");
  const workflows = manifests().workflows.workflows;
  const keys = workflows.map((workflow) => `${workflow.executionSurface}:${workflow.canonicalSourceFiles.join(",")}:${workflow.entryPoint}`);
  assert.equal(new Set(keys).size, keys.length, "duplicate canonical workflows exist");
  assert(workflows.some((workflow) => workflow.supportingEvidence.length > workflow.tablesTouched.length), "technical call sites were not deduplicated");
  for (const model of ["PrintReissueRequest", "OwnershipTransfer", "AuthWebAuthnChallenge", "VerificationDecision", "CustomerTrustCredential"]) assert(accesses.some((access) => access.prismaModel === model), `${model} barrel/alias access was not detected`);
});

test("unregistered or legacy classifications require import and registration evidence", () => {
  const { workflows } = manifests();
  for (const item of workflows.generatedEvidence.unregisteredPotentiallyDeadAccesses) {
    assert.equal(item.production, false);
    assert.equal(item.registrationEvidence, "unregistered");
    assert(fs.existsSync(path.join(repoRoot, item.sourceFile)), `${item.id} source evidence is missing`);
  }
  assert(!workflows.workflows.some((workflow) => /dead|legacy/.test(workflow.currentCompatibilityStatus)), "production workflow was automatically declared dead");
});

test("security-sensitive tables and runtime identities fail closed", () => {
  const { tables, identities, decisions } = manifests();
  for (const table of tables.tables.filter((item) => item.category === "security-sensitive")) {
    assert.match(table.rowOwnershipModel, /^Special /);
    assert(table.preAuthAccessMode && !/^direct/i.test(table.preAuthAccessMode));
    assert.notEqual(table.policyStatus, "ordinary-tenant-access");
  }
  for (const identity of identities.identities) {
    assert.equal(identity.mayUseBypassRls, false);
    assert.equal(identity.superuser, false);
  }
  validateRuntimeIdentities(identities, decisions);
});

test("all tables have resolved ownership, command, FORCE, and exception classifications", () => {
  const { tables, identities, decisions } = manifests();
  const identityById = new Map(identities.identities.map((identity) => [identity.id, identity]));
  assert.equal(tables.tables.length, 77);
  assert.equal(tables.tables.filter((table) => table.forceRlsTarget).length, 75);
  assert.deepEqual(tables.tables.filter((table) => table.primaryCategory === "migration-only").map((table) => table.prismaModel).sort(), ["BatchPrintPackToken", "PrintRenderToken"]);
  assert.equal(tables.tables.filter((table) => table.primaryCategory === "intentionally-non-rls").length, 0);
  for (const table of tables.tables) {
    assert.equal(table.classificationStatus, "resolved", table.id);
    assert(table.primaryCategory && table.physicalOwnerRole && table.rowOwnershipModel, table.id);
    assert.equal(identityById.get(table.physicalOwnerRole)?.loginExpectation, "NOLOGIN", table.id);
    assert.equal(table.primaryCategory !== "parent-inherited" || Boolean(table.authorizationParentTable), true, table.id);
    assert.equal(table.schemaEvidence.fields.some((field) => table.tenantKeyColumns.includes(field.name) && field.optional) && !table.tenantKeyNullSemantics, false, table.id);
    if (table.productionRuntimeWriters.length) assert(table.allowedCommandsByIdentity.length, `${table.id} writers lack a command matrix`);
    for (const identityId of [...table.allowedRuntimeReaders, ...table.allowedRuntimeWriters, ...table.allowedCommandsByIdentity.map((entry) => entry.identityId)]) assert(identityById.has(identityId), `${table.id} -> ${identityId}`);
    if (table.appendOnly) for (const entry of table.allowedCommandsByIdentity) {
      assert(!entry.commands.includes("UPDATE"), table.id);
      assert(!entry.commands.includes("DELETE") || entry.conditions.some((condition) => /retention|redaction/i.test(condition)), table.id);
    }
    if (table.primaryCategory === "migration-only") assert.equal(table.productionRuntimeReaders.length + table.productionRuntimeWriters.length + table.allowedCommandsByIdentity.length, 0, table.id);
  }
  assert.equal(decisions.decisions.find((decision) => decision.id === "decision-table-ownership-classification")?.status, "resolved");
});

test("policy dependency graph is complete, explicit, and acyclic", () => {
  const graph = JSON.parse(fs.readFileSync(policyDependencyGraphPath, "utf8"));
  const tableIds = new Set(manifests().tables.tables.map((table) => table.id));
  assert.deepEqual(new Set(graph.nodes.map((node) => node.id)), tableIds);
  assert.equal(graph.edges.length, 38);
  const dependencies = new Map([...tableIds].map((id) => [id, graph.edges.filter((edge) => edge.sourceTable === id).map((edge) => edge.dependencyTable)]));
  const tableById = new Map(manifests().tables.tables.map((table) => [table.id, table]));
  const visit = (id, stack = new Set()) => {
    assert(!stack.has(id), `cycle at ${id}`);
    stack.add(id);
    for (const dependency of dependencies.get(id)) visit(dependency, new Set(stack));
  };
  for (const id of tableIds) visit(id);
  const terminal = (id) => dependencies.get(id).length ? terminal(dependencies.get(id)[0]) : tableById.get(id).terminalBoundary;
  for (const table of tableById.values()) if (table.primaryCategory === "parent-inherited") assert(["tenant-root", "tenant-key", "actor-key"].includes(terminal(table.id)), table.id);
  for (const edge of graph.edges) {
    assert.notEqual(edge.sourceTable, edge.dependencyTable);
    assert(edge.reason && edge.requiredIndexOrJoinKey && edge.joinKey.sourceColumns.length && edge.joinKey.dependencyColumns.length);
    assert.equal(edge.plannerSensitiveHiddenDependency, false);
    assert.equal(edge.unrestrictedRuntimeOwnedDependency, false);
  }
  assert.equal(graph.acyclic, true);
  assert.equal(graph.selfRecursivePolicies, 0);
});

test("runtime-role validator rejects unsafe ownership, privilege, credential, and break-glass designs", () => {
  const { identities, decisions } = manifests();
  const rejects = (id, mutate, pattern) => {
    const candidate = structuredClone(identities);
    mutate(candidate.identities.find((identity) => identity.id === id), candidate.identities);
    assert.throws(() => validateRuntimeIdentities(candidate, decisions), pattern);
  };
  rejects("identity-authenticated-app", (identity) => { identity.superuser = true; }, /superuser/);
  rejects("identity-worker", (identity) => { identity.mayUseBypassRls = true; }, /BYPASSRLS/);
  rejects("identity-authenticated-app", (identity) => { identity.mayOwnProtectedTables = true; }, /may own protected tables/);
  rejects("identity-table-owner", (identity) => { identity.loginExpectation = "LOGIN"; }, /owner role must be NOLOGIN|runtime identity may own/);
  rejects("identity-pre-auth-app", (identity, candidate) => { identity.credentialSource = candidate.find((item) => item.id === "identity-authenticated-app").credentialSource; }, /must not share credential sources/);
  rejects("identity-pre-auth-app", (identity) => { identity.allowedCommands.push("SELECT"); }, /pre-auth may only/);
  rejects("identity-restricted-read", (identity) => { identity.allowedCommands.push("UPDATE"); }, /restricted read/);
  rejects("identity-migration", (identity) => { identity.maySetRole = true; }, /SET ROLE/);
  rejects("identity-production-break-glass", (identity) => { identity.standingCredential = true; }, /standing credential/);
  rejects("identity-worker", (identity) => { delete identity.environmentRoleNames.production; }, /patterns are incomplete|production role name/);
});

test("activation remains manual and the shared-table apply remains blocked", () => {
  assert(sharedApplyIsBlocked());
  const productionSources = scanProductionAccess().activeFiles.map((file) => fs.readFileSync(path.join(repoRoot, file), "utf8")).join("\n");
  assert(!productionSources.includes("mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql"), "production code references blocked apply SQL");
  for (const migrationDirectory of fs.readdirSync(path.join(repoRoot, "backend/prisma/migrations"))) {
    const file = path.join(repoRoot, "backend/prisma/migrations", migrationDirectory, "migration.sql");
    if (fs.existsSync(file)) assert(!fs.readFileSync(file, "utf8").includes("Shared batch RLS apply blocked"), `${file} embeds the blocked apply`);
  }
});

test("human manifests are present and parseable", () => {
  assert(JSON.parse(fs.readFileSync(identityManifestPath, "utf8")).identities.length >= 10);
  assert(JSON.parse(fs.readFileSync(decisionManifestPath, "utf8")).decisions.length > 0);
  assert(JSON.parse(fs.readFileSync(commandSemanticsPath, "utf8")).rules.length > 0);
  assert(fs.readFileSync(commandSemanticsReviewPath, "utf8").includes("Boundary and deletion summary"));
  assert.equal(JSON.parse(fs.readFileSync(preAuthFunctionsPath, "utf8")).functions.length, 7);
  assert(fs.readFileSync(preAuthBoundaryReviewPath, "utf8").includes("Exact function families"));
  assert.equal(JSON.parse(fs.readFileSync(workerBoundariesPath, "utf8")).boundaries.length, 3);
  assert(fs.readFileSync(workerIdentityReviewPath, "utf8").includes("Approved boundaries"));
  assert.equal(JSON.parse(fs.readFileSync(objectOwnershipChainPath, "utf8")).objectClasses.length, 17);
  assert(fs.readFileSync(objectOwnershipReviewPath, "utf8").includes("Migration lifecycle"));
  assert.equal(JSON.parse(fs.readFileSync(operatorBoundariesPath, "utf8")).boundaries.length, 29);
  assert(fs.readFileSync(operatorAdministrationReviewPath, "utf8").includes("Break-glass lifecycle"));
});
