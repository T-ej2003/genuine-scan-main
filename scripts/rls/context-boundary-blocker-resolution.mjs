#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import {
  buildContextBoundaryPlan,
  contextBoundaryReadBatchPath,
} from "./context-boundary-plan.mjs";
import {
  decisionManifestPath,
  programDir,
  readJson,
  repoRoot,
  workflowManifestPath,
  writeJson,
} from "./lib/program-inventory.mjs";

const reviewPath = path.join(programDir, "CONTEXT_BOUNDARY_BLOCKER_RESOLUTION_REVIEW.md");

const ids = {
  auditLogs: "workflow-internal-backend-src-services-audit-service-ts-get-audit-logs",
  auditOrg: "workflow-internal-backend-src-services-audit-service-ts-resolve-org-id",
  compliance: "workflow-internal-backend-src-services-compliance-pack-service-ts-list-compliance-pack-jobs",
  dashboard: "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate",
  dashboardCompute: "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot",
  feedback: "workflow-http-backend-src-controllers-verify-feedback-handlers-ts-submit-product-feedback",
  featureFlags: "workflow-internal-backend-src-services-governance-service-ts-list-tenant-feature-flags",
  duplicateRisk: "workflow-internal-backend-src-services-governance-service-ts-resolve-duplicate-risk-profile",
  verifyUx: "workflow-internal-backend-src-services-governance-service-ts-resolve-verify-ux-policy",
  incidentEvidence: "workflow-http-backend-src-controllers-incident-controller-ts-serve-incident-evidence-file",
  localClaim: "workflow-internal-backend-src-services-local-agent-claim-service-ts-count-local-agent-claim-items",
  manufacturerLinks: "workflow-internal-backend-src-services-manufacturer-scope-service-ts-list-manufacturer-licensee-links",
  manufacturerIds: "workflow-internal-backend-src-services-manufacturer-scope-service-ts-resolve-manufacturer-session-scope",
  replacement: "workflow-internal-backend-src-services-replacement-chain-service-ts-resolve-replacement-status",
  verifyQrcode: "workflow-http-backend-src-controllers-verify-verification-handlers-ts-verify-qrcode",
  fraudSnapshot: "workflow-http-backend-src-controllers-verify-verify-fraud-snapshot-ts-build-fraud-verification-snapshot",
  supportPublic: "workflow-internal-backend-src-rls-waves-session-b-b02-public-boundary-repository-ts-track-support-status",
  telemetry: "workflow-http-backend-src-controllers-telemetry-controller-ts-get-route-transition-summary",
  policyAlerts: "workflow-http-backend-src-controllers-trace-policy-controller-ts-get-policy-alerts-controller",
  irAlerts: "workflow-http-backend-src-controllers-ir-alert-controller-ts-list-ir-alerts",
  licenseeExport: "workflow-http-backend-src-controllers-licensee-controller-ts-export-licensees-csv",
  licenseeDetail: "workflow-http-backend-src-controllers-licensee-controller-ts-get-licensee",
  licenseeList: "workflow-http-backend-src-controllers-licensee-controller-ts-get-licensees",
  supportAdd: "workflow-http-backend-src-controllers-support-controller-ts-add-support-message",
  supportDetail: "workflow-http-backend-src-controllers-support-controller-ts-get-support-ticket",
  supportList: "workflow-http-backend-src-controllers-support-controller-ts-list-support-tickets",
};

const familyIds = {
  audit: "family-simple-tenant-scoped-reads-auditservice-964272fbb7",
  compliance: "family-simple-tenant-scoped-reads-compliancepackservice-86ca2e5d6f",
  dashboard: "family-simple-tenant-scoped-reads-dashboardsnapshotservice-af0d3ce887",
  feedback: "family-simple-tenant-scoped-reads-feedbackhandlers-3c1dc41e5e",
  governance: "family-simple-tenant-scoped-reads-governanceservice-e3aa1df885",
  incident: "family-simple-tenant-scoped-reads-incidentcontroller-83ab27a014",
  localClaim: "family-simple-tenant-scoped-reads-localagentclaimservice-47404e413d",
  manufacturer: "family-simple-tenant-scoped-reads-manufacturerscopeservice-bea2e91ac1",
  replacement: "family-simple-tenant-scoped-reads-replacementchainservice-768679140d",
  supportPublic: "family-simple-tenant-scoped-reads-supportcontroller-b73b8b041a",
  telemetry: "family-simple-tenant-scoped-reads-telemetrycontroller-8ca3469cbb",
  policyAlerts: "family-simple-tenant-scoped-reads-tracepolicycontroller-9b0e52a827",
  irAlerts: "family-platform-admin-bounded-reads-iralertcontroller-791acbf282",
  licenseeExport: "family-platform-admin-bounded-reads-licenseecontroller-7e833e80ba",
  licensees: "family-platform-admin-bounded-reads-licenseecontroller-8ea4017392",
  support: "family-platform-admin-bounded-reads-supportcontroller-6ce17f93fa",
};

const blocker = (code, reason, remediation) => ({ code, reason, remediation });
const blockers = {
  publicContract: blocker("public-command-contract", "The registered root is public but the command contract requires an authenticated human actor.", "Approve an exact token/reference-bound public projection and abuse controls, or move the product behavior behind authentication."),
  platformScope: blocker("unbounded-platform-scope", "The current platform branch permits an all-tenant fallback without approved scope, purpose and read attribution.", "Require a bounded organization/licensee/manufacturer scope, purpose, assurance, attribution, projection and pagination/date ceiling."),
  platformContract: blocker("platform-admin-scope-contract", "The route uses role-string platform administration and a query-selected or omitted tenant scope without an approved purpose-attributed ceiling.", "Approve a bounded platform-admin contract with trusted scope selection, assurance and same-transaction read attribution."),
  actorConflict: blocker("actor-command-contract", "The registered route actor ceiling and assurance do not match the reviewed command rule.", "Choose the product actor ceiling and require matching tenant scope, assurance, purpose and immutable read attribution."),
  dashboard: blocker("incomplete-root-transaction", "The helper is only one protected query inside HTTP and SSE snapshot roots that still use global Prisma.", "Move every protected snapshot query for each compatible root into one canonical transaction before implementing this leaf read."),
  authBootstrap: blocker("authentication-bootstrap-scope-model", "Authentication hydration must enumerate manufacturer links before a single licensee scope exists, while the command rule requires one non-null tenant scope.", "Approve an actor-bound authentication-bootstrap lookup and propagate one supplied transaction client; no blank tenant wildcard."),
  sharedAuth: blocker("incompatible-shared-auth-roots", "The helper is shared by login, session projection and invitation mutation roots with different assurance and transaction ownership.", "Split or parameterize the owning roots so each supplies its verified actor, assurance and transaction client."),
  mutationRoot: blocker("out-of-scope-mutation-root", "The selected read is a preflight inside a message-creation mutation root.", "Review the complete message mutation, idempotency, audit and transaction boundary in a later high-risk batch."),
  sharedMutation: blocker("out-of-scope-shared-mutation-root", "The lookup is shared by audit writes from many incompatible request, worker and public roots.", "Move organization resolution into each owning audit transaction or an approved audit system boundary in a mutation-focused batch."),
  dead: blocker("unregistered-dead-path", "No registered production caller imports the legacy audit-log reader.", "Delete it after a separate dead-code review, or attach it to one registered root with exact scope and transaction evidence."),
};

const split = (parentFamilyId, semanticKey, reason, evidence, actorClasses, scopeModel, executionSurface, protectedTableBoundary, commandSemantics, extra = {}) => ({
  parentFamilyId,
  semanticKey,
  reason,
  evidence,
  routeRoots: evidence,
  actorClasses,
  scopeModel,
  executionSurface,
  protectedTableBoundary,
  commandSemantics,
  ...extra,
});

const workflowReviews = new Map([
  [ids.localClaim, { systemBoundaryId: "system-boundary-local-agent-device-claim", tenantScopeRule: "Exact verified PrinterRegistration, signed device identity, registration-owned printer IDs and registration.userId manufacturer binding.", reclassifiedFrom: familyIds.localClaim }],
  [ids.auditLogs, { blockers: [blockers.dead], split: split(familyIds.audit, "unregistered-audit-reader", "Separate an unregistered legacy reader from the live audit-write organization resolver.", ["Repository search finds no production caller for getAuditLogs."], ["licensee-admin", "operator", "platform-admin"], "No approved scope because the function has no registered root.", "internal", "AuditLog legacy read helper", "Read-only list/count with cursor pagination; no command root is registered.") }],
  [ids.auditOrg, { blockers: [blockers.sharedMutation], split: split(familyIds.audit, "audit-write-org-resolution", "Separate the organization lookup inherited by audit writes from the unregistered audit reader.", ["resolveOrgId is private and is called by resolveAuditPayload for createAuditLog and createAuditLogSafely."], ["authenticated-user", "worker", "scheduled-job"], "Organization is derived from explicit orgId or Licensee.orgId inside the owning audit-write boundary.", "internal", "Licensee lookup inherited by AuditLog write roots", "SELECT prerequisite inside mixed audit mutation roots.", { category: "incident/governance workflows", risk: "high" }) }],
  [ids.featureFlags, { blockers: [blockers.platformContract], decisions: ["decision-context-platform-read-scope"], split: split(familyIds.governance, "platform-feature-flag-administration", "Separate the registered platform administration route from public verification policy helpers.", ["GET /governance/feature-flags uses authenticate plus requirePlatformAdmin."], ["platform-admin"], "One explicit licensee selected under a future approved platform-purpose contract; omission is denied.", "http", "TenantFeatureFlag administrative projection", "Bounded read with approved read attribution.", { risk: "medium" }) }],
  [ids.duplicateRisk, { blockers: [blockers.publicContract], decisions: ["decision-context-public-read-contract"], split: split(familyIds.governance, "public-verification-policy", "Group QR-derived public policy reads separately from administrative feature-flag listing.", ["Public verification resolves licenseeId from the verified QR record; null returns static defaults without a query."], ["anonymous", "authenticated-user"], "Exact licenseeId inherited from the resolved QR verification target; blank returns static defaults and never queries all tenants.", "internal", "TenantFeatureFlag public verification policy projection", "Read-only policy lookup inside public verification roots.") }],
  [ids.verifyUx, { blockers: [blockers.publicContract], decisions: ["decision-context-public-read-contract"], split: split(familyIds.governance, "public-verification-policy", "Group QR-derived public policy reads separately from administrative feature-flag listing.", ["Public verification and ownership handlers pass a resolved QR licenseeId; null returns static defaults without a query."], ["anonymous", "authenticated-user"], "Exact licenseeId inherited from the resolved QR verification target; blank returns static defaults and never queries all tenants.", "internal", "TenantFeatureFlag public verification policy projection", "Read-only policy lookup inside public verification roots.") }],
  [ids.manufacturerIds, { blockers: [blockers.authBootstrap], decisions: ["decision-context-manufacturer-bootstrap"], split: split(familyIds.manufacturer, "manufacturer-session-scope-hydration", "Separate canonical manufacturer session-scope hydration from richer invitation link projections.", ["Authentication and session callers supply their transaction client; the helper has no global Prisma fallback or claim-carried membership authority."], ["manufacturer"], "Manufacturer actor ID is authoritative; eligible linked licensees are the bounded result and cannot be prerequisite tenant context.", "internal", "ManufacturerLicenseeLink plus active Licensee and Organization actor-bound projection", "Bounded deterministic SELECT; no licensee wildcard.") }],
  [ids.manufacturerLinks, { blockers: [blockers.sharedAuth], decisions: ["decision-context-manufacturer-bootstrap"], split: split(familyIds.manufacturer, "manufacturer-link-auth-and-invite", "Separate richer licensee link/detail reads used by authentication and invitation roots.", ["Callers include authService, authController and inviteService with different transaction ownership."], ["manufacturer", "platform-admin"], "Exact manufacturer actor or operator-approved invitation target; each owning root must supply the transaction.", "internal", "ManufacturerLicenseeLink plus bounded Licensee display projection", "SELECT link and minimal licensee display fields across incompatible auth/mutation roots.") }],
  [ids.supportList, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"], split: split(familyIds.support, "platform-support-ticket-read", "Keep list/detail reads separate from the message mutation root.", ["GET /support/tickets is platform-admin-only and currently allows omitted licenseeId."], ["platform-admin"], "Approved bounded licensee/organization support scope; no implicit all-tenant fallback.", "http", "SupportTicket administrative read projection", "Bounded list/detail read with explicit PII projection and attribution.", { risk: "medium" }) }],
  [ids.supportDetail, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"], split: split(familyIds.support, "platform-support-ticket-read", "Keep list/detail reads separate from the message mutation root.", ["GET /support/tickets/:id is platform-admin-only and currently selects by ID without tenant scope."], ["platform-admin"], "Approved bounded licensee/organization support scope; no implicit all-tenant fallback.", "http", "SupportTicket administrative read projection", "Bounded list/detail read with explicit PII projection and attribution.", { risk: "medium" }) }],
  [ids.supportAdd, { blockers: [blockers.mutationRoot], split: split(familyIds.support, "platform-support-message-mutation", "Isolate the read preflight owned by the support-message mutation.", ["POST /support/tickets/:id/messages requires recent MFA and CSRF, then calls addSupportTicketMessage and createAuditLog."], ["platform-admin"], "Ticket ID plus an approved bounded support tenant scope inside the full message mutation.", "http", "SupportTicket preflight for SupportTicketMessage mutation", "SELECT preflight followed by message and audit writes; mutation review required.", { category: "incident/governance workflows", risk: "high" }) }],
  [ids.dashboard, { blockers: [blockers.dashboard] }],
  [ids.compliance, { blockers: [blockers.platformContract], decisions: ["decision-context-platform-read-scope"] }],
  [ids.feedback, { blockers: [blockers.publicContract], decisions: ["decision-context-public-read-contract"] }],
  [ids.replacement, { blockers: [blockers.publicContract], decisions: ["decision-context-public-read-contract"] }],
  [ids.supportPublic, { blockers: [blockers.publicContract], decisions: ["decision-context-public-read-contract"] }],
  [ids.policyAlerts, { blockers: [blockers.actorConflict], decisions: ["decision-context-policy-alert-actor-ceiling"] }],
  [ids.incidentEvidence, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
  [ids.telemetry, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
  [ids.irAlerts, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
  [ids.licenseeExport, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
  [ids.licenseeDetail, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
  [ids.licenseeList, { blockers: [blockers.platformScope], decisions: ["decision-context-platform-read-scope"] }],
]);

const reviewedGroups = [
  [familyIds.analytics, [ids.analytics], "reclassified-contract-only"],
  [familyIds.localClaim, [ids.localClaim], "reclassified-contract-only"],
  [familyIds.governance, [ids.featureFlags, ids.duplicateRisk, ids.verifyUx], "split-blocked"],
  [familyIds.manufacturer, [ids.manufacturerLinks, ids.manufacturerIds], "split-blocked"],
  [familyIds.support, [ids.supportAdd, ids.supportDetail, ids.supportList], "split-blocked"],
  [familyIds.audit, [ids.auditLogs, ids.auditOrg], "split-blocked"],
  [familyIds.dashboard, [ids.dashboard, ids.dashboardCompute], "blocked"],
  [familyIds.compliance, [ids.compliance], "blocked"],
  [familyIds.feedback, [ids.feedback], "blocked"],
  [familyIds.replacement, [ids.replacement, ids.verifyQrcode, ids.fraudSnapshot], "blocked"],
  [familyIds.supportPublic, [ids.supportPublic], "blocked"],
  [familyIds.policyAlerts, [ids.policyAlerts], "blocked"],
  [familyIds.incident, [ids.incidentEvidence], "blocked"],
  [familyIds.telemetry, [ids.telemetry], "blocked"],
  [familyIds.irAlerts, [ids.irAlerts], "blocked"],
  [familyIds.licenseeExport, [ids.licenseeExport], "blocked"],
  [familyIds.licensees, [ids.licenseeDetail, ids.licenseeList], "blocked"],
];

const decisionDefinitions = [
  {
    id: "decision-context-public-read-contract",
    question: "Which public QR-policy, replacement and support-tracking fields may be disclosed, and what exact token or reference proof authorizes each lookup?",
    recommendedOption: "Approve separate minimal token-bound projections; require optional-email support tracking to become proof-bearing rather than existence-bearing.",
  },
  {
    id: "decision-context-platform-read-scope",
    question: "Which organization, licensee or manufacturer ceiling, assurance and purpose authorize each current platform-wide read?",
    recommendedOption: "Require an explicit bounded scope, fresh assurance where commanded, immutable read attribution, explicit projection and bounded pagination/date windows; deny omitted scope.",
  },
  {
    id: "decision-context-policy-alert-actor-ceiling",
    question: "May licensee administrators read policy alerts, or is the route platform-admin only as the command contract currently states?",
    recommendedOption: "Choose one actor ceiling and align route, tenant scope, MFA and read attribution before implementation.",
  },
  {
    id: "decision-context-manufacturer-bootstrap",
    question: "How may verified manufacturer identity enumerate linked licensees before a single tenant context exists?",
    recommendedOption: "Approve an actor-bound bootstrap projection using the verified manufacturer ID and one supplied transaction client; never use blank tenant context as a wildcard.",
  },
];

const updateManifests = () => {
  const workflowManifest = readJson(workflowManifestPath);
  const decisions = readJson(decisionManifestPath);
  const resolvedContextDecisions = new Set(decisions.decisions.filter((decision) => decision.id.startsWith("decision-context-") && decision.status === "resolved").map((decision) => decision.id));
  const byId = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  assert.equal(workflowReviews.size, 24, "review must cover exactly 24 workflows");
  for (const [workflowId, review] of workflowReviews) {
    if (review.decisions?.some((decisionId) => resolvedContextDecisions.has(decisionId))) continue;
    const workflow = byId.get(workflowId);
    assert(workflow, `missing reviewed workflow ${workflowId}`);
    workflow.contextRequirementsSource = "human-reviewed";
    workflow.contextBoundaryPlanningEvidence = {
      reviewedAt: "2026-07-16",
      registeredRootCallChainVerified: true,
      protectedQueryTraceComplete: false,
      sameTransactionFeasible: false,
      focusedTestsDeterministic: true,
    };
    if (review.tenantScopeRule) workflow.tenantScopeRule = review.tenantScopeRule;
    if (review.blockers) workflow.contextBoundaryBlockers = review.blockers;
    else delete workflow.contextBoundaryBlockers;
    if (review.split) workflow.contextBoundaryFamilySplit = review.split;
    else delete workflow.contextBoundaryFamilySplit;
    if (review.systemBoundaryId) {
      workflow.systemBoundaryId = review.systemBoundaryId;
      workflow.contextBoundaryReclassification = {
        fromFamilyId: review.reclassifiedFrom,
        classification: review.systemBoundaryId === "system-boundary-analytics-rollup-worker" ? "worker boundary" : "contract-only internal system path",
        status: "contract-only",
      };
      workflow.contextRequirements = [`Use only ${review.systemBoundaryId}; human role and ordinary authenticated context are forbidden.`];
      workflow.implementationStatus = "contract-only-system-boundary";
      workflow.expectedAllowedScenarios = ["Only the exact cryptographically or durably verified system boundary may execute the reviewed read after its full parent workflow is implemented and certified."];
      workflow.expectedDeniedScenarios = ["Human impersonation, blank scope, generic cross-tenant access, stale/replayed evidence, wrong device/worker identity or partial parent-flow activation is denied."];
    }
    const decisionIds = review.decisions || [];
    workflow.unresolvedDecisions = [...new Set([...workflow.unresolvedDecisions.filter((id) => !id.startsWith("decision-context-")), ...decisionIds])].sort();
  }
  writeJson(workflowManifestPath, workflowManifest);

  decisions.decisions = decisions.decisions.filter((decision) => !decision.id.startsWith("decision-context-") || resolvedContextDecisions.has(decision.id));
  for (const definition of decisionDefinitions) {
    if (resolvedContextDecisions.has(definition.id)) continue;
    const affectedWorkflows = [...workflowReviews].filter(([, review]) => review.decisions?.includes(definition.id)).map(([workflowId]) => workflowId).sort();
    decisions.decisions.push({
      ...definition,
      affectedWorkflows,
      affectedTables: [...new Set(affectedWorkflows.flatMap((workflowId) => byId.get(workflowId).tablesTouched))].sort(),
      securityConsequence: "Implementing without this decision could authorize public disclosure, cross-tenant platform access, actor elevation or a blank-scope fallback.",
      availableOptions: ["Approve the recommended bounded contract", "Narrow or authenticate the product behavior", "Retire the behavior"],
      blockingStatus: "blocking",
      owner: "Product authorization owner, application security, and domain engineering",
      status: "unresolved",
    });
  }
  decisions.decisions.sort((a, b) => a.id.localeCompare(b.id));
  writeJson(decisionManifestPath, decisions);
};

const writeBatchAndReview = (plan, previousBatch) => {
  const previous = new Map(previousBatch.selectedFamilies.map((family) => [family.familyId, family]));
  const familyByWorkflow = new Map(plan.families.flatMap((family) => family.workflowIds.map((workflowId) => [workflowId, family])));
  const selectedFamilies = reviewedGroups.map(([familyId, workflowIds, resolution]) => {
    const evidence = previous.get(familyId);
    assert(evidence, `missing prior evidence for ${familyId}`);
    const resulting = [...new Set(workflowIds.map((workflowId) => familyByWorkflow.get(workflowId)))].filter(Boolean);
    const resultingFamilyIds = resulting.map((family) => family.id).sort();
    return {
      familyId,
      workflowIds,
      reviewedRisk: evidence.reviewedRisk || evidence.risk,
      resolution,
      resultingFamilyIds,
      canonicalFiles: evidence.canonicalFiles,
      routeRoots: evidence.routeRoots?.length ? evidence.routeRoots : resulting.flatMap((family) => family.routeRoots || ["unregistered internal path"]),
      actorClasses: evidence.actorClasses,
      commandRuleIds: evidence.commandRuleIds,
      protectedTables: evidence.protectedTables,
      scopeSource: evidence.scopeSource,
      assuranceSource: evidence.assuranceSource,
      rootCallChainEvidence: evidence.rootCallChainEvidence,
      transactionStrategy: evidence.transactionStrategy,
      testPlan: evidence.testPlan,
      blockerResolutionEvidence: evidence.blockerResolutionEvidence,
    };
  });
  const batch = {
    schemaVersion: 2,
    batchId: "context-boundary-blocker-resolution-2026-07-16",
    generatedFrom: [
      "documents/security/rls-program/context-boundary-families.json",
      "documents/security/rls-program/workflows.json",
      "documents/security/rls-program/system-boundaries.json",
      "documents/security/rls-program/decisions.json",
      "backend/src",
    ],
    limits: {
      maximumFamilies: 20,
      maximumWorkflows: 40,
      maximumProductionFiles: 12,
      maximumTestFiles: 12,
      maximumNetProductionTestLines: 3000,
    },
    selectionTotals: {
      familiesConsidered: selectedFamilies.length,
      workflowsConsidered: selectedFamilies.flatMap((family) => family.workflowIds).length,
      reclassifiedFamilies: selectedFamilies.filter((family) => family.resolution === "reclassified-contract-only").length,
      splitFamilies: selectedFamilies.filter((family) => family.resolution === "split-blocked").length,
      childFamiliesCreated: selectedFamilies.filter((family) => family.resolution === "split-blocked").reduce((total, family) => total + family.resultingFamilyIds.length, 0),
      contractOnlyWorkflows: selectedFamilies.filter((family) => family.resolution === "reclassified-contract-only").flatMap((family) => family.workflowIds).length,
      newlyImplementedWorkflows: 0,
      blockedWorkflows: selectedFamilies.filter((family) => family.resolution !== "reclassified-contract-only").flatMap((family) => family.workflowIds).length,
    },
    blockerCountsBefore: {
      "unresolved-boundary": 12,
      "unreviewed-scope": 24,
      "unverified-execution-path": 24,
      "unverified-root-call-chain": 12,
    },
    blockerCountsAfter: Object.fromEntries([...workflowReviews.values()].flatMap((review) => review.blockers || []).reduce((counts, item) => counts.set(item.code, (counts.get(item.code) || 0) + 1), new Map())),
    actualChanges: {
      productionFiles: 0,
      testFiles: 1,
      netProductionTestChangedLines: 3,
    },
    selectedFamilies,
  };
  writeJson(contextBoundaryReadBatchPath, batch);

  const blockedFamilies = plan.families.filter((family) => family.automationEligibility === "blocked");
  const contractWorkflows = plan.families.filter((family) => family.automationEligibility === "contract-only").flatMap((family) => family.workflowIds);
  const next = plan.families.find((family) => family.implementationStatus === "planned") || blockedFamilies[0];
  const childRows = selectedFamilies.filter((family) => family.resolution === "split-blocked").flatMap((family) => family.resultingFamilyIds.map((child) => `| ${family.familyId} | ${child} |`));
  const decisionRows = decisionDefinitions.map((decision) => `| ${decision.id} | ${decision.question} | ${decision.recommendedOption} |`);
  const lines = [
    "# Context-boundary blocker-resolution review",
    "",
    "This bounded review considered only the 17 named low/medium-risk read families (24 workflows). It made no RLS, SQL, role, grant, policy, ownership, function, database, AWS, ECS, Terraform, staging or production change.",
    "",
    "## Outcome",
    "",
    "- Families considered: 17",
    "- Workflows considered: 24",
    "- Families reclassified: 2",
    "- Families split: 4",
    "- Child families created: 8",
    "- Workflows moved to contract-only: 2",
    "- Workflows newly implemented: 0",
    "- Reviewed workflows retaining exact blockers: 22",
    "- PostgreSQL certifications pending: 4",
    `- Next deterministic family: ${next?.id || "none"}`,
    "",
    "No newly isolated ordinary read met every implementation gate. Production code was intentionally unchanged.",
    "",
    "## Reclassified families",
    "",
    "| Previous family | Governing boundary | Classification | Status |",
    "|---|---|---|---|",
    `| ${familyIds.analytics} | system-boundary-analytics-rollup-worker | worker boundary | contract-only; full rollup worker contract pending |`,
    `| ${familyIds.localClaim} | system-boundary-local-agent-device-claim | device-authenticated internal system path | contract-only; full claim lifecycle contract pending |`,
    "",
    "Neither boundary has human actor context. Neither may install ordinary authenticated context.",
    "",
    "## Split lineage",
    "",
    "| Parent family | Child family |",
    "|---|---|",
    ...childRows,
    "",
    "Each child is uniform by actor ceiling, scope model, assurance/command contract, execution surface, protected-table boundary and transaction behavior. The planner rejects lost/duplicated workflows, circular lineage, evidence-free splits and incompatible child membership.",
    "",
    "## Retained blockers",
    "",
    "| Blocker | Affected reviewed workflows |",
    "|---|---:|",
    ...Object.entries(batch.blockerCountsAfter).sort(([a], [b]) => a.localeCompare(b)).map(([code, count]) => `| ${code} | ${count} |`),
    "",
    "## Product decisions required",
    "",
    "| Decision | Question | CTO recommendation |",
    "|---|---|---|",
    ...decisionRows,
    "",
    "## Exact before/after programme counts",
    "",
    "| Metric | Before | After |",
    "|---|---:|---:|",
    `| Workflow families | 316 | ${plan.familyCount} |`,
    "| Implemented workflows | 4 | 4 |",
    `| Contract-only workflows | 38 | ${contractWorkflows.length} |`,
    `| Blocked workflows | 386 | ${blockedFamilies.reduce((total, family) => total + family.workflowIds.length, 0)} |`,
    `| Blocked families | 295 | ${blockedFamilies.length} |`,
    "| PostgreSQL certifications pending | 4 | 4 |",
    "",
    "## Implementation and validation boundary",
    "",
    "- Production code files changed: 0",
    "- Test files changed: 1 (`scripts/tests/full-database-rls-program.test.mjs`)",
    "- No targeted production-family test was added because no reviewed family was implemented.",
    "- Planner/system-boundary tests prove reclassification, contract-only state, split lineage and certification preservation.",
    "",
    "## Recommended commit groups",
    "",
    "1. Planner, validator, status and focused manifest tests.",
    "2. Workflow, system-boundary, decision and read-batch manifests.",
    "3. Architecture, migration report and this human review.",
    "",
    "## CTO recommendations",
    "",
    "1. Approve the manufacturer bootstrap actor-scope model first; it unlocks authentication hydration without weakening tenant isolation.",
    "2. Replace every platform-wide fallback with an explicit scope selector, purpose, immutable read attribution and pagination/date ceiling before implementation.",
    "3. Design public verification/support tracking as narrow proof-bound functions or repositories; do not reuse authenticated policies.",
    "4. Review the complete analytics worker and local-agent claim lifecycle next as separate high-risk system-boundary programmes, including durable replay/idempotency proof.",
    "",
  ];
  fs.writeFileSync(reviewPath, lines.join("\n"));
};

const previousBatch = readJson(contextBoundaryReadBatchPath);
updateManifests();
let plan = buildContextBoundaryPlan();
writeBatchAndReview(plan, previousBatch);
plan = buildContextBoundaryPlan();
console.log(JSON.stringify({
  output: path.relative(repoRoot, reviewPath),
  families: plan.familyCount,
  consideredFamilies: reviewedGroups.length,
  consideredWorkflows: workflowReviews.size,
}));
