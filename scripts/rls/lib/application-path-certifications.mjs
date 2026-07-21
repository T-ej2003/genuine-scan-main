import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const registryRepoRoot = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));

export const RISK_ANALYTICS_WORKFLOW_ID = "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics";
export const DASHBOARD_SNAPSHOT_WORKFLOW_IDS = [
  "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot",
  "workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate",
];

export const applicationPathCertificationFamilies = [
  {
    id: "risk-analytics",
    workflowIds: [RISK_ANALYTICS_WORKFLOW_ID],
    registeredRoots: ["GET /api/analytics/risk-scores"],
    testFile: "backend/tests/riskAnalyticsApplicationPathPostgres18.test.js",
    runtimeRole: "identity-authenticated-app",
    positiveActors: ["licensee-admin", "platform-admin"],
    deniedCases: ["blank-context", "foreign-scope", "forged-role", "stale-membership"],
    enable: ["MSCQR_RISK_ANALYTICS_POSTGRES18_TEST", "true"],
    confirm: ["MSCQR_RISK_ANALYTICS_POSTGRES18_CONFIRM", "MSCQR_RUN_LOCAL_RISK_ANALYTICS_POSTGRES18_TEST"],
    connections: { DATABASE_URL: "app" },
  },
  {
    id: "dashboard-snapshot",
    workflowIds: DASHBOARD_SNAPSHOT_WORKFLOW_IDS,
    registeredRoots: ["GET /api/dashboard/stats", "GET /api/events/dashboard"],
    testFile: "backend/tests/dashboardSnapshotApplicationPathPostgres18.test.js",
    runtimeRole: "identity-authenticated-app",
    positiveActors: ["licensee-admin", "manufacturer", "platform-admin"],
    deniedCases: ["blank-context", "foreign-scope", "forged-role", "stale-membership", "wrong-assurance", "wrong-purpose"],
    enable: ["MSCQR_DASHBOARD_POSTGRES18_TEST", "true"],
    confirm: ["MSCQR_DASHBOARD_POSTGRES18_CONFIRM", "MSCQR_RUN_LOCAL_DASHBOARD_POSTGRES18_TEST"],
    connections: { DATABASE_URL: "app", MSCQR_DASHBOARD_BOOTSTRAP_URL: "bootstrap" },
  },
].map((family) => Object.freeze({
  ...family,
  workflowIds: Object.freeze([...family.workflowIds]),
  registeredRoots: Object.freeze([...family.registeredRoots]),
  positiveActors: Object.freeze([...family.positiveActors]),
  deniedCases: Object.freeze([...family.deniedCases]),
  connections: Object.freeze({ ...family.connections }),
}));

const familyByWorkflowId = new Map();
for (const family of applicationPathCertificationFamilies) {
  for (const workflowId of family.workflowIds) {
    assert(!familyByWorkflowId.has(workflowId), `${workflowId} has duplicate application-path certification families`);
    familyByWorkflowId.set(workflowId, family);
  }
}

export const applicationPathCertificationFamilyFor = (workflowId) => familyByWorkflowId.get(workflowId) || null;

export const applicationPathCertificationEvidenceFor = (workflowId) => {
  const family = applicationPathCertificationFamilyFor(workflowId);
  return family && {
    status: "application-path-certified",
    postgresqlMajor: 18,
    testFile: family.testFile,
    harnessFile: "scripts/rls/certify-clean-room-database.mjs",
    runtimeRole: family.runtimeRole,
    positiveActors: [...family.positiveActors],
    deniedCases: [...family.deniedCases],
    atomicAttributionVerified: true,
    exactColumnPrivilegesVerified: true,
  };
};

export const applyApplicationPathCertificationEvidence = (workflowManifest) => {
  const workflows = new Map(workflowManifest.workflows.map((workflow) => [workflow.id, workflow]));
  for (const family of applicationPathCertificationFamilies) {
    assert(fs.existsSync(path.join(registryRepoRoot, family.testFile)), `${family.id} application-path test is missing`);
    for (const workflowId of family.workflowIds) {
      const workflow = workflows.get(workflowId);
      assert(workflow, `${workflowId} application-path workflow is missing`);
      assert.equal(workflow.contextBoundaryStatus, "implemented", `${workflowId} is certified before its canonical boundary is implemented`);
      workflow.postgresqlCertificationStatus = "certified";
      workflow.implementationStatus = "complete";
      workflow.applicationPathCertificationEvidence = applicationPathCertificationEvidenceFor(workflowId);
    }
  }
};

export const buildRegisteredCallPathEvidence = ({ workflowsManifest, partition, repoRoot }) => {
  assert.equal(workflowsManifest.workflows.length, 428, "registered workflow inventory must contain 428 workflows");
  const registeredRoutes = new Set((workflowsManifest.generatedEvidence?.registrations?.routes || [])
    .map((route) => `${route.method} ${route.path}`));
  const assignments = new Map();
  for (const assignment of partition.assignments) {
    assert(!assignments.has(assignment.workflowId), `${assignment.workflowId} has duplicate session assignments`);
    assignments.set(assignment.workflowId, assignment);
  }
  const rows = workflowsManifest.workflows.map((workflow) => {
    const assignment = assignments.get(workflow.id);
    assert(assignment, `${workflow.id} has no session assignment`);
    assert(workflow.supportingEvidence?.length, `${workflow.id} has no production access evidence`);
    assert(workflow.supportingEvidence.every((item) => ["registered-entrypoint", "reachable-from-registered-entrypoint"].includes(item.registration)), `${workflow.id} is not registered or reachable from a registered production entrypoint`);
    const family = applicationPathCertificationFamilyFor(workflow.id);
    const certification = workflow.applicationPathCertificationEvidence || null;
    if (family) {
      for (const root of family.registeredRoots) assert(registeredRoutes.has(root.replace(" /api/", " /")), `${workflow.id} root is not present in the production route registry: ${root}`);
      assert.deepEqual(certification, applicationPathCertificationEvidenceFor(workflow.id), `${workflow.id} certification evidence drifted from its executable family`);
      assert(fs.existsSync(path.join(repoRoot, family.testFile)), `${workflow.id} certification test is missing`);
    } else {
      assert(!certification, `${workflow.id} has certification evidence without an executable registered family`);
    }
    const prohibited = workflow.operatorBoundaryId?.startsWith("operator-boundary-prohibited-");
    const disposition = family
      ? "application-path-certified"
      : prohibited
        ? "frozen-product-prohibited"
        : workflow.contextBoundaryStatus === "implemented"
          ? "postgresql-application-path-pending"
          : "implementation-pending";
    return {
      workflowId: workflow.id,
      sessionId: assignment.sessionId,
      waveId: assignment.waveId,
      entryPoint: workflow.entryPoint,
      executionSurface: workflow.executionSurface,
      canonicalSourceFiles: workflow.canonicalSourceFiles,
      registeredRoots: family?.registeredRoots || [workflow.entryPoint],
      productionAccessPath: workflow.supportingEvidence.map(({ accessId, source, registration, method }) => ({ accessId, source, registration, method })),
      implementationFamilyId: workflow.implementationFamilyId || null,
      canonicalContextInstalled: workflow.sameTransactionGuarantee === true,
      protectedQueryClient: workflow.protectedQueryClient || null,
      disposition,
      certification,
    };
  }).sort((left, right) => left.workflowId.localeCompare(right.workflowId));
  assert.equal(rows.length, assignments.size, "partition contains unknown workflow assignments");
  const count = (disposition) => rows.filter((row) => row.disposition === disposition).length;
  return {
    schemaVersion: 1,
    generatedFrom: [
      "documents/security/rls-program/workflows.json",
      "documents/security/rls-program/workflow-three-session-partition.json",
      "scripts/rls/lib/application-path-certifications.mjs",
    ],
    workflowCount: rows.length,
    summary: {
      applicationPathCertified: count("application-path-certified"),
      postgresqlApplicationPathPending: count("postgresql-application-path-pending"),
      frozenProductProhibited: count("frozen-product-prohibited"),
      implementationPending: count("implementation-pending"),
    },
    workflows: rows,
  };
};
