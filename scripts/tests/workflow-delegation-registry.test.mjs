import assert from "node:assert/strict";
import test from "node:test";
import { missingWorkflowDiagnostic, repoRoot, scanProductionAccess, workflowIdFor } from "../rls/lib/program-inventory.mjs";
import { delegationKey, resolveWorkflowDelegation, validateWorkflowDelegations, WORKFLOW_DELEGATIONS } from "../rls/lib/workflow-delegation-registry.mjs";

test("incident repository access resolves to the canonical controller workflow", () => {
  const access = scanProductionAccess().accesses.find((item) => item.sourceFile.endsWith("c03IncidentRepository.ts") && item.function === "loadIncidentEvidenceFileInTransaction");
  const delegation = resolveWorkflowDelegation(access);
  assert.equal(workflowIdFor(delegation.canonical), "workflow-http-backend-src-controllers-incident-controller-ts-serve-incident-evidence-file");
  assert.equal(access.method, "$function:app_rls.c03_get_incident_evidence_file_by_storage_key");
});

test("registry rejects duplicate keys, invalid surfaces, missing functions, and sorts deterministically", () => {
  const entry = structuredClone(WORKFLOW_DELEGATIONS[0]);
  assert.throws(() => validateWorkflowDelegations({ entries: [entry, structuredClone(entry)], repoRoot }), /duplicate delegated source key/);
  entry.delegated.executionSurface = "database";
  assert.throws(() => validateWorkflowDelegations({ entries: [entry], repoRoot }), /invalid execution surface/);
  entry.delegated.executionSurface = "internal";
  entry.canonical.function = "missingFunction";
  assert.throws(() => validateWorkflowDelegations({ entries: [entry], repoRoot }), /function is missing/);
  const validated = validateWorkflowDelegations({ repoRoot });
  assert.deepEqual(validated.map((item) => delegationKey(item.delegated)), [...validated].map((item) => delegationKey(item.delegated)).sort((a, b) => a.localeCompare(b)));
});

test("existing delegations retain their canonical identities and missing-workflow diagnostics stay actionable", () => {
  const scan = scanProductionAccess();
  for (const [sourceFile, functionName, expected] of [
    ["auditCsvExportService.ts", "readAuditCsvExport", "workflow-http-backend-src-controllers-audit-controller-ts-export-logs-csv"],
    ["auditLogQueryService.ts", "queryAuditLogs", "workflow-http-backend-src-controllers-audit-controller-ts-get-logs"],
    ["fraudReportQueryService.ts", "queryFraudReports", "workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports"],
    ["analyticsService.ts", "loadRiskPolicy", "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"],
  ]) {
    const access = scan.accesses.find((item) => item.sourceFile.endsWith(sourceFile) && item.function === functionName);
    assert.equal(workflowIdFor(resolveWorkflowDelegation(access).canonical), expected);
  }
  const refresh = WORKFLOW_DELEGATIONS.find((entry) => entry.delegated.sourceFile.endsWith("refreshTokenService.ts") && entry.delegated.function === "revoke");
  assert.equal(workflowIdFor(refresh.canonical), "workflow-internal-backend-src-services-auth-refresh-token-service-ts-rotate-refresh-token");
  const output = missingWorkflowDiagnostic({ scope: "platform read scope", workflowId: "workflow-http-backend-src-controllers-incident-controller-ts-serve-incident-evidence-file", classification: { tableProjections: [{ tableId: "table-incident-evidence" }] }, workflowManifest: { workflows: [] }, scan });
  assert.match(output, /Canonical source: backend\/src\/controllers\/incidentController\.ts:serveIncidentEvidenceFile/);
  assert.match(output, /Related accesses: .*c03IncidentRepository/);
  assert.match(output, /do not edit generated workflow JSON/);
});
