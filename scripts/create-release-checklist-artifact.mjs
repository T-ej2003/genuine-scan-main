import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const outputPath = path.resolve(process.cwd(), process.env.RELEASE_CHECKLIST_OUTPUT || "audit-artifacts/release-checklist.json");

const required = (name, fallback = "") => String(process.env[name] || fallback).trim();
const repository = required("GITHUB_REPOSITORY");
const commitSha = required("GITHUB_SHA");
const runId = required("GITHUB_RUN_ID");
const runAttempt = required("GITHUB_RUN_ATTEMPT");
const serverUrl = required("GITHUB_SERVER_URL", "https://github.com");
const trustCriticalResult = required("TRUST_CRITICAL_RESULT");
const stagingSmokeResult = required("STAGING_SMOKE_RESULT");
const governanceResult = required("GOVERNANCE_RESULT");
const dependencyAuditResult = required("DEPENDENCY_AUDIT_RESULT", trustCriticalResult);
const provenanceBackfillEvidenceRef = required("PROVENANCE_BACKFILL_EVIDENCE_REF");
const secretRotationEvidenceRef = required("SECRET_ROTATION_EVIDENCE_REF");
const incidentDrillEvidenceRef = required("INCIDENT_DRILL_EVIDENCE_REF");

const trustCriticalPassHash = createHash("sha256")
  .update(
    JSON.stringify({
      repository,
      commitSha,
      trustCriticalResult,
      dependencyAuditResult,
      runId,
      runAttempt,
    })
  )
  .digest("hex");

const payload = {
  generatedAt: new Date().toISOString(),
  repository,
  commitSha,
  workflowRun: {
    id: runId || null,
    attempt: runAttempt || null,
  },
  checks: {
    trustCritical: trustCriticalResult || "unknown",
    stagingSmoke: stagingSmokeResult || "unknown",
    governance: governanceResult || "unknown",
    dependencyAudit: dependencyAuditResult || "unknown",
  },
  trustCriticalPassHash,
  stagingSmokeRunId: runId || null,
  links: {
    workflowRunUrl: repository && runId ? `${serverUrl}/${repository}/actions/runs/${runId}` : null,
  },
  evidence: {
    provenanceBackfillRef: provenanceBackfillEvidenceRef || null,
    secretRotationRef: secretRotationEvidenceRef || null,
    incidentDrillRef: incidentDrillEvidenceRef || null,
  },
};

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

console.log(`Release checklist artifact written: ${outputPath}`);
