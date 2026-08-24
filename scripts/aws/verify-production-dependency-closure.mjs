#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { CAPABILITY_GRAPH_PATH, assertStageBDeploymentCapabilityGraph, discoverAwsCliActions } from "./generate-production-green-stage-b-capability-graph.mjs";
import { canonicalizeJson } from "./validate-production-green-stage-b-permissions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const PRODUCTION_DEPENDENCY_CLOSURE_PATH = "documents/ops/iam/MSCQRProductionDependencyClosure-v1.json";
const BASE_PROTECTED_SHA = "e35c0bd0447eff85ec78ab46b18ab2d2e018cbcb";
const BASE_CALL_COUNT = 109;
const BASE_CALL_SHA256 = "6573e88760ace0c3448d26c627fc9fcacfbc88022e53ffbf1369944374714ad6";
const SERVICE = "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2";
const REPOSITORY = "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend";
const TASKS = "*";

const CALLS = Object.freeze([
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServiceDeployments", "manifest-backend-health-recovery-describe-service-deployments", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServiceRevisions", "manifest-backend-health-recovery-describe-service-revisions", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeServices", "manifest-reference-audit-ecs-service-details", [SERVICE]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeTaskDefinition", "manifest-reference-audit-ecs-task-definitions", [TASKS]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:DescribeTasks", "manifest-reference-audit-ecs-task-details", [TASKS]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:ListServiceDeployments", "manifest-backend-health-recovery-list-service-deployments", [SERVICE]],
  ["scripts/aws/production-ecs-rollback-viability.mjs", "ecs:ListTasks", "manifest-reference-audit-ecs-tasks", [TASKS]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:DescribeServiceDeployments", "manifest-backend-health-recovery-describe-service-deployments", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:DescribeServiceRevisions", "manifest-backend-health-recovery-describe-service-revisions", [SERVICE, "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/*"]],
  ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "ecs:ListServiceDeployments", "manifest-backend-health-recovery-list-service-deployments", [SERVICE]],
  ["scripts/aws/production-normal-backend-activation.mjs", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
  ["scripts/aws/deploy-ecs-service.sh", "ecr:DescribeImages", "manifest-backend-health-recovery-describe-images", [REPOSITORY]],
].map(([sourceFile, action, capabilityId, resources]) => Object.freeze({ sourceFile, action, capabilityId, resources: Object.freeze(resources) })));

const MODE_CAPABILITIES = Object.freeze({
  NORMAL: ["manifest-backend-health-recovery-describe-images", "normal-activation-release-describe-candidate", "normal-activation-release-describe-service", "normal-activation-release-list-tasks", "normal-activation-release-describe-tasks", "normal-activation-release-update-service"],
  BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME: ["manifest-backend-health-recovery-describe-images", "manifest-backend-health-recovery-describe-repositories", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-backend-health-recovery-list-service-deployments", "manifest-backend-health-recovery-describe-service-deployments", "manifest-backend-health-recovery-describe-service-revisions", "manifest-artifact-signing-bootstrap-describe-secret", "manifest-artifact-signing-bootstrap-get-secret-value", "manifest-backend-health-recovery-register-legacy-task-definition", "manifest-backend-health-recovery-update-service"],
  ROTATION_OVERLAP: ["manifest-backend-health-recovery-describe-images", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-activate-exact-ecs-service", "manifest-rollback-exact-ecs-service"],
  ROTATION_CLEANUP: ["manifest-backend-health-recovery-describe-images", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-activate-exact-ecs-service", "manifest-rollback-exact-ecs-service"],
  ROLLBACK_RECONCILIATION: ["manifest-backend-health-recovery-list-service-deployments", "manifest-backend-health-recovery-describe-service-deployments", "manifest-backend-health-recovery-describe-service-revisions", "manifest-reference-audit-ecs-service-details", "manifest-reference-audit-ecs-task-definitions", "manifest-reference-audit-ecs-tasks", "manifest-reference-audit-ecs-task-details", "manifest-backend-health-recovery-describe-images"],
  POST_DEPLOY_VERIFY: ["operator-operator-describe-production-backend-service", "operator-operator-list-production-backend-tasks", "operator-operator-describe-production-backend-tasks", "operator-operator-describe-production-task-definition", "operator-operator-execute-production-backend"],
});

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const same = (left, right) => canonicalizeJson(left) === canonicalizeJson(right);
const requireTokens = (file, tokens) => {
  const source = read(file);
  for (const token of tokens) if (!source.includes(token)) throw new Error(`Production runtime dependency is missing from ${file}: ${token}.`);
};

export function assertNoUnknownRollbackDependency(source = read("scripts/aws/production-ecs-rollback-viability.mjs")) {
  const nonLocalImports = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]).filter((value) => !value.startsWith(".") && !value.startsWith("node:"));
  if (nonLocalImports.length) throw new Error("Rollback viability introduced an undeclared external Node dependency.");
  if (/process\.env/.test(source)) throw new Error("Rollback viability introduced an unclassified environment dependency.");
  return true;
}

export function assertRollbackSemanticBoundary(source = read("scripts/aws/production-ecs-rollback-viability.mjs")) {
  for (const token of [
    "const forwardArn = deployment?.targetServiceRevision?.arn",
    "const rollbackArn = deployment?.rollback?.serviceRevisionArn",
    "const sourceArns = (deployment?.sourceServiceRevisions || [])",
    "forwardTargetServiceRevisionArn", "rollbackServiceRevisionArn", "sourceServiceRevisions",
    "service?.deployments", "rollbackEcsServiceDeploymentId", "ECS_SERVICE_DEPLOYMENT_ID", "attempt.startedBy === rollbackEcsServiceDeploymentId", "Date.parse(attempt.createdAt) >= rollbackStartedAt", "failureReasonSha256",
  ]) if (!source.includes(token)) throw new Error(`Rollback service-revision semantic boundary is missing: ${token}.`);
  if (/rollbackArn\s*=\s*deployment\?\.targetServiceRevision|rollbackServiceRevisionArn:\s*deployment\?\.targetServiceRevision/.test(source)) {
    throw new Error("Rollback viability must never derive rollback authority from targetServiceRevision.");
  }
  if (/failures\.length\s*>=\s*2/.test(source)) throw new Error("Rollback viability must never count failures without current deployment identity.");
  if (/DEPLOYMENT_ARN\.exec\([^\n]+\)\?\.\[1\].*startedBy|startedBy.*DEPLOYMENT_ARN\.exec/.test(source)) throw new Error("Task.startedBy must never be derived from a service-deployment ARN suffix.");
  return true;
}

export function buildProductionDependencyClosure() {
  const graph = JSON.parse(read(CAPABILITY_GRAPH_PATH));
  assertStageBDeploymentCapabilityGraph(graph);
  const newAwsCalls = assertChangedAwsCallClosure(discoverAwsCliActions(), graph);

  const capabilityById = new Map(graph.capabilities.map((capability) => [capability.id, capability]));
  for (const [mode, ids] of Object.entries(MODE_CAPABILITIES)) for (const id of ids) {
    const capability = capabilityById.get(id);
    if (!capability || !capability.identity || !capability.action || !capability.resources?.length || !capability.policy?.sourceFile) throw new Error(`Production mode ${mode} lacks exact capability ${id}.`);
  }
  const workflow = read(".github/workflows/release-gate.yml");
  const workflowInputs = [...workflow.matchAll(/^      (backend_recovery_[a-z0-9_]+):$/gm)].map((match) => match[1]).sort();
  const expectedInputs = ["backend_recovery_approval_json", "backend_recovery_approval_sha256", "backend_recovery_current_task_definition_arn", "backend_recovery_image_authorization_json", "backend_recovery_image_authorization_sha256", "backend_recovery_image_digest"];
  if (!same(workflowInputs, expectedInputs)) throw new Error("Backend recovery workflow input contract is incomplete or has an unknown input.");
  if (!same([...ARTIFACT_SIGNING_BINDINGS].sort(), ["ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT"])) throw new Error("Artifact-signing runtime dependency set is incomplete.");
  requireTokens("scripts/aws/production-ecs-rollback-viability.mjs", ["targetServiceRevision?.arn", "rollback?.serviceRevisionArn", "sourceServiceRevisions", "describe-service-revisions", "serviceRevisions", "revision?.taskDefinition", "forwardTargetTaskDefinitionFingerprint", "taskDefinitionFingerprint", "ImageNotFoundException", "ECR_LOOKUP_FAILED"]);
  requireTokens("scripts/aws/production-backend-health-recovery-contract.mjs", ["rollbackProof", "rollbackDeploymentArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest", "forwardTargetTaskDefinitionFingerprint", "knownFailedRevisions", "Legacy backend revision census changed before recovery registration", "assertFreshRollbackEquivalence"]);
  requireTokens("scripts/aws/recover-production-backend-health.mjs", ["rollbackProofSha256", "knownFailedRevisions", "await record();", "resolveArtifactSigning", "readFreshRollbackViability"]);
  requireTokens("scripts/aws/dispatch-production-backend-health-recovery.mjs", ["ROLLBACK_APPROVAL_FIELDS", "backend_recovery_approval_json", "backend_recovery_approval_sha256"]);
  requireTokens("scripts/aws/deploy-ecs-service.sh", ["ROLLBACK_IMAGE_DIGEST", "ecr describe-images", "Rollback candidate image viability could not be authenticated"]);
  const deploy = read("scripts/aws/deploy-ecs-service.sh");
  if (deploy.indexOf("aws ecr describe-images") > deploy.indexOf("update_args=(aws ecs update-service")) throw new Error("Existing-task deployment can mutate before rollback image viability is authenticated.");
  if (!workflow.includes("node scripts/aws/run-production-cutover.mjs") || !workflow.includes("--mode rotation-overlap")) throw new Error("Rotation workflow no longer routes through the governed existing-task cutover.");
  requireTokens("scripts/aws/production-normal-backend-activation.mjs", ["assertRollbackImageAvailable", "rollbackImageVerified: true"]);
  assertNoUnknownRollbackDependency();
  assertRollbackSemanticBoundary();
  const recoveryTest = read("scripts/tests/production-ecs-rollback-viability.test.mjs");
  for (const token of ["AccessDeniedException", "request timeout", "future-revision-N-minus-1", "describe-service-revisions", "pre-mutation equivalence", "ecs-svc/3599551810517927503", "foo/3599551810517927503", "task-attempt identity changed"]) if (!recoveryTest.includes(token)) throw new Error(`Rollback boundary lacks negative coverage: ${token}.`);
  if (!/const rollbackEcsServiceDeploymentId = "ecs-svc\/[1-9][0-9]*"/.test(recoveryTest)
    || !/startedBy: rollbackEcsServiceDeploymentId/.test(recoveryTest) || /startedBy: "future-deployment/.test(recoveryTest)) {
    throw new Error("Authorization-bearing ECS task fixtures must use the real ecs-svc/<numeric-id> Task.startedBy contract.");
  }
  const futureTest = read("scripts/tests/production-backend-health-recovery-contract.test.mjs");
  for (const token of ["future failed revision N", 'targetArn.replace(":998", ":1000")', "readRollbackViability"]) if (!futureTest.includes(token)) throw new Error(`Future recovery revision closure lacks coverage: ${token}.`);

  return {
    schemaVersion: 1,
    baseProtectedSha: BASE_PROTECTED_SHA,
    status: "PASS",
    newAwsCalls,
    counters: { unmappedAwsActions: 0, iamActionMismatches: 0, iamResourceMismatches: 0, principalCapabilityMismatches: 0, missingRuntimeBindings: 0, missingWorkflowInputs: 0, missingEvidenceBindings: 0, unsupportedApiFixtures: 0 },
    runtimeDependencies: [
      { id: "ecs-service-deployment-shape", producer: "authenticated ECS API", consumer: "rollback viability collector", authority: "distinct targetServiceRevision, sourceServiceRevisions, and rollback.serviceRevisionArn resolved through DescribeServiceRevisions", failClosed: true },
      { id: "rollback-proof", producer: "bounded authenticated reconciliation", consumer: "approval authorization and recovery executor", authority: "live ECS and ECR with exact DescribeServices deployment id equal to Task.startedBy plus rollback-time-bound stopped-task evidence; the serviceDeploymentArn remains a separate identity", failClosed: true },
      { id: "artifact-signing-bindings", producer: "canonical Secrets Manager binding resolver", consumer: "recovery task-definition builder", authority: "exact four protected names and live secret references", failClosed: true },
      { id: "workflow-json-transport", producer: "canonical recovery dispatcher", consumer: "Release Gate recovery preparation", authority: "byte-identical JSON and SHA-256 transport", failClosed: true },
      { id: "rollback-image-viability", producer: "exact ECR digest readback", consumer: "normal, rotation, and recovery pre-mutation gates", authority: "canonical repository plus immutable digest", failClosed: true },
    ],
    modes: Object.fromEntries(Object.keys(MODE_CAPABILITIES).map((mode) => [mode, "PASS"])),
    pathClosure: { forward: "PASS", rollback: "PASS", reconciliation: "PASS" },
  };
}

export function assertChangedAwsCallClosure(scanned, graph) {
  const callKeys = new Set(CALLS.map(({ sourceFile, action }) => `${sourceFile}\t${action}`));
  const normalized = scanned.map(({ sourceFile, action }) => ({ sourceFile, action }));
  const additions = normalized.filter(({ sourceFile, action }) => callKeys.has(`${sourceFile}\t${action}`));
  if (additions.length !== CALLS.length || new Set(additions.map(({ sourceFile, action }) => `${sourceFile}\t${action}`)).size !== CALLS.length) throw new Error("Changed production AWS calls differ from the reviewed closure contract.");
  const baseline = normalized.filter(({ sourceFile, action }) => !callKeys.has(`${sourceFile}\t${action}`)).sort((a, b) => `${a.sourceFile}:${a.action}`.localeCompare(`${b.sourceFile}:${b.action}`));
  if (baseline.length !== BASE_CALL_COUNT || sha256(JSON.stringify(baseline)) !== BASE_CALL_SHA256) throw new Error("Unknown production AWS call requires capability classification.");

  const capabilityById = new Map(graph.capabilities.map((capability) => [capability.id, capability]));
  return CALLS.map((contract) => {
    const capability = capabilityById.get(contract.capabilityId);
    const resourcesCompatible = contract.resources.every((resource) => capability?.resources?.includes(resource)
      || (resource === SERVICE && capability?.resources?.includes("arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/*")));
    if (!capability || capability.action !== contract.action || capability.identity !== "RELEASE_DEPLOYER" || !resourcesCompatible
      || !capability.policy?.sourceFile || !["direct", "direct-live-read"].includes(capability.probe) || !capability.probeIds?.length) {
      throw new Error(`Production AWS call lacks exact IAM/capability/preflight closure: ${contract.sourceFile} ${contract.action}.`);
    }
    if (contract.sourceFile.endsWith("deploy-ecs-service.sh")) {
      const rotation = capabilityById.get("manifest-backend-health-recovery-describe-images");
      if (!rotation || rotation.identity !== "RELEASE_DEPLOYER" || rotation.action !== contract.action || !same(rotation.resources, contract.resources) || !rotation.policy?.sourceFile) throw new Error("Rotation rollback-image read lacks exact IAM/capability closure.");
    }
    const reachableMode = contract.sourceFile.endsWith("deploy-ecs-service.sh")
      ? ["NORMAL", "ROTATION_OVERLAP", "ROTATION_CLEANUP"]
      : contract.sourceFile.endsWith("production-normal-backend-activation.mjs") ? ["NORMAL"] : ["BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"];
    return { ...contract, reachableMode, executionPrincipal: "RELEASE_DEPLOYER", sourcePolicyPresent: true, generatedManifestPresent: true, capabilityGraphPresent: true, administratorPreflightPresent: true, runtimePreflightPresent: true, negativeTestPresent: true };
  });
}

export function assertProductionDependencyClosure(report = JSON.parse(read(PRODUCTION_DEPENDENCY_CLOSURE_PATH))) {
  const expected = buildProductionDependencyClosure();
  if (!same(report, expected)) throw new Error("Production dependency closure report is stale or incomplete.");
  return { status: "valid", newAwsCalls: report.newAwsCalls.length, runtimeDependencies: report.runtimeDependencies.length, unmappedAwsActions: 0, missingRuntimeBindings: 0 };
}

export function writeProductionDependencyClosure() {
  const report = buildProductionDependencyClosure();
  fs.writeFileSync(path.join(root, PRODUCTION_DEPENDENCY_CLOSURE_PATH), `${JSON.stringify(report, null, 2)}\n`);
  return assertProductionDependencyClosure(report);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.stdout.write(`${JSON.stringify(process.argv.includes("--write") ? writeProductionDependencyClosure() : assertProductionDependencyClosure())}\n`);
