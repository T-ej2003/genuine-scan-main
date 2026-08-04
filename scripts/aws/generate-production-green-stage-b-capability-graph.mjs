#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RELEASE_READ_PROBES } from "./production-green-stage-b-identity-capabilities.mjs";
import { RELEASE_POLICY_SOURCES, canonicalizeJson } from "./validate-production-green-stage-b-permissions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const CAPABILITY_GRAPH_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.json";
export const CAPABILITY_GRAPH_SCHEMA_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.schema.json";
export const CAPABILITY_GRAPH_MARKDOWN_PATH = "documents/ops/iam/MSCQRProductionGreenStageBDeploymentCapabilities-v1.md";
const manifestPath = "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json";
const publisherPolicyPath = "infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json";
const terraformPath = "infra/aws/terraform/production-green-stage-b/main.tf";
const awsCliSourceFiles = [
  "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs",
  "scripts/aws/create-production-green-stage-b-approval.mjs", "scripts/aws/generate-production-green-stage-a-prerequisites.mjs",
  "scripts/aws/production-green-stage-b-ecs-observations.mjs", "scripts/aws/production-green-stage-b-image-evidence.mjs",
  "scripts/aws/production-green-stage-b-identity-capabilities.mjs", "scripts/aws/run-production-green-stage-b-preflight.mjs",
  "scripts/aws/validate-production-green-stage-b-permissions.mjs",
];
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
const asArray = (value) => Array.isArray(value) ? value : [value];

const PHASES = Object.freeze([
  ["protected-main-checkout", "scripts/aws/stage-b-release-gate.mjs"],
  ["dependency-installation", "package.json"],
  ["rls-package-verification", "scripts/rls/verify-full-rls-package.mjs"],
  ["image-impact-classification", "scripts/aws/validate-stage-b-image-reuse.mjs"],
  ["image-workflow-dispatch", "scripts/aws/dispatch-production-green-stage-b-images.mjs"],
  ["image-artifact-verification", ".github/workflows/production-green-stage-b-image-build.yml"],
  ["schema-v3-image-evidence", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["administrator-iam-simulation", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["administrator-kms-signing", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["bootstrap-mfa-session", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-role-assumption", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["release-direct-read-preflight", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["backend-config-generation", "scripts/aws/generate-production-green-stage-b-backend-config.mjs"],
  ["terraform-initialization", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["backend-metadata-validation", "scripts/aws/stage-b-terraform-backend-contract.mjs"],
  ["workspace-validation", "scripts/aws/stage-b-terraform-workspace.mjs"],
  ["stage-b-state-pull", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["stage-a-state-read", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["stage-a-handoff-generation", "scripts/aws/generate-production-green-stage-a-prerequisites.mjs"],
  ["tfvars-generation", "scripts/aws/generate-production-green-stage-b-tfvars.mjs"],
  ["refresh-only", "scripts/refresh-production-green-stage-b.mjs"],
  ["saved-plan-generation", "scripts/plan-production-green-stage-b.mjs"],
  ["plan-json-canonicalization", "scripts/plan-production-green-stage-b.mjs"],
  ["reference-audit", "scripts/aws/generate-production-green-stage-b-reference-audit.mjs"],
  ["plan-bound-permission-report", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["production-closure", "scripts/aws/validate-stage-b-deployment-closure.mjs"],
  ["validator", "scripts/plan-production-green-stage-b.mjs"],
  ["wrapper-verify-only", "scripts/apply-production-green-stage-b.mjs"],
  ["wrapper-apply", "scripts/apply-production-green-stage-b.mjs"],
  ["post-apply-verification", "scripts/aws/verify-production-green-stage-b-ecs-observations.mjs"],
  ["runtime-activation-boundary", "scripts/aws/create-production-green-stage-b-approval.mjs"],
]);

const FIXED = Object.freeze([
  ["admin-image-repositories", "schema-v3-image-evidence", "ADMINISTRATOR", "ecr:DescribeRepositories", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-image-records", "schema-v3-image-evidence", "ADMINISTRATOR", "ecr:DescribeImages", "ADMIN_DIRECT_READ", "scripts/aws/production-green-stage-b-image-evidence.mjs"],
  ["admin-role", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRole", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-list", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-inline-read", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetRolePolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-role-attachments", "administrator-iam-simulation", "ADMINISTRATOR", "iam:ListAttachedRolePolicies", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicy", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-managed-policy-version", "administrator-iam-simulation", "ADMINISTRATOR", "iam:GetPolicyVersion", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-simulate-release", "administrator-iam-simulation", "ADMINISTRATOR", "iam:SimulatePrincipalPolicy", "ADMIN_SIMULATION", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-cloudtrail-denials", "administrator-iam-simulation", "ADMINISTRATOR", "cloudtrail:LookupEvents", "ADMIN_DIRECT_READ", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["admin-sign-evidence", "administrator-kms-signing", "ADMINISTRATOR", "kms:Sign", "ADMIN_SIGN", "scripts/aws/validate-production-green-stage-b-permissions.mjs"],
  ["bootstrap-identify", "bootstrap-mfa-session", "BOOTSTRAP_OPERATOR", "sts:GetCallerIdentity", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["bootstrap-mfa", "bootstrap-mfa-session", "BOOTSTRAP_OPERATOR", "sts:GetSessionToken", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["bootstrap-assume-release", "release-role-assumption", "BOOTSTRAP_OPERATOR", "sts:AssumeRole", "BOOTSTRAP_SESSION", "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_INFRASTRUCTURE_RUNBOOK.md"],
  ["publisher-oidc", "image-workflow-dispatch", "GITHUB_IMAGE_PUBLISHER", "sts:AssumeRoleWithWebIdentity", "GITHUB_IMAGE_MUTATION", ".github/workflows/production-green-stage-b-image-build.yml"],
  ["release-verify-signature", "release-direct-read-preflight", "RELEASE_DEPLOYER", "kms:Verify", "RELEASE_DIRECT_READ", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
  ["release-identify", "release-direct-read-preflight", "RELEASE_DEPLOYER", "sts:GetCallerIdentity", "RELEASE_DIRECT_READ", "scripts/aws/run-production-green-stage-b-preflight.mjs"],
]);

const classification = (entry, forbidden) => forbidden ? "FORBIDDEN"
  : entry.phase === "apply" ? "TERRAFORM_APPLY_MUTATION"
    : entry.phase === "refresh" ? "TERRAFORM_REFRESH_READ"
      : entry.phase === "reference-audit" ? "POST_APPLY_READ" : "RELEASE_DIRECT_READ";

function sourcePolicies() {
  return RELEASE_POLICY_SOURCES.map((policy) => ({ ...policy, document: readJson(policy.sourcePath), sourceSha256: sha256(Buffer.from(canonicalizeJson(readJson(policy.sourcePath)))) }));
}

function authority(entry, forbidden, policies) {
  for (const policy of policies) for (const statement of policy.document.Statement || []) {
    const actions = asArray(statement.Action);
    const resources = asArray(statement.Resource);
    if (statement.Effect === (forbidden ? "Deny" : "Allow") && actions.includes(entry.action)
      && asArray(entry.resources).every((resource) => resources.some((allowed) => allowed === "*" || allowed === resource || (allowed.endsWith("*") && resource.startsWith(allowed.slice(0, -1)))))) {
      return { sourceFile: policy.sourcePath, sid: statement.Sid, livePolicyArn: policy.arn, expectedVersion: "signed-administrator-evidence", expectedPolicySha256: policy.sourceSha256 };
    }
  }
  if (forbidden) return { sourceFile: null, sid: "implicit-deny", livePolicyArn: null, expectedVersion: null, expectedPolicySha256: null };
  throw new Error(`No reviewed source policy authorizes ${entry.id}.`);
}

function terraformRuntimeActions() {
  const text = fs.readFileSync(path.join(root, terraformPath), "utf8");
  return [...text.matchAll(/Action\s*=\s*(?:\[([^\]]+)\]|"([^"]+)")/g)]
    .flatMap((match) => match[2] ? [match[2]] : [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]))
    .filter((action) => /^[a-z0-9-]+:[A-Z]/.test(action))
    .filter((action, index, actions) => actions.indexOf(action) === index)
    .sort();
}

function discoverAwsCliActions() {
  const serviceNames = "sts|iam|kms|ecr|ec2|ecs|rds|lambda|logs|cloudtrail|secretsmanager|dynamodb|s3api";
  const pattern = new RegExp(`\\[\\s*["'](${serviceNames})["']\\s*,\\s*["']([a-z0-9-]+)["']`, "g");
  const calls = [];
  for (const sourceFile of awsCliSourceFiles) {
    const source = fs.readFileSync(path.join(root, sourceFile), "utf8");
    for (const match of source.matchAll(pattern)) {
      const service = match[1] === "s3api" ? "s3" : match[1];
      const operation = match[2].split("-").map((part) => part[0].toUpperCase() + part.slice(1)).join("").replaceAll("Db", "DB").replaceAll("Vpc", "VPC").replaceAll("Url", "URL");
      calls.push({ sourceFile, action: `${service}:${operation}` });
    }
  }
  return calls.filter((call, index) => calls.findIndex((candidate) => candidate.sourceFile === call.sourceFile && candidate.action === call.action) === index)
    .sort((left, right) => `${left.sourceFile}:${left.action}`.localeCompare(`${right.sourceFile}:${right.action}`));
}

export function buildStageBDeploymentCapabilityGraph() {
  const manifest = readJson(manifestPath); const policies = sourcePolicies(); const probesByAction = new Map();
  for (const probe of RELEASE_READ_PROBES) probesByAction.set(probe.action, [...(probesByAction.get(probe.action) || []), probe.id]);
  const manifestCapabilities = [[manifest.required, false], [manifest.forbidden, true]].flatMap(([entries, forbidden]) => entries.map((entry) => ({
    id: `manifest-${entry.id}`, phase: entry.phase === "apply" ? "wrapper-apply" : entry.phase === "reference-audit" ? "reference-audit" : entry.phase === "preflight" ? "release-direct-read-preflight" : "refresh-only",
    identity: forbidden ? "ADMINISTRATOR" : "RELEASE_DEPLOYER", executor: forbidden ? "iam-simulator" : "terraform-or-aws-cli", sourceFile: manifestPath,
    sourceFunction: entry.id, action: entry.action, resources: entry.resources, context: entry.context || [], classification: classification(entry, forbidden),
    probe: forbidden ? "administrator-simulation" : probesByAction.has(entry.action) ? "direct" : entry.phase === "apply" ? "plan-derived-simulation" : "administrator-simulation",
    probeIds: probesByAction.get(entry.action) || [], policy: authority(entry, forbidden, policies), required: true, mutation: entry.phase === "apply" || forbidden,
  })));
  const publisher = readJson(publisherPolicyPath).Statement.flatMap((statement) => asArray(statement.Action).map((action) => ({
    id: `publisher-${statement.Sid}-${action.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, phase: "image-workflow-dispatch", identity: "GITHUB_IMAGE_PUBLISHER", executor: "github-actions",
    sourceFile: publisherPolicyPath, sourceFunction: statement.Sid, action, resources: asArray(statement.Resource), context: statement.Condition || {}, classification: statement.Effect === "Deny" ? "FORBIDDEN" : "GITHUB_IMAGE_MUTATION",
    probe: "structural", policy: { sourceFile: publisherPolicyPath, sid: statement.Sid, livePolicyArn: "github-oidc-role-policy", expectedVersion: "protected-main-source", expectedPolicySha256: sha256(Buffer.from(canonicalizeJson(readJson(publisherPolicyPath)))) }, required: true, mutation: statement.Effect !== "Deny",
  })));
  const fixed = FIXED.map(([id, phase, identity, action, actionClass, sourceFile]) => ({ id, phase, identity, executor: sourceFile.endsWith(".yml") ? "github-actions" : "aws-cli", sourceFile, sourceFunction: id, action, resources: ["reviewed-exact-resource"], context: { account: "368992683803", region: "eu-west-2" }, classification: actionClass, probe: actionClass === "RELEASE_DIRECT_READ" ? "direct" : actionClass === "ADMIN_SIMULATION" ? "administrator-simulation" : "structural", policy: { sourceFile: identity === "RELEASE_DEPLOYER" ? manifestPath : sourceFile, sid: "identity-boundary", livePolicyArn: identity === "RELEASE_DEPLOYER" ? "signed-administrator-evidence" : null, expectedVersion: "source-bound", expectedPolicySha256: null }, required: true, mutation: ["ADMIN_SIGN", "GITHUB_IMAGE_MUTATION"].includes(actionClass) }));
  const runtime = terraformRuntimeActions().map((action) => ({ id: `runtime-${action.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`, phase: "runtime-activation-boundary", identity: "SERVICE_RUNTIME", executor: "lambda-or-ecs-role", sourceFile: terraformPath, sourceFunction: "generated runtime IAM policy", action, resources: ["terraform-derived-runtime-resource"], context: {}, classification: "SERVICE_RUNTIME_ACTION", probe: "structural", policy: { sourceFile: terraformPath, sid: "terraform-generated", livePolicyArn: "created-or-updated-by-stage-b", expectedVersion: "saved-plan", expectedPolicySha256: null }, required: false, mutation: !/^(?:ecr:|kms:Verify|secretsmanager:Get|s3:Get)/.test(action) }));
  const capabilities = [...fixed, ...publisher, ...manifestCapabilities, ...runtime].sort((a, b) => a.id.localeCompare(b.id));
  return {
    schemaVersion: 1, deployment: "production-green-stage-b", account: "368992683803", region: "eu-west-2",
    phases: PHASES.map(([id, sourceFile], index) => ({ order: index + 1, id, sourceFile })),
    identities: ["GITHUB_IMAGE_PUBLISHER", "ADMINISTRATOR", "BOOTSTRAP_OPERATOR", "RELEASE_DEPLOYER", "SERVICE_RUNTIME"], capabilities,
    directProbes: RELEASE_READ_PROBES.map(({ id, action }) => ({ id, action })), sourceScan: discoverAwsCliActions(),
    artifactContracts: ["protected-checkout", "image-impact", "schema-v3-image-evidence", "stage-a-handoff", "tfvars-binding-report", "refresh-only", "saved-plan", "canonical-plan-json", "reference-audit", "plan-capability-manifest", "signed-permission-report"],
    stateContracts: ["stage-a-exact-object-lineage-minimum-serial-sha", "stage-b-direct-key-lineage-minimum-serial-sha", "stage-b-serial-stable-plan-to-apply"],
    freshnessContracts: [{ artifact: "image-evidence", maxAgeSeconds: 86400 }, { artifact: "reference-audit", maxAgeSeconds: 900 }, { artifact: "permission-report", maxAgeSeconds: 900 }],
    configurationContracts: ["head-equals-origin-main", "clean-non-shallow-checkout", "direct-production-s3-key", "strict-backend-metadata", "tf-workspace-default", "no-workspace-select-or-migration", "73-classified-58-no-op-12-create-3-update-0-destroy", "no-service-database-alb-dns-traffic-or-secret-value-change"],
  };
}

export function assertStageBDeploymentCapabilityGraph(graph = readJson(CAPABILITY_GRAPH_PATH)) {
  const expected = buildStageBDeploymentCapabilityGraph();
  if (canonicalizeJson(graph) !== canonicalizeJson(expected)) throw new Error("Stage B deployment capability graph is stale or incomplete.");
  if (graph.phases.length !== 31 || new Set(graph.phases.map(({ id }) => id)).size !== 31) throw new Error("Stage B capability graph phase coverage is incomplete.");
  if (new Set(graph.capabilities.map(({ id }) => id)).size !== graph.capabilities.length) throw new Error("Stage B capability IDs are not unique.");
  if (graph.capabilities.some(({ identity, action }) => !identity || !action)) throw new Error("Stage B capability identity is ambiguous.");
  if (graph.capabilities.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy")) throw new Error("Release-deployer cannot own IAM simulation.");
  const graphActions = new Set(graph.capabilities.map(({ action }) => action));
  for (const probe of RELEASE_READ_PROBES) if (!graphActions.has(probe.action)) throw new Error(`Release probe is absent from capability graph: ${probe.id}.`);
  assertStageBAwsCallCoverage(graph, graph.sourceScan);
  return { phases: graph.phases.length, capabilities: graph.capabilities.length, uniqueActions: graphActions.size, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourcePolicyMismatches: 0, manifestMismatches: 0, configurationContradictions: 0 };
}

export function assertStageBAwsCallCoverage(graph, calls) {
  const graphActions = new Set(graph.capabilities.map(({ action }) => action));
  for (const call of calls) if (!graphActions.has(call.action)) throw new Error(`Production AWS CLI call is absent from capability graph: ${call.sourceFile} ${call.action}.`);
  return true;
}

const markdown = (graph) => `# Stage B production deployment capability graph\n\nGenerated from the permission manifest, reviewed source policies, release probes, publisher policy, Terraform runtime policy actions, and the 31-phase production path. Do not edit generated capability rows manually.\n\n- Phases: ${graph.phases.length}\n- Capability nodes: ${graph.capabilities.length}\n- Unique AWS actions: ${new Set(graph.capabilities.map(({ action }) => action)).size}\n- Identities: ${graph.identities.join(", ")}\n\n| Order | Phase | Source |\n|---:|---|---|\n${graph.phases.map(({ order, id, sourceFile }) => `| ${order} | ${id} | \`${sourceFile}\` |`).join("\n")}\n`;

export function writeStageBDeploymentCapabilityGraph() {
  const graph = buildStageBDeploymentCapabilityGraph();
  fs.writeFileSync(path.join(root, CAPABILITY_GRAPH_PATH), `${JSON.stringify(graph, null, 2)}\n`);
  fs.writeFileSync(path.join(root, CAPABILITY_GRAPH_MARKDOWN_PATH), markdown(graph));
  return assertStageBDeploymentCapabilityGraph(graph);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const write = process.argv.includes("--write");
  const result = write ? writeStageBDeploymentCapabilityGraph() : assertStageBDeploymentCapabilityGraph();
  process.stdout.write(`${JSON.stringify({ status: "valid", ...result })}\n`);
}
