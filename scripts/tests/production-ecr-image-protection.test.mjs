import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { addProtectedImage, addRetainedHistoricalWorker, appendOpenRecoveryJournals, readRecoveryJournals, finalizeProtectedInventory, inspectProtectedImages, createAwsRunner, verifyEcrManifestChildren, assertLifecyclePreviewSafe, classifyRepositoryProtectionError, publishMonitorMetrics } from "../aws/production-ecr-image-monitor.mjs";
import { assertEcrRepositoryProtection, ECR_PROTECTION, verifyRepository } from "../aws/verify-production-ecr-repository-protection.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "../aws/stage-b-terraform-backend-contract.mjs";
import { brokerDigest } from "../aws/stage-b-staged-broker-contract.mjs";
import { historicalRuntimeFixture } from "./fixtures/historical-runtime.mjs";
import { historicalRuntimeRetention } from "../aws/production-historical-runtime-evidence.mjs";
import { stateHash } from "../aws/production-component-deployment-state.mjs";

const sha = "a".repeat(40), digest = `sha256:${"b".repeat(64)}`;
const image = (repo = "mscqr-backend") => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repo}@${digest}`;
const guard = { Statement: [{ Effect: "Deny", Principal: "*", Action: ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy"] }] };
const protectedRepository = (repository = "mscqr-backend") => ({ repository, caller: { Account: ECR_PROTECTION.account }, lifecyclePolicy: null,
  description: { repositoryName: repository, registryId: ECR_PROTECTION.account, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, imageTagMutability: "IMMUTABLE", imageScanningConfiguration: { scanOnPush: true } }, repositoryPolicy: guard });

test("generic image publisher and verifier use the same accepted provenance URI", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/publish-ecs-images.yml", import.meta.url), "utf8");
  const verifier = fs.readFileSync(new URL("../aws/verify-release-artifacts.sh", import.meta.url), "utf8");
  const type = "https://mscqr.com/attestations/release-provenance/v1";
  assert.ok(workflow.includes(`PROVENANCE_ATTESTATION_TYPE: ${type}`));
  assert.match(workflow, /cosign attest --yes --type "\$PROVENANCE_ATTESTATION_TYPE"/);
  assert.ok(verifier.includes(`PROVENANCE_ATTESTATION_TYPE:-${type}`));
});

test("all three repositories require no lifecycle expiration and an explicit delete guard", () => {
  for (const repository of ECR_PROTECTION.repositories) assert.equal(assertEcrRepositoryProtection(protectedRepository(repository)), true);
  const good = protectedRepository();
  for (const change of [{ lifecyclePolicy: { rules: [] } }, { repositoryPolicy: { Statement: [] } },
    { caller: { Account: "000000000000" } }, { description: { ...good.description, imageTagMutability: "MUTABLE" } },
    { repositoryPolicy: { Statement: [{ ...guard.Statement[0], Action: ["ecr:BatchDeleteImage"] }] } },
    { repositoryPolicy: { Statement: [{ ...guard.Statement[0], Resource: "*" }] } },
    { repositoryPolicy: { Statement: [{ ...guard.Statement[0], Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/other" }] } }])
    assert.throws(() => assertEcrRepositoryProtection({ ...good, ...change }));
});

test("publisher preflight uses only exact read operations and rejects a lifecycle policy", () => {
  const calls = [], value = protectedRepository();
  const read = (args) => {
    calls.push(args.slice(0, 2).join(" "));
    if (args[0] === "sts") return value.caller;
    if (args[1] === "describe-repositories") return { repositories: [value.description] };
    if (args[1] === "get-lifecycle-policy") return null;
    if (args[1] === "get-repository-policy") return { policyText: JSON.stringify(value.repositoryPolicy) };
    throw new Error("unexpected AWS action");
  };
  assert.deepEqual(verifyRepository("mscqr-backend", read), { repository: "mscqr-backend", status: "PROTECTED" });
  assert.deepEqual(calls, ["sts get-caller-identity", "ecr describe-repositories", "ecr get-lifecycle-policy", "ecr get-repository-policy"]);
});

test("multiple active, rollback, pending and worker reasons deduplicate by exact digest", () => {
  const values = new Map();
  addProtectedImage(values, { image: image(), reason: "ACTIVE_SERVICE", owner: "ecs", sourceSha: sha });
  addProtectedImage(values, { image: image(), reason: "NORMAL_ROLLBACK", owner: "normal-deploy", sourceSha: sha });
  addProtectedImage(values, { image: image("mscqr-web"), reason: "PENDING_RELEASE", owner: "normal-deploy", operation: "123" });
  addProtectedImage(values, { image: image("mscqr-worker"), reason: "HISTORICAL_WORKER", owner: "release-security" });
  const inventory = finalizeProtectedInventory(values, "2026-10-26T00:00:00Z");
  assert.equal(inventory.length, 3);
  assert.deepEqual(inventory.find((entry) => entry.repository === "mscqr-backend").reasons, ["ACTIVE_SERVICE", "NORMAL_ROLLBACK"]);
  assert.ok(inventory.every((entry) => entry.retentionEligibility === "DISABLED"));
  assert.throws(() => finalizeProtectedInventory(new Map(), "now"), /Empty/);
  assert.throws(() => addProtectedImage(values, { image: image("other"), reason: "ACTIVE_SERVICE", owner: "ecs" }));
});

test("signed historical retention protects its exact worker candidate alongside the reviewed legacy worker", () => {
  const f = historicalRuntimeFixture();
  const retention = historicalRuntimeRetention({ evidence: f.evidence, sourceSha: f.release, current: f.state, componentStateSha256: stateHash(f.state), reader: f.reader, verify: f.verify, writerContext: f.writerContext, now: f.now });
  const values = new Map();
  const run = (args) => {
    assert.deepEqual(args.slice(0, 2), ["ecs", "describe-task-definition"]);
    assert.equal(args[3], f.definitionArn);
    return JSON.stringify({ taskDefinition: f.definition });
  };
  addRetainedHistoricalWorker(values, retention, run, f.verify);
  addProtectedImage(values, { image: image("mscqr-worker"), reason: "HISTORICAL_WORKER", owner: "release-security", taskDefinition: "mscqr-worker:4" });
  const inventory = finalizeProtectedInventory(values, f.now);
  assert.equal(inventory.length, 2);
  const retained = inventory.find(({ digest: value }) => value === f.imageDigest);
  assert.deepEqual(retained.reasons, ["RETAINED_HISTORICAL_RUNTIME"]);
  assert.deepEqual(retained.sourceShas, [f.source]);
  const findings = inspectProtectedImages(inventory, (_, imageDigest) => imageDigest === f.imageDigest ? undefined : { registryId: ECR_PROTECTION.account, repositoryName: "mscqr-worker", imageDigest, imageTags: [] });
  assert.equal(findings.find(({ digest: value }) => value === f.imageDigest).severity, "HIGH");
  assert.throws(() => addRetainedHistoricalWorker(new Map(), retention, () => JSON.stringify({ taskDefinition: { ...f.definition, family: "mscqr-worker" } }), f.verify));
  for (const replacement of [
    { ...f.definition, containerDefinitions: [{ ...f.definition.containerDefinitions[0], image: image("mscqr-worker") }] },
    { ...f.definition, containerDefinitions: [{ ...f.definition.containerDefinitions[0], environment: [{ name: "RELEASE_GIT_SHA", value: "9".repeat(40) }] }] },
  ]) assert.throws(() => addRetainedHistoricalWorker(new Map(), retention, () => JSON.stringify({ taskDefinition: replacement }), f.verify));
  assert.throws(() => addRetainedHistoricalWorker(new Map(), { ...retention, authority: { ...retention.authority, signatureBase64: Buffer.from("wrong").toString("base64") } }, run, f.verify));
});

test("missing active is critical, missing rollback or pending is high, unreadable ECR is unknown", () => {
  const values = new Map();
  addProtectedImage(values, { image: image(), reason: "ACTIVE_SERVICE", owner: "ecs" });
  addProtectedImage(values, { image: image("mscqr-web"), reason: "NORMAL_ROLLBACK", owner: "normal-deploy" });
  const inventory = finalizeProtectedInventory(values, "now");
  const missing = () => { const error = new Error("ImageNotFoundException"); error.name = "ImageNotFoundException"; throw error; };
  assert.deepEqual(inspectProtectedImages(inventory, missing).map((finding) => finding.severity).sort(), ["CRITICAL", "HIGH"]);
  assert.deepEqual(inspectProtectedImages(inventory, () => undefined).map((finding) => finding.severity).sort(), ["CRITICAL", "HIGH"]);
  assert.deepEqual(inspectProtectedImages(inventory, () => { throw new Error("timeout"); }).map((finding) => finding.severity), ["UNKNOWN", "UNKNOWN"]);
  assert.deepEqual(inspectProtectedImages(inventory, (repository, imageDigest) => ({ repositoryName: repository, imageDigest, registryId: ECR_PROTECTION.account, imageTags: [] })), []);
});

test("monitor AWS runner rejects ECS mutations before invoking AWS", () => {
  assert.throws(() => createAwsRunner()(["ecs", "update-service"]), /unreviewed AWS action/);
  assert.throws(() => createAwsRunner()(["ecr", "batch-delete-image"]), /unreviewed AWS action/);
});

test("manifest-list children must remain available even when the parent digest exists", () => {
  const child = `sha256:${"c".repeat(64)}`;
  const run = (args) => args[1] === "batch-get-image" ? JSON.stringify({ images: [{ imageManifest: JSON.stringify({ manifests: [{ digest: child }] }) }] }) : JSON.stringify({ imageDetails: [{ imageDigest: child }] });
  assert.doesNotThrow(() => verifyEcrManifestChildren(run, "mscqr-backend", { imageDigest: digest, imageManifestMediaType: "application/vnd.oci.image.index.v1+json" }));
  assert.throws(() => verifyEcrManifestChildren((args) => args[1] === "batch-get-image" ? run(args) : JSON.stringify({ imageDetails: [] }), "mscqr-backend", { imageDigest: digest, imageManifestMediaType: "application/vnd.docker.distribution.manifest.list.v2+json" }), /ImageNotFoundException/);
});

test("a complete lifecycle preview selecting a protected digest fails closed", () => {
  const values = new Map(); addProtectedImage(values, { image: image(), reason: "ACTIVE_SERVICE", owner: "ecs" });
  const inventory = finalizeProtectedInventory(values, "now");
  assert.throws(() => assertLifecyclePreviewSafe({ repository: "mscqr-backend", inventory, preview: { status: "COMPLETE", previewResults: [{ imageDigest: digest, action: { type: "EXPIRE" } }] } }), /selects protected/);
  assert.throws(() => assertLifecyclePreviewSafe({ repository: "mscqr-backend", inventory, preview: { status: "COMPLETE", previewResults: [{ imageDigest: digest, action: { type: "TRANSITION" } }] } }), /selects protected/);
  assert.throws(() => assertLifecyclePreviewSafe({ repository: "mscqr-backend", inventory, preview: { status: "IN_PROGRESS", previewResults: [] } }), /unavailable/);
  assert.equal(assertLifecyclePreviewSafe({ repository: "mscqr-backend", inventory, preview: { status: "COMPLETE", previewResults: [] } }), true);
});

test("unknown inventory never publishes zero-valued healthy severity metrics", () => {
  let request;
  publishMonitorMetrics((args) => { request = args; }, { unknown: true, findings: [{ severity: "UNKNOWN" }] });
  const metrics = JSON.parse(request[request.indexOf("--metric-data") + 1]);
  assert.deepEqual(metrics.map((metric) => metric.MetricName), ["UNKNOWNFindings", "CheckCompleted"]);
  assert.deepEqual(metrics.map((metric) => metric.Value), [1, 0]);
});

test("repository control read failures are unknown, while authenticated drift is warning", () => {
  assert.equal(classifyRepositoryProtectionError({ name: "AwsReadFailure" }), "UNKNOWN");
  assert.equal(classifyRepositoryProtectionError(new Error("Wrong AWS account")), "UNKNOWN");
  assert.equal(classifyRepositoryProtectionError(new Error("Lifecycle policy must be absent")), "WARNING");
});

test("open authenticated recovery journal protects its digest; completion releases only that journal reason", () => {
  const operationId = "c".repeat(64), kind = "PRODUCTION_RELEASE_COORDINATOR_OPERATION";
  const entry = (phase, value) => {
    const key = { operationId, phase };
    return { key: `${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/green-backend-recovery/execute/${brokerDigest({ kind, key })}.json`, body: { kind, key, value } };
  };
  const dispatch = entry("BACKEND:UPDATE:DISPATCH", { imageDigest: digest, sourceSha: sha });
  const values = new Map();
  appendOpenRecoveryJournals(values, [dispatch]);
  assert.deepEqual(finalizeProtectedInventory(values, "now")[0].reasons, ["OPEN_RECOVERY_JOURNAL"]);
  const complete = entry("BACKEND:RECOVERY:COMPLETE", { imageDigest: digest, sourceSha: sha });
  const finished = new Map();
  appendOpenRecoveryJournals(finished, [dispatch, complete]);
  assert.equal(finished.size, 0);
  assert.throws(() => appendOpenRecoveryJournals(new Map(), [{ ...dispatch, key: dispatch.key.replace(/a/g, "b") }]));
  assert.throws(() => appendOpenRecoveryJournals(new Map(), [{ ...dispatch, key: `${dispatch.key}/extra` }]));
});

test("recovery inventory accepts real-sized authorization evidence while bounding total journal data", () => {
  const kind = "PRODUCTION_RELEASE_COORDINATOR_OPERATION", key = { operationId: "c".repeat(64), phase: "BACKEND:UPDATE:DISPATCH" };
  const objectKey = `${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/green-backend-recovery/execute/${brokerDigest({ kind, key })}.json`;
  const body = JSON.stringify({ kind, key, value: { imageDigest: digest, sourceSha: sha, input: { databaseCompatibility: "x".repeat(225000) } } });
  const listing = { Contents: [{ Key: objectKey, ETag: '"reviewed"', Size: Buffer.byteLength(body) }], IsTruncated: false };
  const run = args => {
    if (args[1] === "list-objects-v2") return JSON.stringify(listing);
    assert.equal(args[1], "get-object");
    fs.writeFileSync(args.at(-1), body);
    return JSON.stringify({ ETag: '"reviewed"' });
  };
  const records = readRecoveryJournals(run);
  const protectedImages = new Map();
  appendOpenRecoveryJournals(protectedImages, records);
  assert.deepEqual(finalizeProtectedInventory(protectedImages, "now")[0].reasons, ["OPEN_RECOVERY_JOURNAL"]);
  listing.Contents[0].Size = 512 * 1024 + 1;
  assert.throws(() => readRecoveryJournals(run), /object is outside/);
  listing.Contents = Array.from({ length: 33 }, () => ({ Key: objectKey, ETag: '"reviewed"', Size: 512 * 1024 }));
  assert.throws(() => readRecoveryJournals(run), /total size bound/);
});

test("Terraform and publishers cannot restore count-based expiration", () => {
  const terraform = fs.readFileSync("infra/aws/terraform/production-ecr-protection/main.tf", "utf8");
  const publisher = fs.readFileSync("scripts/aws/apply-ecr-repository-controls.sh", "utf8");
  assert.doesNotMatch(terraform, /aws_ecr_lifecycle_policy|tagStatus\s*=\s*"any"/);
  assert.doesNotMatch(publisher, /aws ecr put-lifecycle-policy|aws ecr batch-delete-image/);
  for (const file of ["infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json", "infra/aws/terraform/production-green-stage-b-publisher-bootstrap/publisher-permissions-boundary.json"]) {
    const policy = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.ok(policy.Statement.every((statement) => !JSON.stringify(statement.Action).includes("PutLifecyclePolicy")));
  }
});

test("EventBridge targets use exact-rule SNS topic policy without an execution role", () => {
  const terraform = fs.readFileSync("infra/aws/terraform/production-ecr-protection/monitor.tf", "utf8");
  assert.match(terraform, /import \{\s*to = aws_sns_topic_policy\.ecr_alerts\s*id = "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts"\s*\}/);
  assert.match(terraform, /resource "aws_sns_topic_policy" "ecr_alerts"/);
  assert.doesNotMatch(terraform, /resource "aws_sns_topic"/);
  assert.match(terraform, /Sid\s*=\s*"__default_statement_ID"/);
  assert.match(terraform, /Principal\s*=\s*\{ Service = "events\.amazonaws\.com" \}/);
  assert.match(terraform, /"aws:SourceArn"\s*=\s*local\.ecr_event_rule_arns/);
  assert.match(terraform, /arn:aws:events:eu-west-2:368992683803:rule\/mscqr-production-ecr-protection-change/);
  assert.match(terraform, /arn:aws:events:eu-west-2:368992683803:rule\/mscqr-production-ecr-image-action/);
  assert.match(terraform, /"aws:SourceAccount"\s*=\s*"368992683803"/);
  assert.equal((terraform.match(/depends_on = \[aws_sns_topic_policy\.ecr_alerts\]/g) || []).length, 2);
  assert.doesNotMatch(terraform, /role_arn\s*=|ecr_alert_event_target/);
});

test("scheduled monitor has exact main OIDC trust, scoped reads and no ECS mutation grant", () => {
  const terraform = fs.readFileSync("infra/aws/terraform/production-ecr-protection/monitor.tf", "utf8");
  const workflow = fs.readFileSync(".github/workflows/production-ecr-image-monitor.yml", "utf8");
  const monitor = yaml.load(workflow);
  for (const claim of ["repo:T-ej2003/genuine-scan-main:environment:production-ecr-monitor", "refs/heads/main", "Production ECR Image Monitor", "1145608538", "183396573"])
    assert.ok(terraform.includes(claim));
  assert.match(terraform, /token\.actions\.githubusercontent\.com:workflow"/);
  assert.doesNotMatch(terraform, /job_workflow_ref|workflow_ref/);
  assert.match(terraform, /s3:ListBucket[\s\S]*green-backend-recovery/);
  assert.match(terraform, /ecr:GetRepositoryPolicy/);
  assert.match(terraform, /cloudwatch:PutMetricData/);
  assert.match(terraform, /events\.amazonaws\.com/);
  assert.match(terraform, /aws:SourceArn/);
  assert.match(terraform, /sns:Publish/);
  assert.doesNotMatch(terraform, /"ecs:UpdateService"|"ecs:RegisterTaskDefinition"|"ecs:RunTask"/);
  assert.equal(monitor.name, "Production ECR Image Monitor");
  assert.ok(monitor.on.schedule?.[0]?.cron);
  assert.ok(Object.hasOwn(monitor.on, "workflow_dispatch"));
  assert.equal(monitor.jobs.monitor.environment, "production-ecr-monitor");
  assert.equal(monitor.jobs.monitor.permissions, undefined);
  assert.match(workflow, /mscqr-production-ecr-monitor/);
  assert.doesNotMatch(workflow, /production-normal-deploy|production-stage-b-image-publish/);
});
