#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createProductionComponentDeploymentStateClient } from "./production-component-deployment-state.mjs";
import { ECR_PROTECTION, verifyRepository } from "./verify-production-ecr-repository-protection.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { brokerDigest } from "./stage-b-staged-broker-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertHistoricalRuntimeRetention } from "./production-historical-runtime-contract.mjs";
import { authenticateHistoricalRuntimeEvidence } from "./production-historical-runtime-evidence.mjs";

const CLUSTER = "mscqr-prod-euw2-main";
const SERVICES = ["mscqr-backend-servi-euw2", "mscqr-frontend-servi-euw2"];
const WORKER = "mscqr-worker:4"; // Reviewed historical worker dependency; retirement is disabled.
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/(mscqr-backend|mscqr-web|mscqr-worker)@(sha256:[a-f0-9]{64})$/;
const METRIC = "MSCQR/ProductionEcrProtection";
const JOURNAL_PREFIX = `${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/green-backend-recovery/`;
const AWS_ACTIONS = new Set(["sts get-caller-identity", "dynamodb get-item", "ecs describe-services", "ecs list-tasks", "ecs describe-tasks", "ecs describe-task-definition", "ecr describe-images", "ecr batch-get-image", "ecr describe-repositories", "ecr get-lifecycle-policy", "ecr get-repository-policy", "s3api list-objects-v2", "s3api get-object", "cloudwatch put-metric-data"]);

export function addProtectedImage(inventory, { image, reason, owner, sourceSha = null, taskDefinition = null, operation = null }) {
  const match = IMAGE.exec(image || "");
  assert.ok(match, "Protected image is not an exact production digest");
  const [, repository, digest] = match;
  const key = `${repository}@${digest}`;
  const current = inventory.get(key) || { repository, digest, sourceShas: [], taskDefinitions: [], operations: [], reasons: [], owners: [] };
  if (sourceSha !== null) { assert.match(sourceSha, /^[a-f0-9]{40}$/); current.sourceShas.push(sourceSha); }
  if (taskDefinition !== null) current.taskDefinitions.push(taskDefinition);
  if (operation !== null) current.operations.push(operation);
  assert.match(reason, /^[A-Z_]+$/); assert.match(owner, /^[a-z-]+$/);
  current.reasons.push(reason); current.owners.push(owner);
  inventory.set(key, current);
}

export function finalizeProtectedInventory(inventory, checkedAt) {
  assert.ok(inventory instanceof Map && inventory.size > 0, "Empty protected-image inventory");
  return [...inventory.values()].map((item) => ({ ...item,
    sourceShas: [...new Set(item.sourceShas)].sort(), taskDefinitions: [...new Set(item.taskDefinitions)].sort(),
    operations: [...new Set(item.operations)].sort(), reasons: [...new Set(item.reasons)].sort(), owners: [...new Set(item.owners)].sort(),
    retentionEligibility: "DISABLED", inventoryObservedAt: checkedAt, lastVerificationTimestamp: null,
  })).sort((a, b) => `${a.repository}@${a.digest}`.localeCompare(`${b.repository}@${b.digest}`));
}

export function appendOpenRecoveryJournals(inventory, records) {
  const operations = new Map();
  for (const { key, body } of records) {
    assert.match(key, new RegExp(`^${JOURNAL_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:prepare|execute)/[a-f0-9]{64}\\.json$`));
    assert.equal(body?.kind, "PRODUCTION_RELEASE_COORDINATOR_OPERATION");
    assert.match(body.key?.operationId || "", /^[a-f0-9]{64}$/);
    assert.match(body.key?.phase || "", /^BACKEND:[A-Z:0-9a-f]+$/);
    assert.equal(key.split("/").at(-1), `${brokerDigest({ kind: body.kind, key: body.key })}.json`, "Journal identity mismatch");
    const record = operations.get(body.key.operationId) || { completed: false, digests: new Set(), sourceShas: new Set() };
    if (body.key.phase === "BACKEND:RECOVERY:COMPLETE") record.completed = true;
    if (body.value?.imageDigest !== undefined) { assert.match(body.value.imageDigest, /^sha256:[a-f0-9]{64}$/); record.digests.add(body.value.imageDigest); }
    if (body.value?.sourceSha !== undefined) { assert.match(body.value.sourceSha, /^[a-f0-9]{40}$/); record.sourceShas.add(body.value.sourceSha); }
    operations.set(body.key.operationId, record);
  }
  for (const [operation, record] of operations) {
    if (record.completed) continue;
    assert.ok(record.digests.size === 1, "Open recovery operation has missing or conflicting image identity");
    assert.ok(record.sourceShas.size <= 1, "Open recovery operation has conflicting source identity");
    addProtectedImage(inventory, { image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${[...record.digests][0]}`,
      reason: "OPEN_RECOVERY_JOURNAL", owner: "release-security", sourceSha: [...record.sourceShas][0] || null,
      operation });
  }
}

function readRecoveryJournals(run) {
  const objects = [], tokens = new Set();
  let continuation;
  do {
    const listing = json(run, ["s3api", "list-objects-v2", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName,
      "--prefix", JOURNAL_PREFIX, "--expected-bucket-owner", ECR_PROTECTION.account, "--no-paginate",
      ...(continuation ? ["--continuation-token", continuation] : [])]);
    assert.ok(Array.isArray(listing.Contents || []), "Recovery journal listing incomplete");
    assert.equal(typeof listing.IsTruncated, "boolean", "Recovery journal pagination status missing");
    objects.push(...(listing.Contents || []));
    assert.ok(objects.length <= 10000, "Recovery journal inventory exceeds reviewed bound");
    continuation = listing.IsTruncated ? listing.NextContinuationToken : undefined;
    if (listing.IsTruncated) { assert.ok(continuation && !tokens.has(continuation), "Recovery journal pagination is inconsistent"); tokens.add(continuation); }
  } while (continuation);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-ecr-monitor-"));
  try {
    return objects.map(({ Key, ETag, Size }, index) => {
      assert.ok(Number.isSafeInteger(Size) && Size > 0 && Size <= 131072, "Recovery journal object is outside the reviewed size bound");
      const file = path.join(directory, `${index}.json`);
      const readback = json(run, ["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", Key,
        "--expected-bucket-owner", ECR_PROTECTION.account, file]);
      assert.equal(readback.ETag, ETag, "Recovery journal changed during inventory read");
      return { key: Key, body: JSON.parse(fs.readFileSync(file, "utf8")) };
    });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function inspectProtectedImages(inventory, describeImage) {
  const findings = [];
  for (const image of inventory) {
    try {
      const result = describeImage(image.repository, image.digest);
      if (!result) { const missing = new Error("ImageNotFoundException"); missing.name = "ImageNotFoundException"; throw missing; }
      assert.equal(result?.registryId, ECR_PROTECTION.account);
      assert.equal(result?.repositoryName, image.repository);
      assert.equal(result?.imageDigest, image.digest);
      for (const sourceSha of image.sourceShas) assert.ok(result.imageTags?.includes(sourceSha), "Image source tag is missing");
    } catch (error) {
      const missing = /ImageNotFoundException/.test(`${error?.name} ${error?.message}`);
      const provenance = /source tag is missing/.test(error?.message || "");
      findings.push({ severity: missing || provenance ?
        (image.reasons.some((reason) => reason.startsWith("ACTIVE_") || reason === "COMPONENT_STATE") ? "CRITICAL" : "HIGH") : "UNKNOWN",
      repository: image.repository, digest: image.digest, reasons: image.reasons,
      operation: image.operations, ...(error.childDigest ? { childDigest: error.childDigest } : {}),
      code: missing ? "DIGEST_MISSING" : provenance ? "SOURCE_PROVENANCE_MISMATCH" : "ECR_READ_FAILED" });
    }
  }
  return findings;
}

export function assertLifecyclePreviewSafe({ repository, preview, inventory }) {
  assert.ok(ECR_PROTECTION.repositories.includes(repository));
  assert.equal(preview?.status, "COMPLETE", "ECR lifecycle preview is unavailable or incomplete");
  assert.ok(Array.isArray(preview.previewResults), "ECR lifecycle preview results are missing");
  const protectedDigests = new Set(inventory.filter((image) => image.repository === repository).map((image) => image.digest));
  assert.ok(protectedDigests.size > 0, "Cannot evaluate lifecycle preview against an empty repository inventory");
  for (const result of preview.previewResults) {
    if (result.action) assert.ok(!protectedDigests.has(result.imageDigest), `Lifecycle preview selects protected ${repository} digest`);
  }
  return true;
}

export const classifyRepositoryProtectionError = (error) =>
  error?.name === "AwsReadFailure" || /Wrong AWS account/.test(error?.message || "") ? "UNKNOWN" : "WARNING";

export function createAwsRunner() {
  return (args) => {
    assert.ok(AWS_ACTIONS.has(`${args[0]} ${args[1]}`), "Monitoring cannot execute an unreviewed AWS action");
    const result = spawnSync("aws", [...args, "--region", ECR_PROTECTION.region, "--output", "json", "--no-cli-pager"], {
      encoding: "utf8", timeout: 45000, maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, AWS_MAX_ATTEMPTS: "2", AWS_CLI_AUTO_PROMPT: "off" },
    });
    if (result.error || result.status !== 0) {
      const error = new Error(`AWS ${args[0]} ${args[1]} failed (${result.error?.code || result.status})`);
      error.name = /ImageNotFoundException/.test(result.stderr || "") ? "ImageNotFoundException" :
        /LifecyclePolicyNotFoundException/.test(result.stderr || "") ? "LifecyclePolicyNotFoundException" : "AwsReadFailure";
      if (error.name === "LifecyclePolicyNotFoundException") error.message = "LifecyclePolicyNotFoundException";
      throw error;
    }
    return result.stdout || "{}";
  };
}

const json = (run, args) => JSON.parse(run(args));
export function verifyEcrManifestChildren(run, repository, detail) {
  if (!/image\.index|manifest\.list/.test(detail.imageManifestMediaType || "")) return;
  const response = json(run, ["ecr", "batch-get-image", "--repository-name", repository, "--image-ids", `imageDigest=${detail.imageDigest}`]);
  assert.equal(response.images?.length, 1, "Manifest list readback incomplete");
  const manifest = JSON.parse(response.images[0].imageManifest);
  assert.ok(Array.isArray(manifest.manifests) && manifest.manifests.length > 0, "Manifest list has no child images");
  for (const child of manifest.manifests) {
    assert.match(child.digest || "", /^sha256:[a-f0-9]{64}$/);
    const details = json(run, ["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${child.digest}`]).imageDetails;
    if (details?.length !== 1 || details[0].imageDigest !== child.digest) {
      const error = new Error("ImageNotFoundException"); error.name = "ImageNotFoundException"; error.childDigest = child.digest; throw error;
    }
  }
}
const imageFromTask = (task) => {
  const images = task.containerDefinitions?.map((container) => container.image).filter((value) => IMAGE.test(value)) || [];
  assert.equal(images.length, 1, "Expected exactly one production image in task definition");
  return images[0];
};

export function addRetainedHistoricalWorker(inventory, retention, run, verify) {
  assertHistoricalRuntimeRetention(retention);
  const { reference, authority } = retention;
  authenticateHistoricalRuntimeEvidence({ evidence: { schemaVersion: 1, reference, binding: authority.binding, signatureBase64: authority.signatureBase64 }, retained: true, verify });
  const runtime = reference.runtime;
  const definition = json(run, ["ecs", "describe-task-definition", "--task-definition", runtime.taskDefinitionArn]).taskDefinition;
  assert.equal(definition?.taskDefinitionArn, runtime.taskDefinitionArn);
  assert.equal(definition.family, "mscqr-production-rls-green-worker-candidate");
  const { registeredAt, registeredBy, status, ...contents } = definition;
  assert.equal(canonicalSha256(contents), runtime.taskDefinitionSha256, "Retained worker task definition changed");
  const worker = definition.containerDefinitions?.find(({ name }) => name === "worker");
  assert.ok(worker);
  const sources = worker.environment?.filter(({ name }) => ["RELEASE_GIT_SHA", "GIT_SHA"].includes(name)).map(({ value }) => value) || [];
  assert.ok(sources.length > 0 && sources.every((value) => value === runtime.sourceSha), "Retained worker source changed");
  const image = imageFromTask(definition);
  assert.equal(image, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@${runtime.imageDigest}`);
  addProtectedImage(inventory, { image, reason: "RETAINED_HISTORICAL_RUNTIME", owner: "component-state", sourceSha: runtime.sourceSha, taskDefinition: runtime.taskDefinitionArn, operation: retention.closure.githubRunId });
}

export function collectProtectedInventory(run, now = new Date().toISOString(), role = "mscqr-production-ecr-monitor") {
  assert.ok(["mscqr-production-ecr-monitor", "mscqr-production-ecr-infrastructure-plan", "mscqr-production-ecr-infrastructure-apply"].includes(role), "Unreviewed inventory principal");
  const caller = json(run, ["sts", "get-caller-identity"]);
  assert.equal(caller.Account, ECR_PROTECTION.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::368992683803:assumed-role/${role}/[^/]+$`), "Wrong inventory principal");
  const state = createProductionComponentDeploymentStateClient({ run }).read();
  assert.ok(state, "Missing production component state");
  const inventory = new Map();
  const definitions = new Map();
  const taskImage = (arn) => {
    assert.match(arn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/);
    if (!definitions.has(arn)) definitions.set(arn, imageFromTask(json(run, ["ecs", "describe-task-definition", "--task-definition", arn]).taskDefinition));
    return definitions.get(arn);
  };
  for (const serviceName of SERVICES) {
    const expectedRepository = serviceName === SERVICES[0] ? "mscqr-backend" : "mscqr-web";
    const service = json(run, ["ecs", "describe-services", "--cluster", CLUSTER, "--services", serviceName]).services?.[0];
    assert.equal(service?.serviceName, serviceName); assert.equal(service.clusterArn, `arn:aws:ecs:eu-west-2:368992683803:cluster/${CLUSTER}`);
    assert.ok(service.desiredCount > 0 && service.taskDefinition);
    const addTask = (arn, reason) => {
      const image = taskImage(arn);
      assert.ok(image.includes(`/${expectedRepository}@`), "Service task definition changed component repository");
      addProtectedImage(inventory, { image, reason, owner: "ecs", taskDefinition: arn });
    };
    for (const deployment of service.deployments || []) addTask(deployment.taskDefinition, "ACTIVE_DEPLOYMENT");
    addTask(service.taskDefinition, "ACTIVE_SERVICE");
    for (const status of ["RUNNING", "PENDING"]) {
      const arns = json(run, ["ecs", "list-tasks", "--cluster", CLUSTER, "--service-name", serviceName, "--desired-status", status]).taskArns;
      assert.ok(Array.isArray(arns), "Task inventory incomplete");
      for (let i = 0; i < arns.length; i += 100) {
        const tasks = json(run, ["ecs", "describe-tasks", "--cluster", CLUSTER, "--tasks", ...arns.slice(i, i + 100)]).tasks;
        assert.equal(tasks?.length, arns.slice(i, i + 100).length, "Task readback incomplete");
        for (const task of tasks) {
          assert.equal(task.clusterArn, service.clusterArn); assert.equal(task.group, `service:${serviceName}`);
          addTask(task.taskDefinitionArn, `ACTIVE_${status}_TASK`);
        }
      }
    }
  }
  assert.ok(state.components.backend && state.components.frontend, "Active component state is incomplete");
  for (const [component, value] of Object.entries(state.components)) {
    if (!value?.imageDigest) continue;
    assert.ok(["backend", "frontend"].includes(component));
    const image = taskImage(value.taskDefinitionArn);
    assert.equal(image.split("@")[1], value.imageDigest, "Component state and task definition disagree");
    addProtectedImage(inventory, { image, reason: "COMPONENT_STATE", owner: "component-state", sourceSha: value.sourceSha, taskDefinition: value.taskDefinitionArn });
  }
  if (state.normalDeploymentReceipt) {
    const receipt = state.normalDeploymentReceipt;
    for (const [name, predecessor] of Object.entries(receipt.predecessors)) addProtectedImage(inventory, { image: taskImage(predecessor.taskDefinitionArn), reason: "NORMAL_ROLLBACK", owner: "normal-deploy", sourceSha: predecessor.sourceSha, taskDefinition: predecessor.taskDefinitionArn, operation: receipt.githubRunId });
    for (const [name, image] of Object.entries(receipt.images)) addProtectedImage(inventory, { image, reason: "PENDING_RELEASE", owner: "normal-deploy", sourceSha: receipt.sourceSha, operation: receipt.githubRunId });
  }
  appendOpenRecoveryJournals(inventory, readRecoveryJournals(run));
  if (state.historicalRuntimeRetention) addRetainedHistoricalWorker(inventory, state.historicalRuntimeRetention, run);
  const worker = json(run, ["ecs", "describe-task-definition", "--task-definition", WORKER]).taskDefinition;
  assert.equal(worker?.family, "mscqr-worker");
  addProtectedImage(inventory, { image: imageFromTask(worker), reason: "HISTORICAL_WORKER", owner: "release-security", taskDefinition: worker.taskDefinitionArn });
  return finalizeProtectedInventory(inventory, now);
}

export function checkProductionImages(run, now = new Date().toISOString()) {
  const inventory = collectProtectedInventory(run, now);
  const findings = inspectProtectedImages(inventory, (repository, digest) => {
    const detail = json(run, ["ecr", "describe-images", "--repository-name", repository, "--image-ids", `imageDigest=${digest}`]).imageDetails?.[0];
    if (detail) verifyEcrManifestChildren(run, repository, detail);
    return detail;
  });
  for (const image of inventory) if (!findings.some((finding) => finding.repository === image.repository && finding.digest === image.digest)) image.lastVerificationTimestamp = now;
  for (const repository of ECR_PROTECTION.repositories) {
    try {
      verifyRepository(repository, (args, options) => {
        try { return json(run, args); }
        catch (error) { if (options?.allowMissingLifecycle && /LifecyclePolicyNotFoundException/.test(error.message)) return null; throw error; }
      });
    } catch (error) {
      const severity = classifyRepositoryProtectionError(error);
      findings.push({ severity, repository, code: severity === "UNKNOWN" ? "REPOSITORY_CONTROL_READ_FAILED" : "REPOSITORY_PROTECTION_DRIFT" });
    }
  }
  return { checkedAt: now, account: ECR_PROTECTION.account, region: ECR_PROTECTION.region, inventory, findings };
}

export function publishMonitorMetrics(run, report) {
  const count = (severity) => report.findings.filter((finding) => finding.severity === severity).length;
  const unknown = report.unknown || count("UNKNOWN") > 0;
  const severities = unknown ? ["CRITICAL", "HIGH", "WARNING"].filter((severity) => count(severity) > 0).concat("UNKNOWN") : ["CRITICAL", "HIGH", "WARNING", "UNKNOWN"];
  const metrics = severities.map((severity) => ({ MetricName: `${severity}Findings`, Value: count(severity), Unit: "Count" }));
  metrics.push({ MetricName: "CheckCompleted", Value: unknown ? 0 : 1, Unit: "Count" });
  run(["cloudwatch", "put-metric-data", "--namespace", METRIC, "--metric-data", JSON.stringify(metrics)]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const run = createAwsRunner();
  let report;
  try { report = checkProductionImages(run); }
  catch (error) { report = { unknown: true, findings: [{ severity: "UNKNOWN", code: "INVENTORY_OR_AWS_READ_FAILED" }] }; }
  process.stdout.write(`${JSON.stringify(report)}\n`);
  publishMonitorMetrics(run, report);
  if (report.findings.length) process.exitCode = 1;
}
