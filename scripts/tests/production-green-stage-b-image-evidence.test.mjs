import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import {
  assertImageEvidence,
  generateImageEvidence,
  imageEvidenceSha256,
  signImageEvidence,
  verifyImageEvidenceSignature,
  assertStageBPlanImageEvidenceBinding,
} from "../aws/production-green-stage-b-image-evidence.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const imageReleaseSha = "7245a6036492f875654c414473737e33c1422f3c";
const workflowRunId = "30760789616";
const observedAt = "2026-08-02T18:30:00.000Z";
const verifierCallerArn = `arn:aws:iam::${STAGE_B.account}:root`;
const records = [
  ["backend", "mscqr-backend", imageReleaseSha],
  ["worker", "mscqr-worker", imageReleaseSha],
  ["rls-executor", "mscqr-backend", `${imageReleaseSha}-rls-executor`],
  ["rls-canary", "mscqr-backend", `${imageReleaseSha}-rls-canary`],
].map(([service, repository, tag], index) => {
  const digest = `sha256:${String(index + 1).repeat(64)}`;
  return {
    service,
    repository,
    image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`,
    image_tag: tag,
    image_digest: digest,
    image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@${digest}`,
  };
});
const artifactBytes = Buffer.from(`${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
const artifactSha256 = crypto.createHash("sha256").update(artifactBytes).digest("hex");
const describe = (repository, tag) => {
  const record = records.find((candidate) => candidate.repository === repository && candidate.image_tag === tag);
  return { digest: record.image_digest, imagePushedAt: observedAt };
};
const planReferences = {
  backend: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}`,
  worker: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"2".repeat(64)}`,
  executor: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"3".repeat(64)}`,
  canary: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"4".repeat(64)}`,
};
const planReferenceForAddress = (address) => address.startsWith("aws_ecs_task_definition.executor[") ? planReferences.executor : address.includes('["backend"]') ? planReferences.backend : address.includes('["worker"]') ? planReferences.worker : planReferences.canary;
const imagePlan = (overrides = {}) => {
  const variables = {
    backend_image: { value: planReferences.backend },
    worker_image: { value: planReferences.worker },
    executor_image: { value: planReferences.executor },
    canary_image: { value: planReferences.canary },
    read_only_canary_image: { value: planReferences.canary },
    ...overrides.variables,
  };
  const resource_changes = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
    address,
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family, container_definitions: JSON.stringify([{ image: planReferenceForAddress(address) }]) } },
  }));
  return { ...overrides, variables, resource_changes: overrides.resource_changes || resource_changes };
};

function reportFixture(overrides = {}) {
  return generateImageEvidence({ artifactBytes, imageReleaseSha, workflowRunId, artifactSha256, verifierCallerArn, observedAt, describe, ...overrides });
}

function signatureFixture(report, overrides = {}) {
  return signImageEvidence(report, { now: observedAt, sign: () => "AQ==", ...overrides });
}

function assertValid(report = reportFixture(), signatureArtifact = signatureFixture(report), overrides = {}) {
  return assertImageEvidence(report, {
    signatureArtifact,
    verifySignature: ({ report: evidence, signatureArtifact: signature, now }) => verifyImageEvidenceSignature({ report: evidence, signatureArtifact: signature, now, verify: () => true }),
    imageReleaseSha,
    workflowRunId,
    artifactSha256,
    now: observedAt,
    ...overrides,
  });
}

test("administrator evidence proves all four exact release tag-to-digest bindings", () => {
  const report = reportFixture();
  assert.equal(assertValid(report), true);
  assert.deepEqual(report.images.map(({ service, repository, tag, digest }) => ({ service, repository, tag, digest })), [
    { service: "backend", repository: "mscqr-backend", tag: imageReleaseSha, digest: `sha256:${"1".repeat(64)}` },
    { service: "rls-canary", repository: "mscqr-backend", tag: `${imageReleaseSha}-rls-canary`, digest: `sha256:${"4".repeat(64)}` },
    { service: "rls-executor", repository: "mscqr-backend", tag: `${imageReleaseSha}-rls-executor`, digest: `sha256:${"3".repeat(64)}` },
    { service: "worker", repository: "mscqr-worker", tag: imageReleaseSha, digest: `sha256:${"2".repeat(64)}` },
  ]);
});

test("release role is not an approved image-evidence verifier", () => {
  assert.throws(() => reportFixture({ verifierCallerArn: `arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/session` }), /approved administrator/);
});

test("missing, duplicate, mismatched, or modified evidence fails closed", () => {
  const missing = Buffer.from(`${records.slice(0, 3).map(JSON.stringify).join("\n")}\n`);
  assert.throws(() => reportFixture({ artifactBytes: missing, artifactSha256: crypto.createHash("sha256").update(missing).digest("hex") }), /exactly one record/);
  const duplicate = Buffer.from(`${records.slice(0, 3).map(JSON.stringify).concat(JSON.stringify(records[0])).join("\n")}\n`);
  assert.throws(() => reportFixture({ artifactBytes: duplicate, artifactSha256: crypto.createHash("sha256").update(duplicate).digest("hex") }), /exactly one record/);
  assert.throws(() => reportFixture({ artifactSha256: "0".repeat(64) }), /artifact SHA256/);
  assert.throws(() => reportFixture({ describe: () => ({ digest: `sha256:${"f".repeat(64)}`, imagePushedAt: observedAt }) }), /does not match canonical artifact/);
  const modified = reportFixture(); modified.images[0].digest = `sha256:${"f".repeat(64)}`;
  assert.throws(() => assertValid(modified, signatureFixture(reportFixture())), /different report/);
});

test("signed evidence is independently bound to key, report, freshness, and release", () => {
  const report = reportFixture();
  const signature = signatureFixture(report);
  assert.equal(assertValid(report, signature), true);
  assert.throws(() => assertValid(report, { ...signature, reportSha256: imageEvidenceSha256({ changed: true }) }), /different report/);
  assert.throws(() => assertValid(report, { ...signature, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other" }), /identity or algorithm/);
  assert.throws(() => assertValid(report, signature, { imageReleaseSha: "a".repeat(40) }), /different image release|different release/);
  assert.throws(() => assertValid(report, signature, { workflowRunId: "30760808821" }), /different release|different image release/);
  assert.throws(() => assertValid(report, signature, { now: "2026-08-02T19:00:01.000Z" }), /stale/);
});

test("the release wrapper has no ECR read or mutation path", () => {
  const wrapper = fs.readFileSync(new URL("../apply-production-green-stage-b.mjs", import.meta.url), "utf8");
  assert.equal(wrapper.includes("describe-images"), false);
  assert.equal(wrapper.includes("ecr:DescribeImages"), false);
  assert.equal(wrapper.includes("ecr:PutImage"), false);
  assert.equal(wrapper.includes("BatchDeleteImage"), false);
});

test("exact production-shaped plan variables and all twelve task definitions bind to signed evidence", () => {
  const bindings = assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: reportFixture() });
  assert.deepEqual(bindings, {
    backend: { repository: "mscqr-backend", digest: `sha256:${"1".repeat(64)}`, imageReference: planReferences.backend },
    worker: { repository: "mscqr-worker", digest: `sha256:${"2".repeat(64)}`, imageReference: planReferences.worker },
    executor: { repository: "mscqr-backend", digest: `sha256:${"3".repeat(64)}`, imageReference: planReferences.executor },
    applicationCanary: { repository: "mscqr-backend", digest: `sha256:${"4".repeat(64)}`, imageReference: planReferences.canary },
    readOnlyCanary: { repository: "mscqr-backend", digest: `sha256:${"4".repeat(64)}`, imageReference: planReferences.canary },
  });
});

test("every plan variable must equal its signed repository and digest", () => {
  for (const variable of ["backend_image", "worker_image", "executor_image", "canary_image", "read_only_canary_image"]) {
    const plan = imagePlan({ variables: { [variable]: { value: `${planReferences.backend}:wrong` } } });
    assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan, imageEvidence: reportFixture() }), new RegExp(`Terraform image variable ${variable}`));
  }
  for (const value of [
    "mscqr-backend:latest",
    `000000000000.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}`,
    `368992683803.dkr.ecr.us-east-1.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}`,
  ]) {
    assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan({ variables: { backend_image: { value } } }), imageEvidence: reportFixture() }), /Terraform image variable backend_image/);
  }
});

test("missing or duplicate signed image records fail closed", () => {
  const missing = reportFixture(); missing.images = missing.images.filter((image) => image.service !== "worker");
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: missing }), /exactly four image records/);
  const duplicate = reportFixture(); duplicate.images.push({ ...duplicate.images[0] });
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: duplicate }), /exactly four image records/);
});

test("planned current task-definition images must match, while retained history may remain old", () => {
  const changed = imagePlan();
  changed.resource_changes.find((change) => change.address.includes('executor["full-rls-verification"]')).change.after.container_definitions = JSON.stringify([{ image: planReferences.canary }]);
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: changed, imageEvidence: reportFixture() }), /task-definition image does not match/);
  const retained = imagePlan();
  retained.resource_changes.push({ address: 'aws_ecs_task_definition.executor_retained["old-full-rls-verification"]', type: "aws_ecs_task_definition", change: { actions: ["no-op"], after: { family: "mscqr-production-full-rls-green-full-rls-verification", container_definitions: JSON.stringify([{ image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"9".repeat(64)}` }]) } } });
  assert.doesNotThrow(() => assertStageBPlanImageEvidenceBinding({ plan: retained, imageEvidence: reportFixture() }));
});
