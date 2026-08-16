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
  IMAGE_EVIDENCE_MAX_AGE_MS,
  IMAGE_EVIDENCE_REVOCATION_MODEL,
  readImageEvidence,
  readImageRepositoryEvidence,
  runCli,
} from "../aws/production-green-stage-b-image-evidence.mjs";
import { buildStageBImagePublicationIdentity, publicationIdentitySha256 } from "../aws/stage-b-image-publication-identity.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";
import { STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS } from "../aws/stage-b-deployment-contract.mjs";

const imageReleaseSha = "7245a6036492f875654c414473737e33c1422f3c";
const toolingSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
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
const publicationIdentity = buildStageBImagePublicationIdentity({
  expectedToolingSha: toolingSha,
  expectedReleaseSha: imageReleaseSha,
  artifactBytes,
  observed: { workflowRunId, workflowDatabaseId: "401", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: "Production Green Stage B Images", event: "workflow_dispatch", workflowDefinitionSha: toolingSha, imageReleaseSha, headBranch: "main", conclusion: "success", artifactId: "501", artifactName: "production-green-stage-b-images", artifactExpired: false, artifactArchiveFilename: null },
  observedAt,
});
const repositoryEvidence = ["mscqr-backend", "mscqr-worker"].map((repository) => ({
  repositoryName: repository,
  repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`,
  registryId: "368992683803",
  repositoryUri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}`,
  imageTagMutability: "IMMUTABLE",
  encryptionConfiguration: { encryptionType: "AES256" },
  createdAt: "2026-04-17T15:17:09.210Z",
  observedAt,
}));
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

const importedBackendPlan = () => {
  const plan = imagePlan();
  const backend = plan.resource_changes.find(({ address }) => address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS);
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS];
  const taskDefinition = {
    arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:9`,
    id: family,
    family,
    revision: 9,
    skip_destroy: null,
    container_definitions: backend.change.after.container_definitions,
    cpu: "512",
    memory: "1024",
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    execution_role_arn: "arn:aws:iam::368992683803:role/execution",
    task_role_arn: "arn:aws:iam::368992683803:role/task",
    runtime_platform: {},
    volume: [],
  };
  backend.change = { actions: ["update"], replace_paths: [], before: taskDefinition, after: { ...taskDefinition, skip_destroy: true } };
  for (const change of plan.resource_changes) {
    if (change.address !== STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS) change.change.actions = ["create", "delete"];
  }
  return plan;
};

function reportFixture(overrides = {}) {
  const selectedArtifactBytes = overrides.artifactBytes ?? artifactBytes;
  const selectedArtifactSha256 = overrides.artifactSha256 ?? crypto.createHash("sha256").update(selectedArtifactBytes).digest("hex");
  const selectedPublicationIdentity = overrides.publicationIdentity ?? (selectedArtifactBytes === artifactBytes ? publicationIdentity : buildStageBImagePublicationIdentity({
    expectedToolingSha: toolingSha,
    expectedReleaseSha: imageReleaseSha,
    artifactBytes: selectedArtifactBytes,
    observed: publicationIdentity,
    observedAt,
  }));
  return generateImageEvidence({ artifactBytes: selectedArtifactBytes, toolingSha, imageReleaseSha, workflowRunId, artifactSha256: selectedArtifactSha256, publicationIdentity: selectedPublicationIdentity, verifierCallerArn, observedAt, describe, repositories: repositoryEvidence, ...overrides });
}

function signatureFixture(report, overrides = {}) {
  return signImageEvidence(report, { now: observedAt, sign: () => "AQ==", ...overrides });
}

function assertValid(report = reportFixture(), signatureArtifact = signatureFixture(report), overrides = {}) {
  return assertImageEvidence(report, {
    signatureArtifact,
    verifySignature: ({ report: evidence, signatureArtifact: signature, now }) => verifyImageEvidenceSignature({ report: evidence, signatureArtifact: signature, now, verify: () => true }),
    toolingSha,
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
  assert.equal(report.revocationModel, IMAGE_EVIDENCE_REVOCATION_MODEL);
  assert.deepEqual(report.repositories, repositoryEvidence);
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
  assert.throws(() => reportFixture({ artifactBytes: missing, artifactSha256: crypto.createHash("sha256").update(missing).digest("hex") }), /exactly the four reviewed services/);
  const duplicate = Buffer.from(`${records.slice(0, 3).map(JSON.stringify).concat(JSON.stringify(records[0])).join("\n")}\n`);
  assert.throws(() => reportFixture({ artifactBytes: duplicate, artifactSha256: crypto.createHash("sha256").update(duplicate).digest("hex") }), /exactly the four reviewed services/);
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
  assert.throws(() => assertValid(report, signature, { imageReleaseSha: "a".repeat(40) }), /protected release SHA|different image release|different release|requested image release/);
  assert.throws(() => assertValid(report, signature, { workflowRunId: "30760808821" }), /different release|different image release/);
  assert.throws(() => assertValid(report, signature, { now: new Date(Date.parse(observedAt) + IMAGE_EVIDENCE_MAX_AGE_MS + 1).toISOString() }), /stale/);
});

test("immutable image evidence survives realistic credential and artifact delays", () => {
  const report = reportFixture();
  const signature = signatureFixture(report);
  const delayedNow = new Date(Date.parse(observedAt) + 16 * 60 * 1000).toISOString();
  assert.doesNotThrow(() => assertValid(report, signature, { now: delayedNow }));
  assert.doesNotThrow(() => assertValid(report, signature, { now: new Date(Date.parse(observedAt) + 60 * 60 * 1000).toISOString() }));
  assert.throws(() => assertValid(report, signature, { now: new Date(Date.parse(observedAt) + IMAGE_EVIDENCE_MAX_AGE_MS + 1).toISOString() }), /stale/);
});

test("authoritative repository evidence and revocation capability are required", () => {
  const report = reportFixture();
  const signature = signatureFixture(report);
  assert.throws(() => verifyImageEvidenceSignature({ report: { ...report, repositories: undefined }, signatureArtifact: signature, verify: () => true }), /authoritative repository/);
  assert.throws(() => assertValid({ ...report, repositories: undefined }, signature, { verifySignature: () => true }), /authoritative repository/);
  assert.throws(() => signImageEvidence({ ...report, revocationModel: "superseded-false" }, { sign: () => "AQ==" }), /revocation model/);
  assert.throws(() => signImageEvidence({ ...report, repositories: [{ ...report.repositories[0], imageTagMutability: "MUTABLE" }, report.repositories[1]] }, { sign: () => "AQ==" }), /not authoritatively immutable/);
});

test("repository configuration is validated from AWS-shaped evidence before signing", () => {
  let calls = 0;
  const describeRepositories = (repository) => {
    calls += 1;
    return { repositories: [{ repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: "368992683803", repositoryUri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z" }] };
  };
  const evidence = ["mscqr-backend", "mscqr-worker"].map((repository) => readImageRepositoryEvidence(repository, { observedAt, describe: describeRepositories }));
  assert.equal(calls, 2);
  assert.deepEqual(evidence.map(({ repositoryName, imageTagMutability }) => ({ repositoryName, imageTagMutability })), [
    { repositoryName: "mscqr-backend", imageTagMutability: "IMMUTABLE" },
    { repositoryName: "mscqr-worker", imageTagMutability: "IMMUTABLE" },
  ]);
  assert.doesNotThrow(() => reportFixture({ repositories: evidence }));
});

test("repository reader accepts the AWS envelope once and returns the exact normalized contract", () => {
  const raw = { repositories: [{ repositoryName: "mscqr-backend", repositoryArn: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", registryId: "368992683803", repositoryUri: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend", imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z" }] };
  let calls = 0;
  const normalized = readImageRepositoryEvidence("mscqr-backend", { observedAt, describe: () => { calls += 1; return raw; } });
  assert.equal(calls, 1);
  assert.deepEqual(Object.keys(normalized).sort(), ["createdAt", "encryptionConfiguration", "imageTagMutability", "observedAt", "registryId", "repositoryArn", "repositoryName", "repositoryUri"]);
  assert.equal(normalized.repositoryName, "mscqr-backend");
});

test("repository reader rejects projected arrays, raw strings, wrong casing, and invalid counts", () => {
  const repository = { repositoryName: "mscqr-backend", repositoryArn: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend", registryId: "368992683803", repositoryUri: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend", imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z" };
  for (const response of [[], JSON.stringify({ repositories: [repository] }), { Repositories: [repository] }, { repositories: [] }, { repositories: [repository, repository] }]) {
    assert.throws(() => readImageRepositoryEvidence("mscqr-backend", { observedAt, describe: () => response }), /exactly one repository/);
  }
});

test("image reader accepts the AWS imageDetails envelope exactly once", () => {
  let calls = 0;
  const image = readImageEvidence("mscqr-backend", imageReleaseSha, {
    describe: () => { calls += 1; return { imageDetails: [{ imageDigest: records[0].image_digest, imagePushedAt: observedAt }] }; },
  });
  assert.equal(calls, 1);
  assert.deepEqual(image, { digest: records[0].image_digest, imagePushedAt: observedAt });
});

test("administrator CLI reads DescribeRepositories exactly once per unique repository", () => {
  const directory = fs.mkdtempSync("/tmp/stage-b-image-evidence-cli-");
  try {
    const artifactPath = `${directory}/artifact.jsonl`;
    const outputPath = `${directory}/report.json`;
    const signaturePath = `${directory}/signature.json`;
    const identityPath = `${directory}/stage-b-image-publication-identity.json`;
    fs.writeFileSync(artifactPath, artifactBytes);
    fs.writeFileSync(identityPath, `${JSON.stringify(publicationIdentity)}\n`, { mode: 0o600 });
    let calls = 0;
    const result = runCli(["--artifact", artifactPath, "--tooling-sha", toolingSha, "--image-release-sha", imageReleaseSha, "--workflow-run-id", workflowRunId, "--artifact-sha256", artifactSha256, "--publication-identity", identityPath, "--publication-identity-sha256", publicationIdentitySha256(publicationIdentity), "--output", outputPath, "--signature-output", signaturePath], {
      getCaller: () => verifierCallerArn,
      observedAt,
      describe: (repository, tag) => describe(repository, tag),
      describeRepository: (repository) => {
        calls += 1;
        return { repositories: [{ repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: "368992683803", repositoryUri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z" }] };
      },
      sign: () => "AQ==",
    });
    assert.equal(calls, 2);
    assert.equal(result.reportSha256, imageEvidenceSha256(JSON.parse(fs.readFileSync(outputPath, "utf8"))));
    assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).repositories.length, 2);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("mutable, exclusion-based, missing, mismatched, or unrelated repository evidence fails closed", () => {
  const cases = [
    ["mutable", { imageTagMutability: "MUTABLE" }, /not authoritatively immutable/],
    ["exclusion", { imageTagMutability: "IMMUTABLE_WITH_EXCLUSION", imageTagMutabilityExclusionFilters: [{ filter: "latest", filterType: "WILDCARD" }] }, /not authoritatively immutable/],
    ["missing", undefined, /exactly one authoritative repository/],
    ["wrong ARN", { repositoryArn: "arn:aws:ecr:us-east-1:000000000000:repository/mscqr-backend" }, /identity is wrong/],
    ["wrong account", { registryId: "000000000000" }, /identity is wrong/],
    ["wrong region", { repositoryArn: "arn:aws:ecr:us-east-1:368992683803:repository/mscqr-backend" }, /identity is wrong/],
    ["unverified repository", [...repositoryEvidence, { repositoryName: "other", repositoryArn: "arn:aws:ecr:eu-west-2:368992683803:repository/other", registryId: "368992683803", repositoryUri: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/other", imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z", observedAt }], /exactly one authoritative repository/],
  ];
  for (const [, change, expected] of cases) {
    const repositories = change === undefined ? [repositoryEvidence[1]] : Array.isArray(change) ? change : repositoryEvidence.map((entry) => entry.repositoryName === "mscqr-backend" ? { ...entry, ...change } : entry);
    assert.throws(() => reportFixture({ repositories }), expected);
  }
});

test("repository evidence is part of the signed report and tampering invalidates it", () => {
  const report = reportFixture();
  const signature = signatureFixture(report);
  const tampered = { ...report, repositories: report.repositories.map((entry) => ({ ...entry, imageTagMutability: "MUTABLE" })) };
  assert.throws(() => verifyImageEvidenceSignature({ report: tampered, signatureArtifact: signature, verify: () => true }), /not authoritatively immutable/);
  assert.throws(() => assertValid({ ...report, revocationModel: "unsupported" }, signature, { verifySignature: () => true }), /revocation model/);
  assert.throws(() => assertValid({ ...report, superseded: false }, signature, { verifySignature: () => true }), /unsupported legacy provenance/);
  assert.throws(() => assertValid({ ...report, immutableTagProof: "ecr-immutable-tag" }, signature, { verifySignature: () => true }), /unsupported legacy provenance/);
});

test("the release wrapper has no ECR read or mutation path", () => {
  const wrapper = fs.readFileSync(new URL("../apply-production-green-stage-b.mjs", import.meta.url), "utf8");
  assert.equal(wrapper.includes("describe-images"), false);
  assert.equal(wrapper.includes("ecr:DescribeImages"), false);
  assert.equal(wrapper.includes("ecr:PutImage"), false);
  assert.equal(wrapper.includes("BatchDeleteImage"), false);
});

test("exact production-shaped plan variables and all twelve task definitions bind to signed evidence", () => {
  const bindings = assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: reportFixture(), planProfile: "BASELINE" });
  assert.deepEqual(bindings, {
    backend: { repository: "mscqr-backend", digest: `sha256:${"1".repeat(64)}`, imageReference: planReferences.backend },
    worker: { repository: "mscqr-worker", digest: `sha256:${"2".repeat(64)}`, imageReference: planReferences.worker },
    executor: { repository: "mscqr-backend", digest: `sha256:${"3".repeat(64)}`, imageReference: planReferences.executor },
    applicationCanary: { repository: "mscqr-backend", digest: `sha256:${"4".repeat(64)}`, imageReference: planReferences.canary },
    readOnlyCanary: { repository: "mscqr-backend", digest: `sha256:${"4".repeat(64)}`, imageReference: planReferences.canary },
  });
});

test("imported-backend image binding accepts the exact reviewed rollover topology", () => {
  const plan = importedBackendPlan();
  const terraformConfiguration = fs.readFileSync(new URL("../../infra/aws/terraform/production-green-stage-b/main.tf", import.meta.url), "utf8");
  assert.doesNotThrow(() => assertStageBPlanImageEvidenceBinding({ plan, imageEvidence: reportFixture(), planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION", terraformConfiguration }));
  plan.resource_changes.find(({ address }) => address !== STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS).change.actions = ["delete", "create"];
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan, imageEvidence: reportFixture(), planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION", terraformConfiguration }), /exact create-before-delete actions/);
});

test("every plan variable must equal its signed repository and digest", () => {
  for (const variable of ["backend_image", "worker_image", "executor_image", "canary_image", "read_only_canary_image"]) {
    const plan = imagePlan({ variables: { [variable]: { value: `${planReferences.backend}:wrong` } } });
    assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan, imageEvidence: reportFixture(), planProfile: "BASELINE" }), new RegExp(`Terraform image variable ${variable}`));
  }
  for (const value of [
    "mscqr-backend:latest",
    `000000000000.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}`,
    `368992683803.dkr.ecr.us-east-1.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}`,
  ]) {
    assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan({ variables: { backend_image: { value } } }), imageEvidence: reportFixture(), planProfile: "BASELINE" }), /Terraform image variable backend_image/);
  }
});

test("missing or duplicate signed image records fail closed", () => {
  const missing = reportFixture(); missing.images = missing.images.filter((image) => image.service !== "worker");
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: missing, planProfile: "BASELINE" }), /exactly four image records/);
  const duplicate = reportFixture(); duplicate.images.push({ ...duplicate.images[0] });
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: imagePlan(), imageEvidence: duplicate, planProfile: "BASELINE" }), /exactly four image records/);
});

test("planned current task-definition images must match, while retained history may remain old", () => {
  const changed = imagePlan();
  changed.resource_changes.find((change) => change.address.includes('executor["full-rls-verification"]')).change.after.container_definitions = JSON.stringify([{ image: planReferences.canary }]);
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: changed, imageEvidence: reportFixture(), planProfile: "BASELINE" }), /task-definition image does not match/);
  const retained = imagePlan();
  retained.resource_changes.push({ address: 'aws_ecs_task_definition.executor_retained["old-full-rls-verification"]', type: "aws_ecs_task_definition", change: { actions: ["no-op"], after: { family: "mscqr-production-full-rls-green-full-rls-verification", container_definitions: JSON.stringify([{ image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"9".repeat(64)}` }]) } } });
  assert.doesNotThrow(() => assertStageBPlanImageEvidenceBinding({ plan: retained, imageEvidence: reportFixture(), planProfile: "BASELINE" }));
});

test("recovery alias-only image binding requires zero current task definitions while retaining image evidence", () => {
  const recoveryPlan = imagePlan({ resource_changes: [] });
  assert.doesNotThrow(() => assertStageBPlanImageEvidenceBinding({ plan: recoveryPlan, imageEvidence: reportFixture(), planProfile: "RECOVERY_ALIAS_ONLY" }));
  const current = imagePlan({ resource_changes: [imagePlan().resource_changes[0]] });
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: current, imageEvidence: reportFixture(), planProfile: "RECOVERY_ALIAS_ONLY" }), /forbids current task-definition addresses/);
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: recoveryPlan, imageEvidence: reportFixture(), planProfile: "UNKNOWN_PROFILE" }), /unsupported/);
  assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan: recoveryPlan, imageEvidence: reportFixture() }), /unsupported/);
});

test("normal image binding rejects zero or incomplete current task-definition sets", () => {
  for (const plan of [
    imagePlan({ resource_changes: [] }),
    imagePlan({ resource_changes: imagePlan().resource_changes.slice(0, -1) }),
  ]) {
    assert.throws(() => assertStageBPlanImageEvidenceBinding({ plan, imageEvidence: reportFixture(), planProfile: "BASELINE" }), /exactly the twelve current task-definition addresses/);
  }
});
