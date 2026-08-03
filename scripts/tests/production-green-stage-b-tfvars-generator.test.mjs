import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { signImageEvidence } from "../aws/production-green-stage-b-image-evidence.mjs";
import { assertStageBTfvarsBinding, deriveContractDigests, deriveRetainedDefinitions, generateStageBTfvars } from "../aws/generate-production-green-stage-b-tfvars.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY } from "../aws/stage-b-deployment-contract.mjs";

const releaseSha = "7245a6036492f875654c414473737e33c1422f3c";
const now = "2026-08-03T12:00:00.000Z";
const digest = (n) => `sha256:${String(n).repeat(64)}`;
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-tfvars-test-"));

function repositoryEvidence(repository) {
  return { repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: STAGE_B.account, repositoryUri: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z", observedAt: now };
}

const images = [
  ["backend", "mscqr-backend", releaseSha, digest(1)],
  ["worker", "mscqr-worker", releaseSha, digest(2)],
  ["rls-executor", "mscqr-backend", `${releaseSha}-rls-executor`, digest(3)],
  ["rls-canary", "mscqr-backend", `${releaseSha}-rls-canary`, `sha256:${"a".repeat(60)}f9a1`],
].map(([service, repository, tag, imageDigest]) => ({ service, repository, tag, digest: imageDigest, imagePushedAt: now }));
const evidence = { schemaVersion: 3, imageReleaseSha: releaseSha, workflowRunId: "30760789616", canonicalArtifactSha256: "a".repeat(64), verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`, account: STAGE_B.account, region: STAGE_B.region, observedAt: now, revocationModel: "time-bounded-no-supersession-registry", repositories: [repositoryEvidence("mscqr-backend"), repositoryEvidence("mscqr-worker")], images };
const signature = signImageEvidence(evidence, { now, sign: () => "AQ==" });

function taskAttributes(family, revision = 1) {
  return { arn: `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:${revision}`, family, revision, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: 1024, memory: 2048, container_definitions: JSON.stringify([{ name: "main", image: "example", essential: true }]), volume: [] };
}

function stateFixture(overrides = {}) {
  const candidates = ["backend", "worker", "canary"].map((kind) => ({ index_key: `60b782b-${kind}`, attributes: taskAttributes(kind === "canary" ? "mscqr-production-full-rls-green-application-canary" : `mscqr-production-rls-green-${kind}-candidate`) }));
  const modes = ["admin-bootstrap", "admin-ownership", "capability-preflight", "role-provision", "role-verify", "rollback", "runtime-policy", "verification"].map((mode) => ({ index_key: `60b782b-full-rls-${mode}`, attributes: taskAttributes(`mscqr-production-full-rls-green-full-rls-${mode}`) }));
  return { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76, resources: [
    { type: "aws_ecs_task_definition", name: "candidate_retained", instances: candidates },
    { type: "aws_ecs_task_definition", name: "executor_retained", instances: modes },
    { type: "aws_iam_policy", name: "broker", instances: [{ attributes: { arn: STAGE_B_BROKER_POLICY.arn } }] },
    { type: "aws_iam_role_policy_attachment", name: "broker", instances: [{ attributes: { policy_arn: STAGE_B_BROKER_POLICY.arn, role: STAGE_B_BROKER_POLICY.roleName } }] },
  ], ...overrides };
}

const stageA = { schemaVersion: 1, accountId: STAGE_B.account, region: STAGE_B.region, vpcId: "vpc-0123456789abcdef0", privateSubnetIds: [...STAGE_B.privateSubnetIds], ecsClusterArn: STAGE_B.clusterArn, stageADatabaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, stageAExecutorSecurityGroupId: STAGE_B.executorSecurityGroupId, stageAExecutorTaskRoleArn: STAGE_B.executorRoleArn, stageABrokerRoleArn: STAGE_B.brokerRoleArn, stageAExecutorLogGroupName: "/ecs/mscqr-production/full-rls-green", stageAExecutorLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", stageABrokerLogGroupName: "/aws/lambda/mscqr-production-rls-approval-broker", stageABrokerLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", stageARuntimeSecretArns: Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`])), stageAExecutorNetworkingReady: true, approvalSecretArn: STAGE_B.approvalSecretArn, approvalKmsKeyArn: STAGE_B.approvalKmsKeyArn, receiptBucketArn: `arn:aws:s3:::${STAGE_B.receiptBucket}`, stageAReadOnlyCanaryDatabaseSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123" };

function files() {
  const dir = fs.mkdtempSync(path.join(tempRoot, "run-"));
  const write = (name, value, mode = 0o600) => { const file = path.join(dir, name); fs.writeFileSync(file, typeof value === "string" || Buffer.isBuffer(value) ? value : `${JSON.stringify(value, null, 2)}\n`, { mode }); return file; };
  const state = write("state.json", stateFixture()); const stageAPath = write("stage-a.json", stageA); const evidencePath = write("evidence.json", evidence); const signaturePath = write("signature.json", signature); const packagePath = write("broker.zip", Buffer.from("broker package fixture"));
  return { dir, state, stageAPath, evidencePath, signaturePath, packagePath };
}

function input(overrides = {}) {
  const f = files();
  return { imageEvidence: f.evidencePath, imageEvidenceSignature: f.signaturePath, stateBackup: f.state, stageAInput: f.stageAPath, brokerPackagePath: f.packagePath, toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), imageReleaseSha: releaseSha, workflowRunId: evidence.workflowRunId, canonicalArtifactSha256: evidence.canonicalArtifactSha256, outputPath: path.join(f.dir, "out.tfvars"), bindingReportPath: path.join(f.dir, "binding.json"), now, verifySignature: () => true, ...overrides };
}

test.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

test("production-shaped inputs generate deterministic private tfvars and binding report", () => {
  const args = input();
  const first = generateStageBTfvars(args);
  assert.match(first.values.read_only_canary_image, /f9a1$/);
  assert.equal(first.bindingReport.images.readOnlyCanary.digestLength, 71);
  assert.equal(first.bindingReport.images.readOnlyCanary.matchesEvidence, true);
  assert.equal(fs.statSync(first.outputPath).mode & 0o777, 0o600);
  const terraformFormat = spawnSync("terraform", ["fmt", "-write=false", "-no-color", first.outputPath], { encoding: "utf8" });
  assert.equal(terraformFormat.status, 0, terraformFormat.stderr || terraformFormat.stdout);
  const reportSha = crypto.createHash("sha256").update(fs.readFileSync(first.bindingReportPath)).digest("hex");
  assertStageBTfvarsBinding({ tfvarsPath: first.outputPath, bindingReportPath: first.bindingReportPath, bindingReportSha256: reportSha, expectedToolingSha: args.toolingSha, expectedToolingTreeSha256: args.toolingTreeSha256, expectedImageReleaseSha: args.imageReleaseSha, expectedImageEvidenceSha256: first.bindingReport.imageEvidenceCanonicalSha256 });
  const second = generateStageBTfvars({ ...args, allowOverwrite: true });
  assert.equal(second.tfvarsSha256, first.tfvarsSha256);
  assert.deepEqual(second.bindingReport, first.bindingReport);
  assert.match(fs.readFileSync(first.outputPath, "utf8"), /read_only_canary_image/);
});

test("all five emitted image variables are byte-for-byte bound to signed evidence", () => {
  const result = generateStageBTfvars(input());
  for (const image of Object.values(result.bindingReport.images)) assert.equal(image.digest, evidence.images.find((record) => record.service === image.service).digest);
  assert.equal(result.bindingReport.images.readOnlyCanary.digest.endsWith("f9a1"), true);
});

for (const [name, mutate] of [
  ["wrong lineage", (value) => { value.lineage = "d".repeat(36); }],
  ["missing retained definition", (value) => { value.resources[0].instances.pop(); }],
  ["duplicate retained key", (value) => { value.resources[0].instances.push(value.resources[0].instances[0]); }],
  ["current task-definition address", (value) => { value.resources.push({ type: "aws_ecs_task_definition", name: "candidate", instances: [] }); }],
  ["mutable repository evidence", (value) => { value.repositories[1].imageTagMutability = "MUTABLE"; }],
  ["legacy provenance field", (value) => { value.immutableTagProof = "legacy"; }],
  ["truncated digest", (value) => { value.images[3].digest = value.images[3].digest.slice(0, -1); }],
]) test(`fails closed for ${name} before output`, () => {
  const f = files(); const source = name.includes("repository") || name.includes("provenance") || name.includes("digest") ? JSON.parse(fs.readFileSync(f.evidencePath, "utf8")) : JSON.parse(fs.readFileSync(f.state, "utf8")); mutate(source); const override = name.includes("repository") || name.includes("provenance") || name.includes("digest") ? { imageEvidence: (() => { const p = path.join(f.dir, "mutated-evidence.json"); fs.writeFileSync(p, `${JSON.stringify(source)}\n`); return p; })() } : { stateBackup: (() => { const p = path.join(f.dir, "mutated-state.json"); fs.writeFileSync(p, `${JSON.stringify(source)}\n`); return p; })() }; const args = input(override); assert.throws(() => generateStageBTfvars(args)); assert.equal(fs.existsSync(args.outputPath), false);
});

test("contract digest source is the source-controlled checksums manifest", () => {
  const result = deriveContractDigests(); assert.match(result.sourceContractSha256, /^[a-f0-9]{64}$/); assert.match(result.migrationSetDigest, /^[a-f0-9]{64}$/); assert.match(result.packageChecksumSha256, /^[a-f0-9]{64}$/); assert.equal(result.packageChecksumSha256, result.checksumsSha256);
});

test("retained-state validation requires broker policy and attachment", () => {
  const state = stateFixture({ resources: stateFixture().resources.filter((resource) => resource.name !== "broker") }); assert.throws(() => deriveRetainedDefinitions(state), /broker managed policy/);
});

test("binding report rejects a modified tfvars file and overwrite is opt-in", () => {
  const args = input(); const result = generateStageBTfvars(args); assert.throws(() => generateStageBTfvars(args), /Refusing to overwrite/);
  fs.appendFileSync(result.outputPath, "\n# modified\n"); const reportSha = crypto.createHash("sha256").update(fs.readFileSync(result.bindingReportPath)).digest("hex");
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath, bindingReportSha256: reportSha }), /modified/);
});
