import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { signImageEvidence } from "../aws/production-green-stage-b-image-evidence.mjs";
import { publicationIdentitySha256 } from "../aws/stage-b-image-publication-identity.mjs";
import { packageStageBBroker } from "../aws/package-production-green-stage-b-broker.mjs";
import { assertStageBCanonicalTfvarsFile, assertStageBTfvarsBinding, deriveContractDigests, deriveRetainedDefinitions, generateStageBTfvars, validateStageBStageAInput, writeAtomicPair } from "../aws/generate-production-green-stage-b-tfvars.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_STATE_OBJECT } from "../aws/generate-production-green-stage-a-prerequisites.mjs";

const releaseSha = "7245a6036492f875654c414473737e33c1422f3c";
const now = "2026-08-03T12:00:00.000Z";
const digest = (n) => `sha256:${String(n).repeat(64)}`;
const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-tfvars-test-"));
const brokerFixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-tfvars-broker-fixture-"));
const brokerFixture = await packageStageBBroker({ outputPath: path.join(brokerFixtureRoot, "broker.zip"), toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), repositoryRoot });

function repositoryEvidence(repository) {
  return { repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: STAGE_B.account, repositoryUri: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z", observedAt: now };
}

const images = [
  ["backend", "mscqr-backend", releaseSha, digest(1)],
  ["worker", "mscqr-worker", releaseSha, digest(2)],
  ["rls-executor", "mscqr-backend", `${releaseSha}-rls-executor`, digest(3)],
  ["rls-canary", "mscqr-backend", `${releaseSha}-rls-canary`, `sha256:${"a".repeat(60)}f9a1`],
].map(([service, repository, tag, imageDigest]) => ({ service, repository, tag, digest: imageDigest, imagePushedAt: now }));
const publicationIdentity = { schemaVersion: 1, workflowRunId: "30760789616", workflowDatabaseId: "401", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: "Production Green Stage B Images", event: "workflow_dispatch", headSha: releaseSha, headBranch: "main", conclusion: "success", artifactId: "501", artifactName: "production-green-stage-b-images", artifactExpired: false, artifactArchiveFilename: null, canonicalFilename: "stage-b-images.jsonl", canonicalArtifactSha256: "a".repeat(64), recordCount: 4, services: ["backend", "rls-canary", "rls-executor", "worker"], observedAt: now };
const evidence = { schemaVersion: 3, imageReleaseSha: releaseSha, workflowRunId: "30760789616", publicationIdentitySha256: publicationIdentitySha256(publicationIdentity), publicationIdentity, canonicalArtifactSha256: "a".repeat(64), verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`, account: STAGE_B.account, region: STAGE_B.region, observedAt: now, revocationModel: "time-bounded-no-supersession-registry", repositories: [repositoryEvidence("mscqr-backend"), repositoryEvidence("mscqr-worker")], images };
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

const stageA = { schemaVersion: 2, generator: "scripts/aws/generate-production-green-stage-a-prerequisites.mjs", toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: STAGE_A_EXPECTED_STATE_LINEAGE, stageAStateSerial: STAGE_A_MINIMUM_STATE_SERIAL, stageAStateSha256: "0".repeat(64), networkEvidence: { vpcId: "vpc-0123456789abcdef0", privateSubnets: [...STAGE_B.privateSubnetIds].map((subnetId, index) => ({ subnetId, availabilityZone: `eu-west-2${index ? "b" : "a"}`, cidrBlock: `10.0.${index}.0/24`, routeTableId: `rtb-${String(index + 1).repeat(8)}`, natGatewayId: `nat-${String(index + 1).repeat(8)}` })), securityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((groupId) => ({ groupId, vpcId: "vpc-0123456789abcdef0" })), ecsClusterArn: STAGE_B.clusterArn, databaseIdentifier: "mscqr-production-rls-green", rdsSubnetIds: [...STAGE_B.privateSubnetIds] }, accountId: STAGE_B.account, region: STAGE_B.region, vpcId: "vpc-0123456789abcdef0", privateSubnetIds: [...STAGE_B.privateSubnetIds], ecsClusterArn: STAGE_B.clusterArn, stageADatabaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, stageAExecutorSecurityGroupId: STAGE_B.executorSecurityGroupId, stageAExecutorTaskRoleArn: STAGE_B.executorRoleArn, stageABrokerRoleArn: STAGE_B.brokerRoleArn, stageAExecutorLogGroupName: "/ecs/mscqr-production/full-rls-green", stageAExecutorLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", stageABrokerLogGroupName: "/aws/lambda/mscqr-production-rls-approval-broker", stageABrokerLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", stageARuntimeSecretArns: Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`])), stageAExecutorNetworkingReady: true, approvalSecretArn: STAGE_B.approvalSecretArn, approvalKmsKeyArn: STAGE_B.approvalKmsKeyArn, receiptBucketArn: `arn:aws:s3:::${STAGE_B.receiptBucket}`, stageAReadOnlyCanaryDatabaseSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123" };

function files() {
  const dir = fs.mkdtempSync(path.join(tempRoot, "run-"));
  const write = (name, value, mode = 0o600) => { const file = path.join(dir, name); fs.writeFileSync(file, typeof value === "string" || Buffer.isBuffer(value) ? value : `${JSON.stringify(value, null, 2)}\n`, { mode }); return file; };
  const state = write("state.json", stateFixture()); const stageAState = write("stage-a-state.json", { lineage: STAGE_A_EXPECTED_STATE_LINEAGE, serial: STAGE_A_MINIMUM_STATE_SERIAL }); const stageAPath = write("stage-a.json", { ...stageA, stageAStateSha256: crypto.createHash("sha256").update(fs.readFileSync(stageAState)).digest("hex") }); const evidencePath = write("evidence.json", evidence); const signaturePath = write("signature.json", signature); const packagePath = write("broker.zip", fs.readFileSync(brokerFixture.package.path));
  fs.copyFileSync(brokerFixture.manifest.path, path.join(dir, "broker.zip.manifest.json")); fs.chmodSync(path.join(dir, "broker.zip.manifest.json"), 0o600);
  return { dir, state, stageAState, stageAPath, evidencePath, signaturePath, packagePath };
}

function input(overrides = {}) {
  const f = files();
  return { imageEvidence: f.evidencePath, imageEvidenceSignature: f.signaturePath, stateBackup: f.state, stageAInput: f.stageAPath, stageAStateBackup: f.stageAState, brokerPackagePath: f.packagePath, toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), imageReleaseSha: releaseSha, workflowRunId: evidence.workflowRunId, canonicalArtifactSha256: evidence.canonicalArtifactSha256, outputPath: path.join(f.dir, "out.tfvars"), bindingReportPath: path.join(f.dir, "binding.json"), now, verifySignature: () => true, ...overrides };
}

test.after(() => { fs.rmSync(tempRoot, { recursive: true, force: true }); fs.rmSync(brokerFixtureRoot, { recursive: true, force: true }); });

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
  assert.equal(first.bindingReport.tfvarsFormat, "hcl");
  assert.equal(first.bindingReport.tfvarsFileName, "out.tfvars");
  assert.equal(first.bindingReport.tfvarsExtension, ".tfvars");
});

test("canonical tfvars rejects JSON and ambiguous filenames before output", () => {
  for (const name of ["production.json", "production.tfvars.json", "production"]) {
    const args = input({ outputPath: path.join(tempRoot, name) });
    assert.throws(() => generateStageBTfvars(args), /Stage B canonical HCL tfvars output must use a \.tfvars filename/);
    assert.equal(fs.existsSync(args.outputPath), false);
  }
});

test("canonical tfvars binding rejects a JSON-looking file and metadata tampering", () => {
  const args = input();
  const result = generateStageBTfvars(args);
  const jsonPath = path.join(path.dirname(args.outputPath), "tampered.tfvars");
  fs.copyFileSync(result.outputPath, jsonPath);
  fs.chmodSync(jsonPath, 0o600);
  const report = JSON.parse(fs.readFileSync(result.bindingReportPath, "utf8"));
  assert.throws(() => assertStageBCanonicalTfvarsFile({ tfvarsPath: jsonPath, bindingReport: report }), /filename does not match/);
  const hclPath = path.join(path.dirname(args.outputPath), "hcl.tfvars");
  fs.writeFileSync(hclPath, JSON.stringify({ account_id: "368992683803" }) + "\n", { mode: 0o600 });
  assert.throws(() => assertStageBCanonicalTfvarsFile({ tfvarsPath: hclPath }), /must be HCL, not JSON/);
  report.tfvarsFormat = "json";
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: (() => { const p = path.join(path.dirname(args.outputPath), "bad-binding.json"); fs.writeFileSync(p, `${JSON.stringify(report)}\n`, { mode: 0o600 }); return p; })() }), /format must be hcl/);
});

test("all five emitted image variables are byte-for-byte bound to signed evidence", () => {
  const result = generateStageBTfvars(input());
  for (const image of Object.values(result.bindingReport.images)) assert.equal(image.digest, evidence.images.find((record) => record.service === image.service).digest);
  assert.equal(result.bindingReport.images.readOnlyCanary.digest.endsWith("f9a1"), true);
});

test("retained generations accept complete historical 11-family and post-canary 12-family shapes", () => {
  const state = stateFixture();
  const candidate = state.resources[0].instances;
  const executor = state.resources[1].instances;
  const originalCandidates = structuredClone(candidate);
  const originalExecutors = structuredClone(executor);
  for (const [generation, revision] of [["760df83", 2], ["7029425", 3]]) {
    candidate.push(...originalCandidates.map((instance) => ({ ...structuredClone(instance), index_key: instance.index_key.replace("60b782b", generation), attributes: { ...structuredClone(instance.attributes), revision, arn: instance.attributes.arn.replace(":1", `:${revision}`) } })));
    executor.push(...originalExecutors.map((instance) => ({ ...structuredClone(instance), index_key: instance.index_key.replace("60b782b", generation), attributes: { ...structuredClone(instance.attributes), revision, arn: instance.attributes.arn.replace(":1", `:${revision}`) } })));
  }
  candidate.push({ index_key: "7029425-read_only_canary", attributes: taskAttributes("mscqr-production-full-rls-green-read-only-canary", 4) });
  assert.equal(deriveRetainedDefinitions(state).counts.candidate, 10);
  assert.equal(deriveRetainedDefinitions(state).counts.executor, 24);
});

test("retained 12-family state generates valid tfvars", () => {
  const f = files();
  const state = stateFixture();
  state.resources[0].instances.push({ index_key: "60b782b-read_only_canary", attributes: taskAttributes("mscqr-production-full-rls-green-read-only-canary", 2) });
  fs.writeFileSync(f.state, `${JSON.stringify(state)}\n`);
  const result = generateStageBTfvars(input({ stateBackup: f.state }));
  assert.equal(result.bindingReport.retainedDefinitions.candidate, 4);
});

test("current broker ZIP bytes are revalidated at the binding gate", () => {
  const args = input();
  const result = generateStageBTfvars(args);
  fs.appendFileSync(args.brokerPackagePath, Buffer.from("changed"));
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath }), /broker package raw SHA256/);
  fs.rmSync(args.brokerPackagePath);
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath }), /broker package must be/);
});

test("incomplete broker manifests are rejected by the tfvars binding gate", () => {
  const args = input();
  const result = generateStageBTfvars(args);
  const manifestPath = result.bindingReport.brokerPackageManifestPath;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  delete manifest.deploymentContractSha256;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath }), /required field|manifest/);
});

test("current Stage-A handoff and source state bytes are revalidated at the binding gate", () => {
  const args = input(); const result = generateStageBTfvars(args);
  fs.appendFileSync(args.stageAInput, "\n");
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath }), /Stage-A prerequisite input was modified/);
  const fresh = input(); const regenerated = generateStageBTfvars(fresh);
  fs.appendFileSync(fresh.stageAStateBackup, "\n");
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: regenerated.outputPath, bindingReportPath: regenerated.bindingReportPath }), /Stage-A state backup was modified/);
});

test("Stage A and Stage B state identities cannot be substituted", () => {
  const args = input(); const stageAInput = JSON.parse(fs.readFileSync(args.stageAInput, "utf8")); const stageBBytes = fs.readFileSync(args.stateBackup);
  const swappedInputPath = path.join(path.dirname(args.stageAInput), "swapped-stage-a.json");
  fs.writeFileSync(swappedInputPath, JSON.stringify({ ...stageAInput, stageAStateSha256: crypto.createHash("sha256").update(stageBBytes).digest("hex") }), { mode: 0o600 });
  assert.throws(() => generateStageBTfvars({ ...args, stageAInput: swappedInputPath, stageAStateBackup: args.stateBackup }), /Stage A state lineage is wrong/);
  assert.throws(() => generateStageBTfvars({ ...input(), stateBackup: args.stageAStateBackup }), /Stage B state lineage is wrong/);
  assert.throws(() => validateStageBStageAInput({ ...stageAInput, stageAStateObject: "env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate" }), /provenance/);
  assert.throws(() => validateStageBStageAInput({ ...stageAInput, stageAStateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a" }), /provenance/);
  assert.throws(() => validateStageBStageAInput({ ...stageAInput, stageAStateSerial: 34 }), /provenance/);
  assert.equal(validateStageBStageAInput({ ...stageAInput, stageAStateSerial: 36 }).stageAStateSerial, 36);
  assert.equal(deriveRetainedDefinitions({ ...stateFixture(), serial: 77 }).serial, 77);
});

test("Stage-A prerequisite identity fields must exactly describe the bound backup", () => {
  const updateInput = (args, mutate) => {
    const value = JSON.parse(fs.readFileSync(args.stageAInput, "utf8")); mutate(value); fs.writeFileSync(args.stageAInput, `${JSON.stringify(value)}\n`);
  };
  const updateState = (args, mutate) => {
    const value = JSON.parse(fs.readFileSync(args.stageAStateBackup, "utf8")); mutate(value); fs.writeFileSync(args.stageAStateBackup, `${JSON.stringify(value)}\n`); return fs.readFileSync(args.stageAStateBackup);
  };

  const artifactAhead = input(); updateInput(artifactAhead, (value) => { value.stageAStateSerial = 36; });
  assert.throws(() => generateStageBTfvars(artifactAhead), /Stage-A prerequisite serial does not match/);

  const backupAhead = input(); const backupAheadBytes = updateState(backupAhead, (value) => { value.serial = 36; }); updateInput(backupAhead, (value) => { value.stageAStateSha256 = crypto.createHash("sha256").update(backupAheadBytes).digest("hex"); });
  assert.throws(() => generateStageBTfvars(backupAhead), /Stage-A prerequisite serial does not match/);

  const lineageMismatch = input(); updateState(lineageMismatch, (value) => { value.lineage = "4e438e59-8b8b-194d-030c-5ede0c26344a"; });
  assert.throws(() => generateStageBTfvars(lineageMismatch), /Stage A state lineage is wrong/);

  const shaMismatch = input(); updateInput(shaMismatch, (value) => { value.stageAStateSha256 = "f".repeat(64); });
  assert.throws(() => generateStageBTfvars(shaMismatch), /source state backup/);

  const objectMismatch = input(); updateInput(objectMismatch, (value) => { value.stageAStateObject = "env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate"; });
  assert.throws(() => generateStageBTfvars(objectMismatch), /provenance/);

  const future = input(); const futureBytes = updateState(future, (value) => { value.serial = 36; }); updateInput(future, (value) => { value.stageAStateSerial = 36; value.stageAStateSha256 = crypto.createHash("sha256").update(futureBytes).digest("hex"); });
  const futureResult = generateStageBTfvars(future);
  assert.equal(futureResult.bindingReport.stageAStateSerial, 36);
  assert.equal(futureResult.bindingReport.stageAStateLineage, STAGE_A_EXPECTED_STATE_LINEAGE);

  const tamperedReport = JSON.parse(fs.readFileSync(futureResult.bindingReportPath, "utf8")); tamperedReport.stageAStateSerial = 35; fs.writeFileSync(futureResult.bindingReportPath, `${JSON.stringify(tamperedReport)}\n`);
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: futureResult.outputPath, bindingReportPath: futureResult.bindingReportPath }), /binding report Stage-A serial/);
});

test("atomic output pair commits together and rolls back on a second rename failure", () => {
  const directory = fs.mkdtempSync(path.join(tempRoot, "pair-"));
  const tfvarsPath = path.join(directory, "out.tfvars");
  const reportPath = path.join(directory, "binding.json");
  let renames = 0;
  const fileSystem = {
    ...fs,
    renameSync: (...args) => {
      renames += 1;
      if (renames === 2) throw new Error("simulated second rename failure");
      return fs.renameSync(...args);
    },
  };
  assert.throws(() => writeAtomicPair({ tfvarsPath, bindingReportPath: reportPath, tfvarsBytes: Buffer.from("tfvars"), bindingReportBytes: Buffer.from("report"), fileSystem }), /second rename/);
  assert.equal(fs.existsSync(tfvarsPath), false);
  assert.equal(fs.existsSync(reportPath), false);
});

test("atomic output pair preflights both destinations and rolls back a second temporary write", () => {
  const directory = fs.mkdtempSync(path.join(tempRoot, "pair-preflight-"));
  const tfvarsPath = path.join(directory, "out.tfvars");
  const reportPath = path.join(directory, "binding.json");
  fs.writeFileSync(reportPath, "existing");
  assert.throws(() => writeAtomicPair({ tfvarsPath, bindingReportPath: reportPath, tfvarsBytes: Buffer.from("new"), bindingReportBytes: Buffer.from("new") }), /Refusing to overwrite/);
  assert.equal(fs.existsSync(tfvarsPath), false);
  let writes = 0;
  const fileSystem = {
    ...fs,
    writeFileSync: (...args) => {
      writes += 1;
      if (writes === 2) throw new Error("simulated second temporary write failure");
      return fs.writeFileSync(...args);
    },
  };
  assert.throws(() => writeAtomicPair({ tfvarsPath, bindingReportPath: path.join(directory, "second.json"), tfvarsBytes: Buffer.from("new"), bindingReportBytes: Buffer.from("new"), fileSystem }), /second temporary write/);
  assert.equal(fs.existsSync(tfvarsPath), false);
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
  assert.throws(() => assertStageBTfvarsBinding({ tfvarsPath: result.outputPath, bindingReportPath: result.bindingReportPath, bindingReportSha256: reportSha }), /tfvars SHA256/);
});
