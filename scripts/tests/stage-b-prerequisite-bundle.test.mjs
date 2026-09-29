import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import JSZip from "jszip";
import { generateStageAPrerequisites, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_STATE_OBJECT, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { packageStageBBroker } from "../aws/package-production-green-stage-b-broker.mjs";
import { produceStageBPrerequisiteBundle } from "../aws/produce-production-green-stage-b-prerequisite-bundle.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_B_STATE_RECONCILIATION } from "../aws/production-green-stage-b-state-reconciliation.mjs";
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from "../aws/stage-b-terraform-backend-contract.mjs";
import { runStageBStateReconciliation } from "../aws/reconcile-production-green-stage-b-state.mjs";
import { deriveStageBToolingInputTreeSha256 } from "../aws/validate-stage-b-image-reuse.mjs";
import { assertStageBPrerequisiteBundle, createStageBPrerequisiteBundle, materializeStageBPrerequisites, writeStageBRuntimeMaterialization, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW } from "../aws/stage-b-prerequisite-bundle.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { productionStageAState } from "./fixtures/production-stage-a-state.mjs";

const sourceSha = "a".repeat(40); const toolingTreeSha256 = "b".repeat(64); const ticketId = "CHG-20260915-001"; const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname); const root = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-prerequisite-bundle-test-")); fs.chmodSync(root, 0o700);
const run = (args) => {
  if (args[1] === "describe-subnets") return JSON.stringify({ Subnets: STAGE_B.privateSubnetIds.map((SubnetId, index) => ({ SubnetId, VpcId: "vpc-0123456789abcdef0", State: "available", MapPublicIpOnLaunch: false, AvailabilityZone: `eu-west-2${index ? "b" : "a"}`, CidrBlock: `10.0.${index}.0/24` })) });
  if (args[1] === "describe-route-tables") return JSON.stringify({ RouteTables: [{ RouteTableId: "rtb-12345678", VpcId: "vpc-0123456789abcdef0", Associations: [{ Main: true }], Routes: [{ DestinationCidrBlock: "0.0.0.0/0", NatGatewayId: "nat-12345678" }] }] });
  if (args[1] === "describe-security-groups") return JSON.stringify({ SecurityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((GroupId) => ({ GroupId, VpcId: "vpc-0123456789abcdef0" })) });
  if (args[1] === "describe-clusters") return JSON.stringify({ clusters: [{ clusterArn: STAGE_B.clusterArn, status: "ACTIVE" }] });
  if (args[1] === "describe-db-instances") return JSON.stringify({ DBInstances: [{ DBInstanceStatus: "available", DBSubnetGroup: { Subnets: STAGE_B.privateSubnetIds.map((SubnetIdentifier) => ({ SubnetIdentifier })) } }] });
  throw new Error(`unexpected AWS command ${args.join(" ")}`);
};

async function fixture() {
  const directory = fs.mkdtempSync(path.join(root, "run-")); fs.chmodSync(directory, 0o700);
  const statePath = path.join(directory, "stage-a-state.json"); const state = productionStageAState({ serial: STAGE_A_MINIMUM_STATE_SERIAL }); fs.writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  const stageAInputPath = path.join(directory, "stage-a-input.json"); generateStageAPrerequisites({ stateBackup: statePath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: sourceSha, toolingTreeSha256, outputPath: stageAInputPath, phase: "POST_APPLY", run });
  const broker = await packageStageBBroker({ outputPath: path.join(directory, "broker-package.zip"), toolingSha: sourceSha, toolingTreeSha256, repositoryRoot });
  const tfvarsPath = path.join(directory, "stage-b.tfvars"); const tfvarsBytes = Buffer.from(`broker_package_path = ${JSON.stringify(broker.package.path)}\n# ${"x".repeat(185184)}\n`); fs.writeFileSync(tfvarsPath, tfvarsBytes, { mode: 0o600 });
  const bindingReportPath = path.join(directory, "stage-b-tfvars-binding.json"); fs.writeFileSync(bindingReportPath, `${JSON.stringify({ tfvarsFormat: "hcl", tfvarsFileName: "stage-b.tfvars", tfvarsExtension: ".tfvars", tfvarsSha256: crypto.createHash("sha256").update(tfvarsBytes).digest("hex"), stageAInputPath, stageAStateBackupPath: statePath, brokerPackagePath: broker.package.path, brokerPackageManifestPath: broker.manifest.path })}\n`, { mode: 0o600 });
  const result = await createStageBPrerequisiteBundle({ outputPath: path.join(directory, "prerequisite-bundle.zip"), sourceSha, ticketId, workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha, brokerPackagePath: broker.package.path, brokerManifestPath: broker.manifest.path, stageAInputPath, stageAStateBackupPath: statePath, tfvarsPath, bindingReportPath });
  return { directory, statePath, stageAInputPath, broker, tfvarsPath, bindingReportPath, result };
}

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test("one producer bundle authenticates realistic payloads and private relocation", async () => {
  const first = await fixture();
  const verified = assertStageBPrerequisiteBundle({ bundlePath: first.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha });
  assert.equal(verified.manifest.payloadMemberCount, 6); assert.equal(verified.manifest.workflowPath, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW);
  const materialized = materializeStageBPrerequisites({ bundlePath: first.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha });
  assert.equal(fs.statSync(materialized.privateRoot).mode & 0o777, 0o700); assert.equal(fs.statSync(materialized.paths["broker-package"]).mode & 0o777, 0o600);
  const runtime = writeStageBRuntimeMaterialization({ prerequisite: materialized });
  assert.equal(runtime.materialization.relocatableFields.length, 4); assert.equal(path.basename(runtime.runtimeTfvarsPath), "stage-b.tfvars"); assert.match(fs.readFileSync(runtime.runtimeTfvarsPath, "utf8"), /consumer/); assert.throws(() => writeStageBRuntimeMaterialization({ prerequisite: materialized, outputDirectory: "/tmp/caller-chosen" }));
});

test("different preparation and execution roots preserve semantic relocation identity", async () => {
  const runFixture = await fixture(); const expected = { bundlePath: runFixture.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha };
  const preparationRoot = materializeStageBPrerequisites(expected); const executionRoot = materializeStageBPrerequisites(expected);
  const preparation = writeStageBRuntimeMaterialization({ prerequisite: preparationRoot });
  const execution = writeStageBRuntimeMaterialization({ prerequisite: executionRoot });
  assert.notEqual(preparation.runtimeTfvarsSha256, execution.runtimeTfvarsSha256);
  assert.notEqual(preparation.runtimeBindingSha256, execution.runtimeBindingSha256);
  assert.notEqual(preparation.runtimeMaterializationSha256, execution.runtimeMaterializationSha256);
  assert.equal(preparation.relocationContractSha256, execution.relocationContractSha256);
  assert.deepEqual(preparation.relocationContract.fieldToLogicalArtifact, execution.relocationContract.fieldToLogicalArtifact);
  assert.deepEqual(preparation.relocationContract.artifactIdentities, execution.relocationContract.artifactIdentities);
  assert.deepEqual(preparation.relocationContract.nonPathTfvarsIdentity, execution.relocationContract.nonPathTfvarsIdentity);
});

test("producer, run, source, ticket, attempt, and archive identity substitutions fail closed", async () => {
  const runFixture = await fixture(); const expected = { bundlePath: runFixture.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha };
  for (const changed of [
    { ...expected, sourceSha: "c".repeat(40), headSha: "c".repeat(40) }, { ...expected, ticketId: "CHG-20260915-002" }, { ...expected, workflowRunId: "124" }, { ...expected, workflowRunAttempt: "2" }, { ...expected, headSha: "d".repeat(40) }, { ...expected, repository: "attacker/repo" },
  ]) assert.throws(() => assertStageBPrerequisiteBundle(changed), /provenance|identity|archive/);
  const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.remove("stage-a-input.json"); const malformed = await archive.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 9 }, platform: "UNIX", streamFiles: false }); const malformedPath = path.join(runFixture.directory, "missing.zip"); fs.writeFileSync(malformedPath, malformed, { mode: 0o600 });
  assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: malformedPath }), /archive|member|manifest/);
  const hash = crypto.createHash("sha256").update(fs.readFileSync(runFixture.result.bundlePath)).digest("hex"); assert.equal(hash, runFixture.result.bundleSha256);
  assert.equal(STAGE_A_EXPECTED_STATE_LINEAGE, "02afb75a-f902-ab8a-f4c1-751d4aef7837"); assert.ok(stageAStateSemanticSha256);
});

test("every payload is required and archive names cannot escape the exact set", async () => {
  const runFixture = await fixture(); const expected = { bundlePath: runFixture.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha };
  for (const filename of ["broker-package.zip", "broker-package.zip.manifest.json", "stage-a-input.json", "stage-a-state-backup.json", "stage-b.tfvars", "stage-b-tfvars-binding.json"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.remove(filename); const file = path.join(runFixture.directory, `missing-${filename}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|manifest/);
  }
  for (const filename of ["broker-package.zip", "broker-package.zip.manifest.json", "stage-a-input.json", "stage-a-state-backup.json", "stage-b.tfvars", "stage-b-tfvars-binding.json"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.file(filename, Buffer.from("substituted")); const file = path.join(runFixture.directory, `modified-${filename}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|manifest/);
  }
  for (const filename of ["unexpected.txt", "../escape", "/absolute"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.file(filename, Buffer.from("x")); const file = path.join(runFixture.directory, `unsafe-${filename.replaceAll("/", "-")}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|filename/);
  }
});

test("the authenticated binding must name exactly stage-b.tfvars", async () => {
  const f = await fixture(); const binding = JSON.parse(fs.readFileSync(f.bindingReportPath, "utf8")); binding.tfvarsFileName = "stage-b.runtime.tfvars"; fs.writeFileSync(f.bindingReportPath, `${JSON.stringify(binding)}\n`, { mode: 0o600 });
  await assert.rejects(() => createStageBPrerequisiteBundle({ outputPath: path.join(f.directory, "filename-mismatch.zip"), sourceSha, ticketId, workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha, brokerPackagePath: f.broker.package.path, brokerManifestPath: f.broker.manifest.path, stageAInputPath: f.stageAInputPath, stageAStateBackupPath: f.statePath, tfvarsPath: f.tfvarsPath, bindingReportPath: f.bindingReportPath }), /filename/);
});

test("the producer carries realistic tfvars through the authenticated artifact instead of dispatch inputs", async () => {
  const f = await fixture(); const outputDirectory = path.join(f.directory, "producer"); fs.mkdirSync(outputDirectory, { mode: 0o700 });
  const integrationSourceSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
  const image = makeCanonicalImageAuthorization({ sourceSha: integrationSourceSha, imageReleaseSha: integrationSourceSha });
  const authorizationPath = path.join(f.directory, "image-authorization.json"); const authorizationBytes = Buffer.from(`${JSON.stringify(image.authorization)}\n`); fs.writeFileSync(authorizationPath, authorizationBytes, { mode: 0o600 });
  const taskAttributes = (family) => ({ arn: `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:1`, family, revision: 1, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: 1024, memory: 2048, container_definitions: JSON.stringify([{ name: "main", image: "example", essential: true }]), volume: [] });
  const candidates = ["backend", "worker", "canary"].map((kind) => ({ index_key: `60b782b-${kind}`, attributes: taskAttributes(kind === "canary" ? "mscqr-production-full-rls-green-application-canary" : `mscqr-production-rls-green-${kind}-candidate`) }));
  const modes = ["admin-bootstrap", "admin-ownership", "capability-preflight", "role-provision", "role-verify", "rollback", "runtime-policy", "verification"].map((mode) => ({ index_key: `60b782b-full-rls-${mode}`, attributes: taskAttributes(`mscqr-production-full-rls-green-full-rls-${mode}`) }));
  const stageBStatePath = path.join(f.directory, "stage-b-state.json"); fs.writeFileSync(stageBStatePath, `${JSON.stringify({ version: 4, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, resources: [{ mode: "managed", type: "aws_ecs_task_definition", name: "candidate_retained", instances: candidates }, { mode: "managed", type: "aws_ecs_task_definition", name: "executor_retained", instances: modes }, { type: "aws_iam_policy", name: "broker", instances: [{ attributes: { arn: STAGE_B_BROKER_POLICY.arn } }] }, { type: "aws_iam_role_policy_attachment", name: "broker", instances: [{ attributes: { policy_arn: STAGE_B_BROKER_POLICY.arn, role: STAGE_B_BROKER_POLICY.roleName } }] }] })}\n`, { mode: 0o600 });
  const producerRun = (args) => {
    if (args[0] === "sts" && args[1] === "get-caller-identity") return JSON.stringify({ Account: STAGE_B.account, Arn: `arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/GitHubActions` });
    if (args[0] === "s3api" && args[1] === "get-object") { const output = args[args.indexOf("--expected-bucket-owner") + 2]; fs.copyFileSync(args.includes("mscqr/production/rls-green/stage-a/terraform.tfstate") ? f.statePath : stageBStatePath, output); fs.chmodSync(output, 0o600); return "{}"; }
    return run(args);
  };
  const result = await produceStageBPrerequisiteBundle({ sourceSha: integrationSourceSha, ticketId, imageAuthorizationPath: authorizationPath, imageAuthorizationSha256: crypto.createHash("sha256").update(authorizationBytes).digest("hex"), outputDirectory, workflowRunId: "456", workflowRunAttempt: "1", run: producerRun, deriveToolingTree: deriveStageBToolingInputTreeSha256, verifyImageEvidence: image.verifyImageEvidence });
  const verified = assertStageBPrerequisiteBundle({ bundlePath: result.bundlePath, sourceSha: integrationSourceSha, ticketId, workflowRunId: "456", workflowRunAttempt: "1", headSha: integrationSourceSha });
  assert.equal(verified.manifest.payloadMemberCount, 6); assert.ok(verified.contents["stage-b.tfvars"].length > 0); assert.equal(JSON.parse(verified.contents["stage-b-tfvars-binding.json"]).brokerPackageManifestPath, path.join(outputDirectory, "broker-package.zip.manifest.json"));
  const materialized = materializeStageBPrerequisites({ bundlePath: result.bundlePath, sourceSha: integrationSourceSha, ticketId, workflowRunId: "456", workflowRunAttempt: "1", headSha: integrationSourceSha }); const runtime = writeStageBRuntimeMaterialization({ prerequisite: materialized });
  assert.equal(path.basename(runtime.runtimeTfvarsPath), "stage-b.tfvars"); assert.equal(path.basename(materialized.paths["broker-package-manifest"]), "broker-package.zip.manifest.json");
  const tfvarsBytes = verified.contents["stage-b.tfvars"]; const bindingBytes = verified.contents["stage-b-tfvars-binding.json"];
  const preflight = { status: "ready-for-plan", sourceSha: integrationSourceSha, tfvarsSha256: crypto.createHash("sha256").update(tfvarsBytes).digest("hex"), bindingReportSha256: crypto.createHash("sha256").update(bindingBytes).digest("hex") };
  const preflightPath = path.join(outputDirectory, "release-preflight.json"); const preflightBytes = Buffer.from(`${JSON.stringify(preflight)}\n`); fs.writeFileSync(preflightPath, preflightBytes, { mode: 0o600 });
  const drift = STAGE_B_STATE_RECONCILIATION.addresses.map((address) => { const policy = address.startsWith("aws_iam_role_policy"); return { address, mode: "managed", type: policy ? "aws_iam_role_policy" : "aws_iam_role", change: { actions: ["update"], before: policy ? { id: address, name: "policy", role: "role", policy: "old" } : { arn: "arn", name: "role", path: "/", permissions_boundary: null, assume_role_policy: "trust", inline_policy: "old" }, after: policy ? { id: address, name: "policy", role: "role", policy: "new" } : { arn: "arn", name: "role", path: "/", permissions_boundary: null, assume_role_policy: "trust", inline_policy: "new" }, before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {}, replace_paths: [] } }; });
  const refreshPlan = { format_version: "1.2", terraform_version: "1.15.8", errored: false, complete: true, applyable: true, variables: { tooling_sha: { value: integrationSourceSha } }, resource_changes: [], resource_drift: drift, output_changes: {} }; const normalPlan = { ...refreshPlan, applyable: false };
  const terraformData = path.join(outputDirectory, "terraform-data"); const savedPlan = path.join(outputDirectory, "refresh.tfplan"); const preparationPath = path.join(outputDirectory, "preparation.json");
  const terraform = (args) => { if (args[0] === "init") { fs.writeFileSync(path.join(terraformData, "terraform.tfstate"), JSON.stringify({ backend: { type: "s3", hash: 1, config: STAGE_B_TERRAFORM_BACKEND_CONFIG } }), { mode: 0o600 }); return ""; } if (args[0] === "plan") { const target = args[args.indexOf("-out") + 1]; fs.writeFileSync(target, Buffer.from("real-preparation-plan"), { mode: 0o600 }); return ""; } if (args[0] === "show") return JSON.stringify(path.basename(args.at(-1)) === "source-alignment.tfplan" ? normalPlan : refreshPlan); throw new Error(`unexpected Terraform command ${args.join(" ")}`); };
  const prepared = runStageBStateReconciliation(["--mode", "prepare", "--source-sha", integrationSourceSha, "--ticket-id", ticketId, "--admin-profile", "unused", "--credential-source", "named-profile", "--release-preflight", preflightPath, "--release-preflight-sha256", crypto.createHash("sha256").update(preflightBytes).digest("hex"), "--prerequisite-bundle", result.bundlePath, "--prerequisite-producer-workflow-run-id", "456", "--prerequisite-producer-workflow-run-attempt", "1", "--prerequisite-bundle-artifact-id", "789", "--prerequisite-bundle-artifact-digest", `sha256:${"e".repeat(64)}`, "--terraform-data-dir", terraformData, "--saved-plan-out", savedPlan, "--preparation-out", preparationPath], { run: producerRun, runTerraform: terraform, assertSource: () => true });
  assert.equal(prepared.status, "prepared"); assert.equal(prepared.preparation.tfvarsSha256, preflight.tfvarsSha256); assert.match(prepared.preparation.runtimeTfvarsSha256, /^[a-f0-9]{64}$/); assert.notEqual(prepared.preparation.tfvarsSha256, prepared.preparation.runtimeTfvarsSha256); assert.equal(prepared.preparation.planSemantics.remoteResourceMutationCount, 0); assert.equal(prepared.preparation.planSemantics.stateRecordChangeCount, 10);
});
