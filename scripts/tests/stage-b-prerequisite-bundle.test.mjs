import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import JSZip from "jszip";
import { generateStageAPrerequisites, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_MINIMUM_STATE_SERIAL, STAGE_A_STATE_OBJECT, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { packageStageBBroker } from "../aws/package-production-green-stage-b-broker.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { assertStageBPrerequisiteBundle, createStageBPrerequisiteBundle, materializeStageBPrerequisites, writeStageBRuntimeMaterialization, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW } from "../aws/stage-b-prerequisite-bundle.mjs";
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
  const result = await createStageBPrerequisiteBundle({ outputPath: path.join(directory, "prerequisite-bundle.zip"), sourceSha, ticketId, workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha, brokerPackagePath: broker.package.path, brokerManifestPath: broker.manifest.path, stageAInputPath, stageAStateBackupPath: statePath });
  return { directory, statePath, stageAInputPath, broker, result };
}

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test("one deterministic producer bundle authenticates four payloads and private relocation", async () => {
  const first = await fixture(); const second = await fixture();
  assert.equal(first.result.bundleSha256, second.result.bundleSha256);
  const verified = assertStageBPrerequisiteBundle({ bundlePath: first.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha });
  assert.equal(verified.manifest.payloadMemberCount, 4); assert.equal(verified.manifest.workflowPath, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW);
  const materialized = materializeStageBPrerequisites({ bundlePath: first.result.bundlePath, sourceSha, ticketId, repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1", headSha: sourceSha });
  assert.equal(fs.statSync(materialized.privateRoot).mode & 0o777, 0o700); assert.equal(fs.statSync(materialized.paths["broker-package"]).mode & 0o777, 0o600);
  const runtime = writeStageBRuntimeMaterialization({ originalTfvarsBytes: Buffer.from('broker_package_path = "/producer/broker.zip"\naccount_id = "368992683803"\n'), originalBindingBytes: Buffer.from(JSON.stringify({ tfvarsSha256: "c".repeat(64), stageAInputPath: "/producer/stage-a-input.json", stageAStateBackupPath: "/producer/stage-a-state-backup.json", brokerPackagePath: "/producer/broker.zip", brokerPackageManifestPath: "/producer/broker-package.manifest.json" }) + "\n"), prerequisite: materialized });
  assert.equal(runtime.materialization.relocatableFields.length, 4); assert.match(fs.readFileSync(runtime.runtimeTfvarsPath, "utf8"), /consumer/); assert.throws(() => writeStageBRuntimeMaterialization({ originalTfvarsBytes: Buffer.from(""), originalBindingBytes: Buffer.from("{}"), prerequisite: materialized, outputDirectory: "/tmp/caller-chosen" }));
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
  for (const filename of ["broker-package.zip", "broker-package.manifest.json", "stage-a-input.json", "stage-a-state-backup.json"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.remove(filename); const file = path.join(runFixture.directory, `missing-${filename}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|manifest/);
  }
  for (const filename of ["broker-package.zip", "broker-package.manifest.json", "stage-a-input.json", "stage-a-state-backup.json"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.file(filename, Buffer.from("substituted")); const file = path.join(runFixture.directory, `modified-${filename}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|manifest/);
  }
  for (const filename of ["unexpected.txt", "../escape", "/absolute"]) {
    const archive = await JSZip.loadAsync(fs.readFileSync(runFixture.result.bundlePath)); archive.file(filename, Buffer.from("x")); const file = path.join(runFixture.directory, `unsafe-${filename.replaceAll("/", "-")}.zip`); fs.writeFileSync(file, await archive.generateAsync({ type: "nodebuffer" }), { mode: 0o600 }); assert.throws(() => assertStageBPrerequisiteBundle({ ...expected, bundlePath: file }), /archive|member|filename/);
  }
});
