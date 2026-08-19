import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readPlanningInputs, runStageBTerraformPlanCommand } from "../plan-production-green-stage-b.mjs";
import { assertStageBRecoveryProvenance } from "../aws/stage-b-refresh-contract.mjs";
import { assertStageBRecoveryRefreshStatus } from "../aws/stage-b-deployment-contract.mjs";

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const digest = (character) => character.repeat(64);

test("recovery refresh status is mode-exact", () => {
  assert.equal(assertStageBRecoveryRefreshStatus({ status: "RESOURCE_DRIFT", recoveryMode: "PARTIAL_APPLY_RECOVERY" }), true);
  assert.equal(assertStageBRecoveryRefreshStatus({ status: "RESOURCE_DRIFT", recoveryMode: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" }), true);
  assert.equal(assertStageBRecoveryRefreshStatus({ status: "REVIEWED_OUTPUT_RECONCILIATION", recoveryMode: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" }), true);
  assert.throws(() => assertStageBRecoveryRefreshStatus({ status: "RESOURCE_DRIFT", recoveryMode: "NORMAL" }), /exact reviewed refresh evidence/);
  for (const recoveryMode of ["PARTIAL_APPLY_RECOVERY", "RECOVERY_ALIAS_ONLY", "NORMAL"]) assert.throws(() => assertStageBRecoveryRefreshStatus({ status: "REVIEWED_OUTPUT_RECONCILIATION", recoveryMode }), /exact reviewed refresh evidence/);
  for (const status of ["NO_CHANGES", "OUTPUT_DRIFT", undefined]) assert.throws(() => assertStageBRecoveryRefreshStatus({ status, recoveryMode: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" }), /exact reviewed refresh evidence/);
});

test("recovery planning validates refresh against observation binding before reaching the plan seam", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-provenance-"));
  fs.chmodSync(directory, 0o700);
  const writePrivate = (name, value) => { const file = path.join(directory, name); fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 }); return file; };
  const sourceSha = "a".repeat(40);
  const toolingTreeSha256 = digest("b");
  const imageReleaseSha = "c".repeat(40);
  const shared = {
    toolingSha: sourceSha, toolingTreeSha256, imageReleaseSha, imageEvidenceCanonicalSha256: digest("d"),
    stageAInputSha256: digest("e"), stageAStateBackupSha256: digest("f"), stageAStateObject: "stage-a.tfstate",
    stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35,
    stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 90, stateBackupSha256: digest("1"),
    brokerPackagePath: "/private/tmp/broker.zip", brokerPackageManifestSha256: digest("2"), brokerPackageRawSha256: digest("3"),
    sourceContractSha256: digest("4"), migrationSetDigest: digest("5"), packageChecksumSha256: digest("6"), images: { backend: "same" },
  };
  const observation = { ...shared, recoveryOnly: false, tfvarsSha256: digest("7") };
  const classification = { status: "REVIEWED_PARTIAL_APPLY_RESIDUE" };
  const classificationPath = writePrivate("classification.json", classification);
  const classificationSha256 = hash(fs.readFileSync(classificationPath));
  const attestation = { currentObservedEvidence: { liveVersion: "2", configuredDesiredVersion: "3" } };
  const attestationPath = writePrivate("attestation.json", attestation);
  const attestationSha256 = hash(fs.readFileSync(attestationPath));
  const signaturePath = writePrivate("signature.json", { signed: true });
  const refresh = { status: "RESOURCE_DRIFT", bindingReportSha256: "0".repeat(64), tfvarsSha256: observation.tfvarsSha256 };
  const refreshPath = writePrivate("refresh.json", refresh);
  const observationPath = writePrivate("observation-binding.json", observation);
  const observationBindingReportSha256 = hash(fs.readFileSync(observationPath));
  refresh.bindingReportSha256 = observationBindingReportSha256;
  fs.writeFileSync(refreshPath, `${JSON.stringify(refresh)}\n`, { mode: 0o600 });
  const refreshReportSha256 = hash(fs.readFileSync(refreshPath));
  const recovery = {
    ...shared, recoveryOnly: true, recoveryMode: "RECOVERY_ALIAS_ONLY", tfvarsSha256: digest("8"),
    recoveryRefreshReportSha256: refreshReportSha256, recoveryClassificationSha256: classificationSha256,
    recoveryAttestationSha256: attestationSha256, recoveryLiveVersion: "2", recoveryDesiredVersion: "3",
  };
  const args = [
    "--binding-report", path.join(directory, "recovery-binding.json"), "--binding-report-sha256", digest("9"),
    "--refresh-binding-report", observationPath, "--refresh-binding-report-sha256", observationBindingReportSha256,
    "--tooling-tree-sha256", toolingTreeSha256, "--image-release-sha", imageReleaseSha,
    "--refresh-report", refreshPath, "--refresh-report-sha256", hash(fs.readFileSync(refreshPath)),
    "--recovery-only", "--recovery-classification", classificationPath, "--recovery-classification-sha256", classificationSha256,
    "--recovery-attestation-sha256", attestationSha256, "--recovery-attestation-report", attestationPath,
    "--recovery-attestation-signature", signaturePath, "--recovery-attestation-signature-sha256", hash(fs.readFileSync(signaturePath)),
    "--closure-mode", "production",
  ];
  let refreshValidatedAgainst;
  const inputs = readPlanningInputs("/private/tmp/recovery.tfvars", args, { currentHead: sourceSha }, {
    validateTfvarsBinding: () => recovery,
    assertRecovery: () => true,
    assertRefresh: ({ bindingReport }) => { refreshValidatedAgainst = bindingReport; return true; },
    backendMetadata: { backendMetadataSha256: digest("a"), terraformDataDir: directory },
  });
  assert.equal(inputs.bindingReport.tfvarsSha256 === observation.tfvarsSha256, false);
  assert.deepEqual(refreshValidatedAgainst, observation);
  let planCalls = 0;
  const result = runStageBTerraformPlanCommand({ env: { TF_WORKSPACE: "default" }, argv: ["/private/tmp/recovery.tfvars", ...args], showWorkspace: () => "default", plan: () => { planCalls += 1; return { status: 2 }; } });
  assert.equal(result.workspace, "default");
  assert.equal(planCalls, 1);
});

test("recovery planning fails closed when the observation binding is omitted", () => {
  assert.throws(() => readPlanningInputs("/private/tmp/recovery.tfvars", ["--binding-report", "/private/tmp/recovery.json", "--binding-report-sha256", digest("a"), "--tooling-tree-sha256", digest("b"), "--image-release-sha", "c".repeat(40), "--refresh-report", "/private/tmp/refresh.json", "--refresh-report-sha256", digest("d"), "--recovery-only", "--closure-mode", "production"], { currentHead: "e".repeat(40) }, { validateTfvarsBinding: () => ({ recoveryOnly: true }) }), /original observation binding/);
});

test("partial-apply recovery accepts only explicitly bound resource drift", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-partial-provenance-"));
  fs.chmodSync(directory, 0o700);
  const write = (name, value) => { const file = path.join(directory, name); fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 }); return file; };
  const sourceSha = "a".repeat(40);
  const shared = { toolingSha: sourceSha, toolingTreeSha256: digest("b"), imageReleaseSha: "g".repeat(40), imageEvidenceCanonicalSha256: digest("d"), stageAInputSha256: digest("1"), stageAStateBackupSha256: digest("2"), stageAStateObject: "stage-a.tfstate", stageAStateLineage: "stage-a-lineage", stageAStateSerial: 35, stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 96, stateBackupSha256: digest("e"), sourceContractSha256: digest("3"), migrationSetDigest: digest("4"), packageChecksumSha256: digest("5"), images: { backend: "same" } };
  const observation = { ...shared, recoveryOnly: false, tfvarsSha256: digest("c") };
  const binding = { ...shared, recoveryOnly: false, partialApplyRecovery: true, recoveryMode: "PARTIAL_APPLY_RECOVERY", tfvarsSha256: observation.tfvarsSha256, recoveryRefreshReportSha256: "0".repeat(64), recoveryObservationBindingSha256: "0".repeat(64), recoveryStateLineage: shared.stateLineage, recoveryStateSerial: shared.stateSerial };
  const bindingPath = write("observation.json", observation);
  const refreshPath = write("refresh.json", { status: "RESOURCE_DRIFT", bindingReportSha256: hash(fs.readFileSync(bindingPath)), tfvarsSha256: observation.tfvarsSha256 });
  const actualRefreshSha256 = hash(fs.readFileSync(refreshPath));
  binding.recoveryRefreshReportSha256 = actualRefreshSha256; binding.recoveryObservationBindingSha256 = hash(fs.readFileSync(bindingPath));
  assert.doesNotThrow(() => assertStageBRecoveryProvenance({ refreshReport: JSON.parse(fs.readFileSync(refreshPath)), refreshReportSha256: actualRefreshSha256, observationBindingReport: observation, observationBindingReportSha256: binding.recoveryObservationBindingSha256, recoveryBindingReport: binding, recoveryBindingReportSha256: digest("f"), recoveryMode: "PARTIAL_APPLY_RECOVERY" }));
  assert.throws(() => assertStageBRecoveryProvenance({ refreshReport: { ...JSON.parse(fs.readFileSync(refreshPath)), tfvarsSha256: digest("6") }, refreshReportSha256: actualRefreshSha256, observationBindingReport: observation, observationBindingReportSha256: binding.recoveryObservationBindingSha256, recoveryBindingReport: binding, recoveryBindingReportSha256: digest("f"), recoveryMode: "PARTIAL_APPLY_RECOVERY" }), /selected observation tfvars/);
  assert.throws(() => assertStageBRecoveryProvenance({ refreshReport: JSON.parse(fs.readFileSync(refreshPath)), refreshReportSha256: actualRefreshSha256, observationBindingReport: observation, observationBindingReportSha256: binding.recoveryObservationBindingSha256, recoveryBindingReport: binding, recoveryBindingReportSha256: binding.recoveryObservationBindingSha256, recoveryMode: "PARTIAL_APPLY_RECOVERY" }), /distinct recovery binding/);
  const args = [
    "--binding-report", path.join(directory, "tfvars-binding.json"), "--binding-report-sha256", digest("f"),
    "--refresh-binding-report", bindingPath, "--refresh-binding-report-sha256", hash(fs.readFileSync(bindingPath)),
    "--tooling-tree-sha256", binding.toolingTreeSha256, "--image-release-sha", "g".repeat(40),
    "--refresh-report", refreshPath, "--refresh-report-sha256", actualRefreshSha256, "--partial-apply-recovery", "--closure-mode", "production",
  ];
  let validated;
  const inputs = readPlanningInputs("/private/tmp/recovery.tfvars", args, { currentHead: sourceSha }, {
    validateTfvarsBinding: () => binding,
    assertRefresh: (value) => { validated = value; return true; },
    backendMetadata: { backendMetadataSha256: digest("h"), terraformDataDir: directory },
  });
  assert.equal(inputs.partialApplyRecovery, true);
  assert.deepEqual(validated.bindingReport, observation);
  assert.equal(validated.allowReviewedResourceDrift, true);
});
