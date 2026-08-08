import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { parseCanonicalTerraformSerialCliText, createRecoveryAttestation, signRecoveryAttestation } from "../aws/stage-b-partial-apply-recovery-contract.mjs";
import { runCli } from "../aws/classify-stage-b-partial-apply-recovery.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const classifier = path.join(repositoryRoot, "scripts/aws/classify-stage-b-partial-apply-recovery.mjs");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const privateDirectory = (prefix) => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); fs.chmodSync(directory, 0o700); return directory; };
const writePrivate = (filePath, bytes) => { fs.writeFileSync(filePath, bytes, { mode: 0o600, flag: "wx" }); return bytes; };

function fixture() {
  const directory = privateDirectory("stage-b-recovery-cli-");
  const refreshReport = { status: "RESOURCE_DRIFT", resourceChanges: { nonNoOp: 1, changes: [{ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", actions: ["update"] }] } };
  const refreshBytes = writePrivate(path.join(directory, "refresh.json"), Buffer.from(`${JSON.stringify(refreshReport)}\n`));
  const refreshReportSha256 = sha256(refreshBytes);
  const current = { protectedSourceSha: "523817e71755616ed004a5dea03ea4e10672723b", terraformLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", terraformSerial: 78, refreshReportSha256, terraformAddress: "aws_lambda_alias.reviewed", resourceMode: "managed", resourceModule: null, resourceType: "aws_lambda_alias", resourceName: "reviewed", functionName: "mscqr-production-rls-approval-broker", aliasName: "reviewed", stateVersion: "3", configuredDesiredVersion: "3", liveVersion: "2", changedAttributes: ["function_version"], routingConfigurationChanged: false, descriptionChanged: false, functionIdentityChanged: false, aliasIdentityChanged: false, additionalManagedResourceDrift: false };
  const historical = { protectedSourceSha: "0".repeat(40), terraformLineage: current.terraformLineage, preApplySerial: 76, failedMutation: { terraformAddress: "aws_lambda_alias.reviewed", awsService: "lambda", operation: "UpdateAlias", result: "FAILED", failureClass: "AUTHORIZATION", awsErrorClass: "AccessDeniedException", attemptedTargetVersion: "3" }, inputs: ["savedPlan", "planJson", "logicalPlan", "planApproved", "planBoundPermission", "applyStdout", "applyStderr"].map((name) => ({ name, path: `/private/tmp/${name}`, sha256: "a".repeat(64), trustClassification: name.startsWith("apply") ? "RAW_FORENSIC" : "STRUCTURED_VERIFIED", required: true })) };
  const report = createRecoveryAttestation({ producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical, currentObservedEvidence: current, reviewedRecoveryAssertion: { historicalFailedTarget: "3", stateTarget: "3", liveTarget: "2", onlyFunctionVersionChanged: true, noAdditionalManagedDrift: true, authorizesPlan: false, authorizesApply: false, failureClass: "AUTHORIZATION", operation: "lambda:UpdateAlias" } });
  const signature = signRecoveryAttestation(report, { sign: () => "AQ==" });
  const attestationBytes = writePrivate(path.join(directory, "attestation.json"), Buffer.from(`${JSON.stringify(report, null, 2)}\n`));
  const signatureBytes = writePrivate(path.join(directory, "signature.json"), Buffer.from(`${JSON.stringify(signature, null, 2)}\n`));
  const fakeBin = path.join(directory, "bin"); fs.mkdirSync(fakeBin, { mode: 0o700 });
  const fakeAws = path.join(fakeBin, "aws"); fs.writeFileSync(fakeAws, "#!/bin/sh\nprintf '{\"SignatureValid\":true}\n'\n", { mode: 0o700, flag: "wx" });
  const args = ["--refresh-report", path.join(directory, "refresh.json"), "--refresh-report-sha256", refreshReportSha256, "--attestation", path.join(directory, "attestation.json"), "--attestation-sha256", sha256(attestationBytes), "--signature", path.join(directory, "signature.json"), "--signature-sha256", sha256(signatureBytes), "--source-sha", current.protectedSourceSha, "--lineage", current.terraformLineage, "--serial", String(current.terraformSerial)];
  return { directory, fakeBin, args, expectedStatus: "REVIEWED_PARTIAL_APPLY_RESIDUE" };
}

test("exported runCli remains synchronous and returns its classification result", () => {
  const value = fixture();
  const result = runCli([...value.args, "--output", path.join(value.directory, "direct.json")], { verifySignature: () => true });
  assert.equal(result.status, value.expectedStatus);
  assert.equal(fs.existsSync(result.outputPath), true);
});

test("executable CLI produces one classification artifact without the Promise TypeError", () => {
  const value = fixture();
  const output = path.join(value.directory, "cli.json");
  const result = spawnSync(process.execPath, [classifier, ...value.args, "--output", output], { cwd: repositoryRoot, env: { ...process.env, PATH: `${value.fakeBin}:${process.env.PATH}` }, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /runCli\(\.\.\.\)\.then is not a function/);
  assert.equal(JSON.parse(fs.readFileSync(output, "utf8")).status, value.expectedStatus);
});

test("executable CLI fails closed on invalid input without publishing classification", () => {
  const value = fixture();
  const output = path.join(value.directory, "invalid.json");
  const args = [...value.args]; args[args.indexOf("--refresh-report-sha256") + 1] = "0".repeat(64);
  const result = spawnSync(process.execPath, [classifier, ...args, "--output", output], { cwd: repositoryRoot, env: { ...process.env, PATH: `${value.fakeBin}:${process.env.PATH}` }, encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA256 mismatch/);
  assert.equal(fs.existsSync(output), false);
  assert.doesNotMatch(result.stderr, /runCli\(\.\.\.\)\.then is not a function/);
});

test("executable CLI accepts numeric state serial supplied as text and rejects malformed serials", () => {
  const valid = fixture();
  for (const serial of ["79", "78foo", "078", " 78 ", "78.0", "7.8e1", "-1", ""]) {
    const output = path.join(valid.directory, `serial-${Buffer.from(serial).toString("hex") || "empty"}.json`);
    const args = [...valid.args]; args[args.indexOf("--serial") + 1] = serial;
    const result = spawnSync(process.execPath, [classifier, ...args, "--output", output], { cwd: repositoryRoot, env: { ...process.env, PATH: `${valid.fakeBin}:${process.env.PATH}` }, encoding: "utf8" });
    assert.notEqual(result.status, 0, `serial ${JSON.stringify(serial)} unexpectedly accepted`);
    assert.equal(fs.existsSync(output), false);
  }
  assert.equal(parseCanonicalTerraformSerialCliText("78"), 78);
});
