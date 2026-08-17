import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildStageBProtectedMainCheckoutEvidence } from "../aws/stage-b-deployment-identity.mjs";
import { recoverCapturedStageBPlan } from "../plan-production-green-stage-b.mjs";

const release = "/private/tmp/stage-b-release-e92ffe5-final.9PMxUd";
const planPath = path.join(release, "stage-b-deployment.tfplan");
const planJsonPath = path.join(release, "stage-b-deployment.plan.json");
const canonicalPath = path.join(release, "stage-b-deployment.plan.canonical.json");
const available = [planPath, planJsonPath, canonicalPath].every((filePath) => fs.existsSync(filePath));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

test("partial-apply captured-plan recovery does not require RECOVERY_ALIAS_ONLY attestation", () => {
  const source = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
  assert.match(source, /const partialApplyRecovery = cliOptions\.includes\("--partial-apply-recovery"\);/);
  assert.match(source, /Object\.entries\(expected\)\.some\(\(\[name, value\]\) => name !== "recoveryAttestationSha256"/);
});

test("preserved production plan recovers to PLAN_CAPTURED without Terraform", { skip: !available }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-recovery-"));
  const previousWorkspace = process.env.TF_WORKSPACE;
  process.env.TF_WORKSPACE = "default";
  try {
    const copied = { saved: path.join(directory, "plan.tfplan"), json: path.join(directory, "plan.json"), canonical: path.join(directory, "plan.canonical.json") };
    fs.copyFileSync(planPath, copied.saved); fs.copyFileSync(planJsonPath, copied.json); fs.copyFileSync(canonicalPath, copied.canonical);
    const hashes = { saved: hash(fs.readFileSync(copied.saved)), json: hash(fs.readFileSync(copied.json)), canonical: hash(fs.readFileSync(copied.canonical)) };
    assert.equal(hashes.saved, "5289c8d58dab9523c90b6065d88182f40568d4f15d4abbb337c7771d25767bb3");
    assert.equal(hashes.json, "0de0ca2b5db2763bb281f44f03493c1ea22024ca0c16bc9fc971aa7128209f0c");
    assert.equal(hashes.canonical, "21b2d5258d49a0ff7ce5a0b848c21bb80f0b526ae4f3787845551a7b68d64ae2");
    const checkout = buildStageBProtectedMainCheckoutEvidence({ toolingSha: "e92ffe5b0eaa46503d41b23b79a56a82c38959ee", currentHead: "e92ffe5b0eaa46503d41b23b79a56a82c38959ee", originMainHead: "e92ffe5b0eaa46503d41b23b79a56a82c38959ee", isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" });
    const capturePath = path.join(directory, "capture.json");
    const result = recoverCapturedStageBPlan({
      tfvars: path.join(directory, "stage-b.tfvars"),
      cliOptions: ["--recovery", "--closure-mode", "production", "--saved-plan", copied.saved, "--plan-json", copied.json, "--canonical-plan-json", copied.canonical, "--capture-report", capturePath, "--saved-plan-sha256", hashes.saved, "--plan-json-sha256", hashes.json, "--canonical-plan-file-sha256", hashes.canonical, "--stage-b-lineage", "4e438e59-8b8b-194d-030c-5ede0c26344a", "--stage-b-serial", "76"],
      protectedMainCheckout: checkout,
      readInputs: () => ({ toolingTreeSha256: "9cf5deb9de7aef6718577fcc1f7a30ab0123ef61ffa559e7d108bbf6c1d0cafe", refreshReportSha256: "d".repeat(64), bindingReport: { stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 76 } }),
    });
    assert.equal(result.status, "PLAN_CAPTURED");
    const report = JSON.parse(fs.readFileSync(capturePath));
    assert.equal(report.brokerOperation, "update");
    assert.equal(report.brokerUpdatePresent, true);
    assert.deepEqual(report.brokerActions, ["update"]);
    assert.equal(report.brokerReferenceValidationPending, true);
    assert.equal(report.approvedForApply, false);
  } finally {
    if (previousWorkspace === undefined) delete process.env.TF_WORKSPACE; else process.env.TF_WORKSPACE = previousWorkspace;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
