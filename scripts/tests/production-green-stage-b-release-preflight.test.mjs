import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { produceStageBReleasePreflight } from "../aws/produce-production-green-stage-b-release-preflight.mjs";

const sourceSha = "a".repeat(40);
const digest = "b".repeat(64);
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-release-preflight-test-"));

test("release-preflight producer emits a source-bound path-independent report", () => {
  const directory = temp(); const imagePath = path.join(directory, "image-authorization.json"); const output = path.join(directory, "release-preflight.json");
  const authorization = { sourceSha, authorizationSha256: digest, images: [] };
  fs.writeFileSync(imagePath, JSON.stringify(authorization), { mode: 0o600 });
  const imageSha = crypto.createHash("sha256").update(fs.readFileSync(imagePath)).digest("hex");
  const result = produceStageBReleasePreflight(["--source-sha", sourceSha, "--image-authorization", imagePath, "--image-authorization-sha256", imageSha, "--tfvars-sha256", digest, "--binding-sha256", digest, "--output", output], {
    readProtectedMainCheckout: () => ({ toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, porcelainStatus: "" }),
    assertProtectedCheckout: () => true,
    readAuthorization: () => authorization,
    verifyAuthorization: () => true,
    releaseRun: () => "{}",
    runReleaseReadPreflight: () => ({ schemaVersion: 1, status: "valid", stageAStateIdentityPath: path.join(directory, "producer-local.json") }),
  });
  const report = JSON.parse(fs.readFileSync(output));
  assert.equal(result.status, "ready-for-plan"); assert.equal(report.sourceSha, sourceSha); assert.equal(report.tfvarsSha256, digest); assert.equal(report.bindingReportSha256, digest); assert.equal(report.stageAStateIdentityPath, null); assert.equal(fs.statSync(output).mode & 0o777, 0o600);
});

test("release-preflight producer rejects a malformed source identity", () => {
  assert.throws(() => produceStageBReleasePreflight(["--source-sha", "bad", "--image-authorization", "/tmp/image", "--image-authorization-sha256", digest, "--tfvars-sha256", digest, "--binding-sha256", digest, "--output", "/tmp/report"]), /identity is malformed/);
});
