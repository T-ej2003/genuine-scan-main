import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertNormalReleaseAuthorizationTransport, assertNormalReleaseGateInputs } from "../aws/production-release-dispatch-contract.mjs";
import { assertReleaseTrainNormalDispatchContract } from "../aws/production-release-oidc-contract.mjs";
import { verifyProductionReleaseImageAuthorization } from "../aws/verify-production-release-image-authorization.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const fixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha });
const bytes = Buffer.from(JSON.stringify(fixture.authorization));
const digest = crypto.createHash("sha256").update(bytes).digest("hex");
const authenticate = (authorization, expectedSourceSha) => {
  verifyProductionReleaseImageAuthorization({ authorization, sourceSha: expectedSourceSha, verifyImageEvidence: fixture.verifyImageEvidence, now: fixture.now });
  return true;
};

test("Release Train validates and forwards the complete normal Release Gate contract", () => {
  const releaseTrain = yaml.load(fs.readFileSync(".github/workflows/release-train.yml", "utf8"));
  assert.equal(assertReleaseTrainNormalDispatchContract(releaseTrain), true);
  const dispatch = releaseTrain.jobs.orchestrate.steps.find(({ name }) => name === "Trigger final Release Gate").run;
  assert.equal(spawnSync("bash", ["-n"], { input: dispatch, encoding: "utf8" }).status, 0);
  assert.equal(assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: bytes, expectedSha256: digest }).authenticationDeferredToReleaseGate, true);
  assert.equal(assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: true, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), true);
});

test("normal Release Gate rejects missing preservation, missing or stale authorization, and wrong source", () => {
  assert.throws(() => assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend: false, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), /preserve/);
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: Buffer.alloc(0), expectedSha256: digest }), /hash-mismatched/);
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: bytes, expectedSha256: "0".repeat(64) }), /hash-mismatched/);
  const stale = Buffer.from(JSON.stringify({ ...fixture.authorization, sourceSha: "b".repeat(40) }));
  assert.throws(() => assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes: stale, expectedSha256: crypto.createHash("sha256").update(stale).digest("hex") }), /stale/);
  assert.throws(() => assertNormalReleaseGateInputs({ sourceSha: "b".repeat(40), preserveCurrentFrontend: true, authorizationBytes: bytes, expectedSha256: digest, authenticateAuthorization: authenticate }), /stale|source/);
});
