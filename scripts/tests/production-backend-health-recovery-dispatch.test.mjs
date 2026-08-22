import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildBackendHealthRecoveryDispatch, canonicalWorkflowJsonInput, runCli } from "../aws/dispatch-production-backend-health-recovery.mjs";

const sourceSha = "d".repeat(40);
const currentTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const recoveryImageDigest = `sha256:${"4".repeat(64)}`;
const image = { schemaVersion: 2, valid: true, sourceSha, imageReleaseSha: sourceSha, backendDigest: recoveryImageDigest, evidenceSha256: "a".repeat(64), authorizationSha256: "a".repeat(64) };
const approval = { ticket: "ticket", approvedBy: "operator", approverRole: "production operator", reason: "missing image recovery", verificationRef: "verification", sourceSha, currentTaskDefinitionArn, recoveryImageDigest };
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("workflow JSON transport owns serialization and hash bytes", () => {
  const variants = [JSON.stringify(image), `${JSON.stringify(image)}\n`, JSON.stringify(image, null, 2), `${JSON.stringify(image, null, 2)}\n`];
  const results = variants.map((value) => canonicalWorkflowJsonInput(Buffer.from(value), "fixture"));
  for (const result of results) assert.equal(result.sha256, hash(result.value));
  assert.equal(new Set(results.map(({ value }) => value)).size, 1);
  assert.notEqual(hash(Buffer.from(`${JSON.stringify(image, null, 2)}\n`)), hash(JSON.stringify(image, null, 2)), "run 32567632721 failure construction must remain reproducible");
});

test("recovery dispatch sends byte-identical authorization and approval hashes", () => {
  const dispatch = buildBackendHealthRecoveryDispatch({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service: "mscqr-backend-servi-euw2", releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", imageAuthorizationBytes: Buffer.from(`${JSON.stringify(image, null, 2)}\n`), approvalBytes: Buffer.from(`${JSON.stringify(approval, null, 2)}\n`) });
  const fields = Object.fromEntries(dispatch.args.flatMap((value, index) => value === "-f" ? [dispatch.args[index + 1].split(/=(.*)/s).slice(0, 2)] : []));
  assert.equal(hash(fields.backend_recovery_image_authorization_json), fields.backend_recovery_image_authorization_sha256);
  assert.equal(hash(fields.backend_recovery_approval_json), fields.backend_recovery_approval_sha256);
  assert.deepEqual(JSON.parse(fields.backend_recovery_image_authorization_json), image);
  assert.deepEqual(JSON.parse(fields.backend_recovery_approval_json), approval);
});

test("recovery CLI passes the builder's exact JSON and hashes to gh", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-dispatch-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, "image.json");
  const approvalPath = path.join(directory, "approval.json");
  fs.writeFileSync(imagePath, `${JSON.stringify(image, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(approvalPath, `${JSON.stringify(approval, null, 2)}\n`, { mode: 0o600 });
  let invocation;
  const result = runCli([
    "--source-sha", sourceSha, "--current-task-definition", currentTaskDefinitionArn,
    "--recovery-image-digest", recoveryImageDigest, "--service", "mscqr-backend-servi-euw2",
    "--release-mode", "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
    "--image-authorization", imagePath, "--approval", approvalPath,
  ], { protectedMain: () => {}, run: (command, args) => { invocation = { command, args }; } });
  const fields = Object.fromEntries(invocation.args.flatMap((value, index) => value === "-f" ? [invocation.args[index + 1].split(/=(.*)/s).slice(0, 2)] : []));
  assert.equal(invocation.command, "gh");
  assert.equal(hash(fields.backend_recovery_image_authorization_json), fields.backend_recovery_image_authorization_sha256);
  assert.equal(hash(fields.backend_recovery_approval_json), fields.backend_recovery_approval_sha256);
  assert.equal(result.imageTransportSha256, fields.backend_recovery_image_authorization_sha256);
  assert.equal(result.approvalTransportSha256, fields.backend_recovery_approval_sha256);
  assert.equal(result.dispatchCount, 1);
});

test("recovery dispatch rejects every mismatched protected binding", () => {
  const valid = { sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service: "mscqr-backend-servi-euw2", releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", imageAuthorizationBytes: Buffer.from(JSON.stringify(image)), approvalBytes: Buffer.from(JSON.stringify(approval)) };
  for (const change of [
    { sourceSha: "e".repeat(40) }, { currentTaskDefinitionArn: currentTaskDefinitionArn.replace(":47", ":48") },
    { recoveryImageDigest: `sha256:${"5".repeat(64)}` }, { service: "wrong" }, { releaseMode: "normal" },
  ]) assert.throws(() => buildBackendHealthRecoveryDispatch({ ...valid, ...change }), /different recovery|differs|invalid/);
  assert.throws(() => canonicalWorkflowJsonInput(Buffer.from("not-json")), /valid JSON/);
});

test("adjacent normal and rotation dispatches hash the values they transport", () => {
  const deployment = fs.readFileSync("documents/ops/deployment-runbook.md", "utf8");
  const rotation = fs.readFileSync("documents/SECURITY_KEY_ROTATION_RUNBOOK.md", "utf8");
  assert.match(deployment, /authorization_sha256="\$\(printf '%s' "\$authorization_json" \| shasum -a 256/);
  assert.doesNotMatch(deployment, /authorization_sha256="\$\(shasum -a 256 "\$NORMAL_IMAGE_AUTHORIZATION_FILE"/);
  assert.equal((rotation.match(/state_sha256="\$\(printf '%s' "\$state_json" \| sha256sum/g) || []).length, 2);
});
