import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildBackendHealthRecoveryDispatch, canonicalWorkflowJsonInput, runCli } from "../aws/dispatch-production-backend-health-recovery.mjs";
import { buildLegacyBackendRecoveryCandidate } from "../aws/production-backend-health-recovery-contract.mjs";
import { imageAuthorizationSha256 } from "../aws/production-image-authorization.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const reused = makeCanonicalImageAuthorization({ sourceSha: "96a4be6f0edcd626285c6a1bd8062a4008175d25", imageReleaseSha: "594bab55f23ff8b2438c12b85b149ba0aebeed1e" });
const fresh = makeCanonicalImageAuthorization({ sourceSha: "94da9651eb9427603be87abe89f89111412755c9", imageReleaseSha: "94da9651eb9427603be87abe89f89111412755c9", impactImageReleaseSha: "29bf92a14d5e832575009bd76b16886feff62cbd" });
const currentTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const approval = (fixture) => ({ ticket: "ticket", approvedBy: "operator", approverRole: "production operator", reason: "missing image recovery", verificationRef: "verification", sourceSha: fixture.authorization.sourceSha, currentTaskDefinitionArn, recoveryImageDigest: fixture.authorization.backendDigest });
const input = (fixture) => ({
  sourceSha: fixture.authorization.sourceSha,
  currentTaskDefinitionArn,
  recoveryImageDigest: fixture.authorization.backendDigest,
  service: "mscqr-backend-servi-euw2",
  releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  imageAuthorizationBytes: Buffer.from(JSON.stringify(fixture.authorization)),
  imageValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence },
  approvalBytes: Buffer.from(JSON.stringify(approval(fixture))),
});
const fields = (dispatch) => Object.fromEntries(dispatch.args.flatMap((value, index) => value === "-f" ? [dispatch.args[index + 1].split(/=(.*)/s).slice(0, 2)] : []));
const rehash = (authorization) => {
  authorization.evidenceSha256 = imageAuthorizationSha256(authorization);
  authorization.authorizationSha256 = authorization.evidenceSha256;
  return authorization;
};
const cliArguments = (imagePath, approvalPath) => [
  "--source-sha", reused.authorization.sourceSha, "--current-task-definition", currentTaskDefinitionArn,
  "--recovery-image-digest", reused.authorization.backendDigest, "--service", "mscqr-backend-servi-euw2",
  "--release-mode", "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  "--image-authorization", imagePath, "--approval", approvalPath,
];

test("workflow JSON transport owns serialization and hash bytes", () => {
  const image = reused.authorization;
  const variants = [JSON.stringify(image), `${JSON.stringify(image)}\n`, JSON.stringify(image, null, 2), `${JSON.stringify(image, null, 2)}\n`];
  const results = variants.map((value) => canonicalWorkflowJsonInput(Buffer.from(value), "fixture"));
  for (const result of results) assert.equal(result.sha256, hash(result.value));
  assert.equal(new Set(results.map(({ value }) => value)).size, 1);
  assert.notEqual(hash(Buffer.from(`${JSON.stringify(image, null, 2)}\n`)), hash(JSON.stringify(image, null, 2)), "run 32567632721 failure construction must remain reproducible");
});

test("fresh and authenticated reused images dispatch with byte-identical hashes", () => {
  for (const fixture of [fresh, reused]) {
    const dispatch = buildBackendHealthRecoveryDispatch(input(fixture));
    const sent = fields(dispatch);
    assert.equal(hash(sent.backend_recovery_image_authorization_json), sent.backend_recovery_image_authorization_sha256);
    assert.equal(hash(sent.backend_recovery_approval_json), sent.backend_recovery_approval_sha256);
    assert.deepEqual(JSON.parse(sent.backend_recovery_image_authorization_json), fixture.authorization);
  }
  assert.equal(fresh.authorization.sourceSha, fresh.authorization.imageReleaseSha);
  assert.notEqual(reused.authorization.sourceSha, reused.authorization.imageReleaseSha);
  assert.equal(reused.authorization.authorizationPath, "IMAGE_REUSE");
});

test("reused image keeps its authenticated release identity in the recovery task definition", () => {
  const current = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
  const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: reused.authorization.backendDigest, imageReleaseSha: reused.authorization.imageReleaseSha });
  const environment = new Map(candidate.containerDefinitions.find(({ name }) => name === "backend").environment.map(({ name, value }) => [name, value]));
  assert.equal(environment.get("GIT_SHA"), reused.authorization.imageReleaseSha);
  assert.equal(environment.get("RELEASE_GIT_SHA"), reused.authorization.imageReleaseSha);
});

test("recovery CLI passes the builder's exact JSON and hashes to gh", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-dispatch-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, "image.json");
  const approvalPath = path.join(directory, "approval.json");
  fs.writeFileSync(imagePath, `${JSON.stringify(reused.authorization, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(approvalPath, `${JSON.stringify(approval(reused), null, 2)}\n`, { mode: 0o600 });
  let invocation;
  const result = runCli(cliArguments(imagePath, approvalPath), { protectedMain: () => {}, imageValidation: input(reused).imageValidation, run: (command, args) => { invocation = { command, args }; } });
  const sent = fields(invocation);
  assert.equal(invocation.command, "gh");
  assert.equal(hash(sent.backend_recovery_image_authorization_json), sent.backend_recovery_image_authorization_sha256);
  assert.equal(hash(sent.backend_recovery_approval_json), sent.backend_recovery_approval_sha256);
  assert.equal(result.imageTransportSha256, sent.backend_recovery_image_authorization_sha256);
  assert.equal(result.approvalTransportSha256, sent.backend_recovery_approval_sha256);
  assert.equal(result.dispatchCount, 1);
});

test("recovery CLI anchors private evidence to the worktree regardless of caller cwd", { concurrency: false }, (context) => {
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-dispatch-private-"));
  const inside = fs.mkdtempSync(path.join(repositoryRoot, ".recovery-dispatch-private-"));
  context.after(() => { fs.rmSync(external, { recursive: true, force: true }); fs.rmSync(inside, { recursive: true, force: true }); });
  const imagePath = path.join(external, "image.json");
  const approvalPath = path.join(external, "approval.json");
  const insideImage = path.join(inside, "image.json");
  const insideApproval = path.join(inside, "approval.json");
  for (const [file, value] of [[imagePath, reused.authorization], [approvalPath, approval(reused)], [insideImage, reused.authorization], [insideApproval, approval(reused)]]) {
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  }
  const originalCwd = process.cwd();
  const invoke = (cwd, image = imagePath, approvalFile = approvalPath) => {
    process.chdir(cwd);
    try {
      return runCli(cliArguments(image, approvalFile), {
        protectedMain: ({ cwd: protectedCwd }) => assert.equal(protectedCwd, repositoryRoot),
        imageValidation: input(reused).imageValidation,
        run: () => {},
      });
    } finally { process.chdir(originalCwd); }
  };
  for (const cwd of [repositoryRoot, path.join(repositoryRoot, "scripts"), path.join(repositoryRoot, "backend"), path.join(repositoryRoot, "scripts/aws"), external]) {
    assert.equal(invoke(cwd).dispatchCount, 1);
  }
  assert.throws(() => invoke(repositoryRoot, insideImage), /must be outside the repository/);
  assert.throws(() => invoke(path.join(repositoryRoot, "scripts"), imagePath, insideApproval), /must be outside the repository/);
  assert.throws(() => invoke(path.join(repositoryRoot, "backend"), insideImage), /must be outside the repository/);
  assert.throws(() => invoke(path.join(repositoryRoot, "scripts/aws"), path.join(repositoryRoot, "scripts", "..", path.basename(inside), "image.json")), /must be outside the repository/);

  const symlink = path.join(external, "image-link.json");
  fs.symlinkSync(imagePath, symlink);
  assert.throws(() => invoke(repositoryRoot, symlink), /regular non-symlink file/);
  fs.chmodSync(imagePath, 0o644);
  assert.throws(() => invoke(repositoryRoot), /mode 0600/);
  fs.chmodSync(imagePath, 0o600);
  assert.throws(() => invoke(repositoryRoot, path.join(external, "missing.json")), /regular non-symlink file/);
});

test("unauthorized reuse, forged envelopes, stale source, and wrong digest fail closed", () => {
  const valid = input(reused);
  const unauthorized = structuredClone(reused.authorization);
  unauthorized.imageReuseEvidence = { ...unauthorized.imageReuseEvidence, imageReuseCompatible: false };
  unauthorized.imageReuseEvidenceSha256 = canonicalSha256(unauthorized.imageReuseEvidence);
  rehash(unauthorized);
  const wrongRelease = rehash({ ...structuredClone(reused.authorization), imageReleaseSha: "a".repeat(40) });
  for (const changed of [
    { imageAuthorizationBytes: Buffer.from(JSON.stringify(unauthorized)) },
    { imageAuthorizationBytes: Buffer.from(JSON.stringify(wrongRelease)) },
    { imageValidation: { now: reused.now, verifyImageEvidence: () => false } },
    { sourceSha: "e".repeat(40) },
    { recoveryImageDigest: `sha256:${"5".repeat(64)}` },
    { currentTaskDefinitionArn: currentTaskDefinitionArn.replace(":47", ":48") },
    { service: "wrong" },
    { releaseMode: "normal" },
  ]) assert.throws(() => buildBackendHealthRecoveryDispatch({ ...valid, ...changed }), /authorization|different|differs|invalid|source|hash|impact|evidence/);
  assert.throws(() => canonicalWorkflowJsonInput(Buffer.from("not-json")), /valid JSON/);
});

test("adjacent normal and rotation dispatches hash the values they transport", () => {
  const deployment = fs.readFileSync("documents/ops/deployment-runbook.md", "utf8");
  const rotation = fs.readFileSync("documents/SECURITY_KEY_ROTATION_RUNBOOK.md", "utf8");
  assert.match(deployment, /authorization_sha256="\$\(printf '%s' "\$authorization_json" \| shasum -a 256/);
  assert.doesNotMatch(deployment, /authorization_sha256="\$\(shasum -a 256 "\$NORMAL_IMAGE_AUTHORIZATION_FILE"/);
  assert.equal((rotation.match(/state_sha256="\$\(printf '%s' "\$state_json" \| sha256sum/g) || []).length, 2);
});
