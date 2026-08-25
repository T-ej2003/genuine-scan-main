import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { buildBackendHealthRecoveryDispatch, canonicalWorkflowJsonInput, measureWorkflowDispatchInputs, parseBackendHealthRecoveryDispatchBundle, runCli, WORKFLOW_DISPATCH_INTERNAL_BUDGET, WORKFLOW_DISPATCH_PLATFORM_LIMIT } from "../aws/dispatch-production-backend-health-recovery.mjs";
import { extractProductionBackendRecoveryDispatchBundle } from "../aws/extract-production-backend-recovery-dispatch-bundle.mjs";
import { createFailedRecoveryEvidenceReference } from "../aws/production-backend-failed-recovery-evidence-reference.mjs";
import { buildLegacyBackendRecoveryCandidate } from "../aws/production-backend-health-recovery-contract.mjs";
import { imageAuthorizationSha256 } from "../aws/production-image-authorization.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const reused = makeCanonicalImageAuthorization({ sourceSha: "96a4be6f0edcd626285c6a1bd8062a4008175d25", imageReleaseSha: "594bab55f23ff8b2438c12b85b149ba0aebeed1e" });
const fresh = makeCanonicalImageAuthorization({ sourceSha: "94da9651eb9427603be87abe89f89111412755c9", imageReleaseSha: "94da9651eb9427603be87abe89f89111412755c9", impactImageReleaseSha: "29bf92a14d5e832575009bd76b16886feff62cbd" });
const currentTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const runtimeConsumabilitySha256 = "8".repeat(64);
const runtimeConsumability = { evidence: { evidenceSha256: runtimeConsumabilitySha256 } };
const failedRecoveryEvidenceReference = null;
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const artifactSigningBindings = {
  ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-key-current-AbCd12",
  ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/active-key-version-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEYS_JSON: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-keys-json-AbCd12",
};
const approval = (fixture) => ({ ticket: "ticket", approvedBy: "operator", approverRole: "production operator", reason: "missing image recovery", verificationRef: "verification", sourceSha: fixture.authorization.sourceSha, currentTaskDefinitionArn, recoveryImageDigest: fixture.authorization.backendDigest, runtimeConsumabilitySha256 });
const input = (fixture) => ({
  sourceSha: fixture.authorization.sourceSha,
  currentTaskDefinitionArn,
  recoveryImageDigest: fixture.authorization.backendDigest,
  service: "mscqr-backend-servi-euw2",
  releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  imageAuthorizationBytes: Buffer.from(JSON.stringify(fixture.authorization)),
  imageValidation: { now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence },
  approvalBytes: Buffer.from(JSON.stringify(approval(fixture))),
  runtimeConsumabilityBytes: Buffer.from(JSON.stringify(runtimeConsumability)),
  failedRecoveryEvidenceReferenceBytes: Buffer.from(JSON.stringify(failedRecoveryEvidenceReference)),
});
const fields = (dispatch) => Object.fromEntries(dispatch.args.flatMap((value, index) => value === "-f" ? [dispatch.args[index + 1].split(/=(.*)/s).slice(0, 2)] : []));
const bundleFrom = (sent) => parseBackendHealthRecoveryDispatchBundle(Buffer.from(sent.backend_recovery_evidence_bundle_json), sent.backend_recovery_evidence_bundle_sha256);
const rehash = (authorization) => {
  authorization.evidenceSha256 = imageAuthorizationSha256(authorization);
  authorization.authorizationSha256 = authorization.evidenceSha256;
  return authorization;
};
const cliArguments = (imagePath, approvalPath, runtimePath, failedReferencePath) => [
  "--source-sha", reused.authorization.sourceSha, "--current-task-definition", currentTaskDefinitionArn,
  "--recovery-image-digest", reused.authorization.backendDigest, "--service", "mscqr-backend-servi-euw2",
  "--release-mode", "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
  "--image-authorization", imagePath, "--approval", approvalPath, "--runtime-consumability", runtimePath, "--failed-recovery-evidence-reference", failedReferencePath,
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
    assert.equal(hash(sent.backend_recovery_evidence_bundle_json), sent.backend_recovery_evidence_bundle_sha256);
    const bundle = bundleFrom(sent);
    for (const component of Object.values(bundle.components)) assert.equal(hash(component.value), component.sha256);
    assert.deepEqual(JSON.parse(bundle.components.imageAuthorization.value), fixture.authorization);
  }
  assert.equal(fresh.authorization.sourceSha, fresh.authorization.imageReleaseSha);
  assert.notEqual(reused.authorization.sourceSha, reused.authorization.imageReleaseSha);
  assert.equal(reused.authorization.authorizationPath, "IMAGE_REUSE");
});

test("canonical recovery bundle binds every component and transaction field", () => {
  const sent = fields(buildBackendHealthRecoveryDispatch(input(reused)));
  const bytes = Buffer.from(sent.backend_recovery_evidence_bundle_json);
  const parsed = bundleFrom(sent);
  assert.equal(parsed.value.sourceSha, reused.authorization.sourceSha);
  assert.throws(() => parseBackendHealthRecoveryDispatchBundle(bytes, "0".repeat(64)), /do not match/);
  assert.throws(() => parseBackendHealthRecoveryDispatchBundle(bytes, sent.backend_recovery_evidence_bundle_sha256, { recoveryImageDigest: `sha256:${"0".repeat(64)}` }), /binding differs/);
  const tampered = JSON.parse(bytes);
  tampered.components.approval.json = `${tampered.components.approval.json} `;
  const tamperedBytes = Buffer.from(JSON.stringify(tampered));
  assert.throws(() => parseBackendHealthRecoveryDispatchBundle(tamperedBytes, hash(tamperedBytes)), /component is invalid/);
});

test("workflow extractor writes the bundle's exact authenticated component bytes", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-bundle-extract-"));
  fs.chmodSync(directory, 0o700);
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const dispatch = buildBackendHealthRecoveryDispatch(input(reused));
  const bundleFile = path.join(directory, "bundle.json");
  fs.writeFileSync(bundleFile, dispatch.bundle.bytes, { mode: 0o600 });
  const result = extractProductionBackendRecoveryDispatchBundle({ bundleFile, bundleSha256: dispatch.bundle.sha256, outputDirectory: directory, expected: { sourceSha: input(reused).sourceSha, currentTaskDefinitionArn, recoveryImageDigest: input(reused).recoveryImageDigest, service: input(reused).service, releaseMode: input(reused).releaseMode } });
  for (const [name, component] of Object.entries(result.manifest.components)) assert.equal(hash(fs.readFileSync(component.file)), dispatch[{ imageAuthorization: "image", approval: "approval", runtimeConsumability: "runtime", failedRecoveryEvidenceReference: "failed" }[name]].sha256);
  assert.throws(() => extractProductionBackendRecoveryDispatchBundle({ bundleFile, bundleSha256: dispatch.bundle.sha256, outputDirectory: directory, expected: { sourceSha: "0".repeat(40) } }), /binding differs/);
});

test("stalled rollback dispatch binds the exact deployment, current revision, and target digest", () => {
  const stalled = {
    ...approval(reused),
    rollbackDeploymentArn: "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/deployment-N",
    rollbackTargetTaskDefinitionArn: currentTaskDefinitionArn,
    rollbackTargetDigest: `sha256:${"b".repeat(64)}`,
  };
  assert.doesNotThrow(() => buildBackendHealthRecoveryDispatch({ ...input(reused), approvalBytes: Buffer.from(JSON.stringify(stalled)) }));
  for (const changed of [
    { rollbackDeploymentArn: stalled.rollbackDeploymentArn.replace("mscqr-backend-servi-euw2", "other") },
    { rollbackTargetTaskDefinitionArn: currentTaskDefinitionArn.replace(":47", ":48") },
    { rollbackTargetDigest: "sha256:short" },
  ]) assert.throws(() => buildBackendHealthRecoveryDispatch({ ...input(reused), approvalBytes: Buffer.from(JSON.stringify({ ...stalled, ...changed })) }), /rollback approval identity/);
});

test("reused image keeps its authenticated release identity in the recovery task definition", () => {
  const current = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
  const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: reused.authorization.backendDigest, imageReleaseSha: reused.authorization.imageReleaseSha, artifactSigningBindings });
  const environment = new Map(candidate.containerDefinitions.find(({ name }) => name === "backend").environment.map(({ name, value }) => [name, value]));
  assert.equal(environment.get("GIT_SHA"), reused.authorization.imageReleaseSha);
  assert.equal(environment.get("RELEASE_GIT_SHA"), reused.authorization.imageReleaseSha);
});

test("recovery CLI passes the builder's exact JSON and hashes to gh", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-dispatch-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, "image.json");
  const approvalPath = path.join(directory, "approval.json");
  const runtimePath = path.join(directory, "runtime.json");
  const failedPath = path.join(directory, "failed.json");
  fs.writeFileSync(imagePath, `${JSON.stringify(reused.authorization, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(approvalPath, `${JSON.stringify(approval(reused), null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(runtimePath, `${JSON.stringify(runtimeConsumability, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(failedPath, "null\n", { mode: 0o600 });
  let invocation;
  const result = runCli(cliArguments(imagePath, approvalPath, runtimePath, failedPath), { protectedMain: () => {}, imageValidation: input(reused).imageValidation, run: (command, args) => { invocation = { command, args }; } });
  const sent = fields(invocation);
  assert.equal(invocation.command, "gh");
  const bundle = bundleFrom(sent);
  assert.equal(result.bundleTransportSha256, sent.backend_recovery_evidence_bundle_sha256);
  assert.equal(result.imageTransportSha256, bundle.components.imageAuthorization.sha256);
  assert.equal(result.approvalTransportSha256, bundle.components.approval.sha256);
  assert.equal(result.runtimeTransportSha256, bundle.components.runtimeConsumability.sha256);
  assert.equal(result.dispatchCount, 1);
});

test("workflow dispatch measures the actual complete payload against a conservative budget", () => {
  const dispatch = buildBackendHealthRecoveryDispatch(input(reused));
  assert.ok(dispatch.payload.characters < WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.ok(dispatch.payload.bytes < WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.ok(WORKFLOW_DISPATCH_INTERNAL_BUDGET < WORKFLOW_DISPATCH_PLATFORM_LIMIT);
  assert.throws(() => measureWorkflowDispatchInputs({ exact: "x".repeat(WORKFLOW_DISPATCH_INTERNAL_BUDGET) }), /internal budget/);
});

test("accumulated historical evidence never enters the bounded workflow dispatch payload", () => {
  const evidenceBytes = Buffer.from(JSON.stringify({ envelopeSha256: "e".repeat(64), history: "x".repeat(1_000_000) }));
  const evidenceHash = hash(evidenceBytes); const envelopeSha256 = "e".repeat(64);
  const asset = { id: 2, name: `backend-failed-recovery-evidence-${envelopeSha256}.json`, state: "uploaded", size: evidenceBytes.length, digest: `sha256:${evidenceHash}` };
  const release = { id: 1, immutable: true, draft: false, tag_name: `mscqr-backend-failed-recovery-evidence-${envelopeSha256}`, target_commitish: reused.authorization.sourceSha, assets: [asset] };
  const reference = createFailedRecoveryEvidenceReference({ sourceSha: reused.authorization.sourceSha, evidenceBytes, release, asset });
  const boundApproval = { ...approval(reused), failedRecoveryEvidenceSha256: envelopeSha256, failedRecoveryEvidenceReferenceSha256: reference.referenceSha256 };
  const dispatch = buildBackendHealthRecoveryDispatch({ ...input(reused), approvalBytes: Buffer.from(JSON.stringify(boundApproval)), failedRecoveryEvidenceReferenceBytes: Buffer.from(JSON.stringify(reference)) });
  assert.ok(dispatch.payload.characters < WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.doesNotMatch(dispatch.bundle.value, /"history"/);
  assert.equal(JSON.parse(dispatch.failed.value).assetSize, evidenceBytes.length);
});

test("recovery CLI anchors private evidence to the worktree regardless of caller cwd", { concurrency: false }, (context) => {
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "recovery-dispatch-private-"));
  const inside = fs.mkdtempSync(path.join(repositoryRoot, ".recovery-dispatch-private-"));
  context.after(() => { fs.rmSync(external, { recursive: true, force: true }); fs.rmSync(inside, { recursive: true, force: true }); });
  const imagePath = path.join(external, "image.json");
  const approvalPath = path.join(external, "approval.json");
  const runtimePath = path.join(external, "runtime.json");
  const failedPath = path.join(external, "failed.json");
  const insideImage = path.join(inside, "image.json");
  const insideApproval = path.join(inside, "approval.json");
  const insideRuntime = path.join(inside, "runtime.json");
  const insideFailed = path.join(inside, "failed.json");
  for (const [file, value] of [[imagePath, reused.authorization], [approvalPath, approval(reused)], [runtimePath, runtimeConsumability], [failedPath, failedRecoveryEvidenceReference], [insideImage, reused.authorization], [insideApproval, approval(reused)], [insideRuntime, runtimeConsumability], [insideFailed, failedRecoveryEvidenceReference]]) {
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  }
  const originalCwd = process.cwd();
  const invoke = (cwd, image = imagePath, approvalFile = approvalPath, runtimeFile = runtimePath, failedFile = failedPath) => {
    process.chdir(cwd);
    try {
      return runCli(cliArguments(image, approvalFile, runtimeFile, failedFile), {
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
  assert.throws(() => invoke(path.join(repositoryRoot, "scripts"), imagePath, approvalPath, insideRuntime), /must be outside the repository/);
  assert.throws(() => invoke(path.join(repositoryRoot, "scripts"), imagePath, approvalPath, runtimePath, insideFailed), /must be outside the repository/);
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
