#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyCompatibilityReadPolicy, appOnlyVerifierBoundaryPolicy,
  appOnlyVerifierLauncherPolicy, appOnlyProductionOidcTrust } from "./production-app-only-policy.mjs";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalizeStageAProductionArtifactsPolicy } from "./production-stage-a-control-plane.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { createAppOnlyAuthorization, assertAppOnlyAuthorization } from "./production-app-only-authorization.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const roleArn = `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`;
const writerRole = "mscqr-production-initial-activation-policy-reconciler";
const policyHash = (value) => canonicalSha256(canonicalizeStageAProductionArtifactsPolicy(normalizeIamPolicyDocument(value)));
const oldBoundaryHash = policyHash(appOnlyVerifierBoundaryPolicy({ includeRotationSelectors: false }));
const desiredBoundary = appOnlyVerifierBoundaryPolicy();
const desiredBoundaryHash = policyHash(desiredBoundary);
const IAM_MUTATIONS = new Set(["create-policy-version", "set-default-policy-version", "put-role-policy"]);
export function createAppOnlyBoundaryAwsRunner({ exec = execFileSync, env = process.env } = {}) {
  return createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER,
    env, exec: (file, args, execution) => exec(file, args, { ...execution,
      env: args[0] === "iam" && IAM_MUTATIONS.has(args[1])
        ? { ...execution.env, AWS_MAX_ATTEMPTS: "1" } : execution.env }) });
}
const json = (run, args) => {
  const value = run([...args, "--output", "json", "--no-cli-pager"]);
  return typeof value === "string" ? JSON.parse(value) : value;
};
const inline = (arn, includeRotationSelectors) => arn
  ? appOnlyVerifierLauncherPolicy(arn, { includeRotationSelectors })
  : appOnlyCompatibilityReadPolicy({ includeRotationSelectors });

export const APP_ONLY_BOUNDARY_RECONCILIATION = Object.freeze({
  policyArn: APP_ONLY_PROVISIONING.verifierBoundaryArn,
  roleArn, writerRole,
  oldBoundaryHash, desiredBoundaryHash,
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/reconcile-production-app-only-verifier-boundary.yml@refs/heads/main",
});

export function readAppOnlyBoundaryState(run) {
  const policy = json(run, ["iam", "get-policy", "--policy-arn", APP_ONLY_BOUNDARY_RECONCILIATION.policyArn]).Policy;
  assert.equal(policy?.Arn, APP_ONLY_BOUNDARY_RECONCILIATION.policyArn);
  assert.equal(policy.PolicyName, "MSCQRProductionAppOnlyVerifierBoundary");
  assert.equal(policy.Path, "/");
  assert.match(policy.DefaultVersionId || "", /^v[1-9][0-9]*$/);
  const versions = json(run, ["iam", "list-policy-versions", "--policy-arn", policy.Arn]);
  assert.equal(versions.IsTruncated, false);
  assert.ok(Array.isArray(versions.Versions) && versions.Versions.length >= 1 && versions.Versions.length <= 5);
  assert.equal(versions.Versions.filter(({ IsDefaultVersion }) => IsDefaultVersion).length, 1);
  assert.ok(versions.Versions.some(({ VersionId, IsDefaultVersion }) => VersionId === policy.DefaultVersionId && IsDefaultVersion));
  const version = json(run, ["iam", "get-policy-version", "--policy-arn", policy.Arn, "--version-id", policy.DefaultVersionId]).PolicyVersion;
  assert.equal(version?.VersionId, policy.DefaultVersionId); assert.equal(version.IsDefaultVersion, true);
  const boundarySha256 = policyHash(version.Document);
  assert.ok([oldBoundaryHash, desiredBoundaryHash].includes(boundarySha256), "Verifier boundary default is not a reviewed predecessor or target");
  const entities = json(run, ["iam", "list-entities-for-policy", "--policy-arn", policy.Arn, "--policy-usage-filter", "PermissionsBoundary"]);
  assert.equal(entities.IsTruncated, false);
  assert.deepEqual(entities.PolicyUsers, []); assert.deepEqual(entities.PolicyGroups, []);
  assert.deepEqual(entities.PolicyRoles?.map(({ RoleName }) => RoleName), [APP_ONLY_VERIFIER.roleName]);
  assert.equal(policy.PermissionsBoundaryUsageCount, 1);
  const role = json(run, ["iam", "get-role", "--role-name", APP_ONLY_VERIFIER.roleName]).Role;
  assert.equal(role?.Arn, roleArn); assert.equal(role.RoleName, APP_ONLY_VERIFIER.roleName);
  assert.equal(role.Path, "/"); assert.equal(role.MaxSessionDuration, 3600);
  assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, policy.Arn);
  assert.equal(canonicalJson(normalizeIamPolicyDocument(role.AssumeRolePolicyDocument)), canonicalJson(appOnlyProductionOidcTrust(APP_ONLY_VERIFIER.roleName)));
  assert.ok(typeof role.RoleId === "string" && role.RoleId.length > 0);
  const attached = json(run, ["iam", "list-attached-role-policies", "--role-name", role.RoleName]);
  const names = json(run, ["iam", "list-role-policies", "--role-name", role.RoleName]);
  assert.equal(attached.IsTruncated, false); assert.deepEqual(attached.AttachedPolicies, []);
  assert.equal(names.IsTruncated, false); assert.deepEqual(names.PolicyNames, [APP_ONLY_PROVISIONING.inlinePolicyName]);
  const observed = json(run, ["iam", "get-role-policy", "--role-name", role.RoleName, "--policy-name", APP_ONLY_PROVISIONING.inlinePolicyName]);
  assert.equal(observed.RoleName, role.RoleName); assert.equal(observed.PolicyName, APP_ONLY_PROVISIONING.inlinePolicyName);
  const document = normalizeIamPolicyDocument(observed.PolicyDocument);
  const verifierArn = document.Statement?.find(({ Sid }) => Sid === "RunExactReadOnlyVerifier")?.Resource;
  if (verifierArn !== undefined) appOnlyVerifierLauncherPolicy(verifierArn);
  const inlineSha256 = policyHash(document);
  const oldInlineHash = policyHash(inline(verifierArn, false));
  const desiredInlineHash = policyHash(inline(verifierArn, true));
  assert.ok([oldInlineHash, desiredInlineHash].includes(inlineSha256), "Verifier inline policy is not a reviewed predecessor or target");
  assert.ok(boundarySha256 !== oldBoundaryHash || inlineSha256 !== desiredInlineHash,
    "Verifier inline policy advanced before its boundary");
  return Object.freeze({ policyArn: policy.Arn, defaultVersionId: policy.DefaultVersionId,
    versionIds: versions.Versions.map(({ VersionId }) => VersionId).sort(), boundarySha256,
    roleArn, roleId: role.RoleId, inlineSha256, verifierArn: verifierArn || null,
    status: boundarySha256 === desiredBoundaryHash && inlineSha256 === desiredInlineHash ? "CONVERGED"
      : boundarySha256 === desiredBoundaryHash ? "BOUNDARY_ONLY" : "PREDECESSOR" });
}

export function prepareAppOnlyBoundaryReconciliation({ sourceSha, run, now = Date.now() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const state = readAppOnlyBoundaryState(run);
  assert.deepEqual(readAppOnlyBoundaryState(run), state, "App-only IAM changed during preparation");
  assert.ok(state.status !== "PREDECESSOR" || state.versionIds.length < 5, "Managed policy version quota requires separate reviewed recovery");
  const body = { schemaVersion: 1, kind: "APP_ONLY_BOUNDARY_RECONCILIATION_PREPARATION", sourceSha,
    generatedAt: new Date(now).toISOString(), predecessor: state,
    desiredBoundarySha256: desiredBoundaryHash, desiredInlineSha256: policyHash(inline(state.verifierArn, true)) };
  return Object.freeze({ ...body, preparationSha256: canonicalSha256(body) });
}

export function assertAppOnlyBoundaryPreparation(value, { sourceSha, now = Date.now() } = {}) {
  const { preparationSha256, ...body } = value;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.deepEqual(Object.keys(body).sort(), ["schemaVersion", "kind", "sourceSha", "generatedAt", "predecessor", "desiredBoundarySha256", "desiredInlineSha256"].sort());
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_BOUNDARY_RECONCILIATION_PREPARATION");
  assert.equal(body.sourceSha, sourceSha); assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const age = now - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Boundary preparation expired");
  assert.equal(body.desiredBoundarySha256, desiredBoundaryHash);
  assert.equal(body.desiredInlineSha256, policyHash(inline(body.predecessor?.verifierArn, true)));
  const predecessor = body.predecessor;
  assert.deepEqual(Object.keys(predecessor || {}).sort(), ["policyArn", "defaultVersionId", "versionIds", "boundarySha256",
    "roleArn", "roleId", "inlineSha256", "verifierArn", "status"].sort());
  assert.equal(predecessor.policyArn, APP_ONLY_BOUNDARY_RECONCILIATION.policyArn);
  assert.equal(predecessor.roleArn, roleArn); assert.ok(typeof predecessor.roleId === "string" && predecessor.roleId.length > 0);
  assert.match(predecessor.defaultVersionId, /^v[1-9][0-9]*$/);
  assert.ok(Array.isArray(predecessor.versionIds) && predecessor.versionIds.length >= 1 && predecessor.versionIds.length <= 5);
  assert.deepEqual(predecessor.versionIds, [...new Set(predecessor.versionIds)].sort());
  assert.ok(predecessor.versionIds.every((id) => /^v[1-9][0-9]*$/.test(id)) && predecessor.versionIds.includes(predecessor.defaultVersionId));
  assert.ok(predecessor.verifierArn === null || typeof predecessor.verifierArn === "string");
  if (predecessor.verifierArn) appOnlyVerifierLauncherPolicy(predecessor.verifierArn);
  const oldInlineHash = policyHash(inline(predecessor.verifierArn, false));
  const expectedStatus = predecessor.boundarySha256 === oldBoundaryHash && predecessor.inlineSha256 === oldInlineHash ? "PREDECESSOR"
    : predecessor.boundarySha256 === desiredBoundaryHash && predecessor.inlineSha256 === oldInlineHash ? "BOUNDARY_ONLY"
      : predecessor.boundarySha256 === desiredBoundaryHash && predecessor.inlineSha256 === body.desiredInlineSha256 ? "CONVERGED" : null;
  assert.equal(predecessor.status, expectedStatus, "Boundary preparation has an unreviewed IAM state");
  assert.ok(predecessor.status !== "PREDECESSOR" || predecessor.versionIds.length < 5, "Managed policy version quota requires separate reviewed recovery");
  return value;
}

export async function executeAppOnlyBoundaryReconciliation({ preparation, authorization, approval, env, run,
  authenticate, writeEvidence, now = Date.now, sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms) }) {
  assertAppOnlyBoundaryPreparation(preparation, { sourceSha: env.GITHUB_SHA, now: now() });
  assertAppOnlyAuthorization({ authorization, phase: "BOUNDARY", preparation, approval, env, now: now() });
  assert.equal(typeof authenticate, "function"); assert.equal(typeof writeEvidence, "function");
  const caller = json(run, ["sts", "get-caller-identity"]);
  assert.equal(caller.Account, APP_ONLY.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${writerRole}/[^/]+$`));
  const fresh = async () => {
    assertAppOnlyBoundaryPreparation(preparation, { sourceSha: env.GITHUB_SHA, now: now() });
    assertAppOnlyAuthorization({ authorization, phase: "BOUNDARY", preparation, approval, env, now: now() });
    await authenticate();
  };
  await fresh();
  let state = readAppOnlyBoundaryState(run);
  const previous = preparation.predecessor;
  if (state.status === "CONVERGED") {
    assert.equal(previous.status, "CONVERGED", "Completed IAM cannot be adopted without its authenticated predecessor");
    assert.deepEqual(state, previous);
    await writeEvidence({ status: "BOUNDARY_ALREADY_CONVERGED", state });
    return { status: "CONVERGED", createPolicyVersionCount: 0, putRolePolicyCount: 0, state };
  }
  assert.deepEqual(state, previous, "IAM predecessor changed after protected approval");
  let createPolicyVersionCount = 0, putRolePolicyCount = 0;
  const readConverged = (expect) => {
    for (let attempt = 0; attempt < 6; attempt++) {
      const observed = readAppOnlyBoundaryState(run);
      if (expect(observed)) return observed;
      if (attempt < 5) sleep([100, 200, 400, 800, 1000][attempt]);
    }
    throw new Error("IAM write outcome requires authenticated readback; do not retry the mutation");
  };
  if (state.status === "PREDECESSOR") {
    assert.ok(state.versionIds.length < 5, "No automatic managed-policy version pruning");
    await fresh(); assert.deepEqual(readAppOnlyBoundaryState(run), state);
    await writeEvidence({ status: "BOUNDARY_VERSION_INTENT", predecessor: state });
    try {
      json(run, ["iam", "create-policy-version", "--policy-arn", state.policyArn,
        "--policy-document", JSON.stringify(desiredBoundary), "--set-as-default"]);
    } catch {
      // A lost AWS response may follow a successful write. Never issue it twice.
    }
    state = readConverged((observed) => observed.status === "BOUNDARY_ONLY"
      && observed.roleId === previous.roleId && observed.verifierArn === previous.verifierArn
      && observed.versionIds.length === previous.versionIds.length + 1
      && previous.versionIds.every((id) => observed.versionIds.includes(id))
      && observed.defaultVersionId !== previous.defaultVersionId);
    createPolicyVersionCount = 1;
    await writeEvidence({ status: "BOUNDARY_VERSION_VERIFIED", state });
  }
  assert.equal(state.status, "BOUNDARY_ONLY");
  assert.equal(state.roleId, previous.roleId); assert.equal(state.verifierArn, previous.verifierArn);
  await fresh(); assert.deepEqual(readAppOnlyBoundaryState(run), state);
  await writeEvidence({ status: "VERIFIER_INLINE_INTENT", predecessor: state });
  try {
    run(["iam", "put-role-policy", "--role-name", APP_ONLY_VERIFIER.roleName,
      "--policy-name", APP_ONLY_PROVISIONING.inlinePolicyName,
      "--policy-document", JSON.stringify(inline(state.verifierArn, true))]);
  } catch {
    // Exact readback below resolves ambiguous responses without replay.
  }
  state = readConverged((observed) => observed.status === "CONVERGED"
    && observed.defaultVersionId === state.defaultVersionId && observed.roleId === previous.roleId
    && observed.verifierArn === previous.verifierArn
    && canonicalJson(observed.versionIds) === canonicalJson(state.versionIds));
  putRolePolicyCount = 1;
  await writeEvidence({ status: "BOUNDARY_AND_INLINE_VERIFIED", state });
  return { status: "CONVERGED", createPolicyVersionCount, putRolePolicyCount, state };
}

async function main() {
  const [mode, sourceSha, preparationPath, preparationSha256, approvalPath, approvalSha256] = process.argv.slice(2);
  assert.ok(["prepare", "execute"].includes(mode)); assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(process.env.GITHUB_ACTIONS, "true"); assert.equal(process.env.GITHUB_SHA, sourceSha);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main"); assert.equal(process.env.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(process.env.GITHUB_WORKFLOW_REF, APP_ONLY_BOUNDARY_RECONCILIATION.workflowRef);
  const github = createProductionGithubCommandRunner();
  const source = () => {
    assertProtectedCheckout({ sourceSha, repositoryRoot: root });
    const main = JSON.parse(github("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  };
  source();
  const run = createAppOnlyBoundaryAwsRunner({
    exec: (command, args, options) => execFileSync(command, args, { ...options, timeout: 30000, maxBuffer: 4 * 1024 * 1024 }) });
  if (mode === "prepare") {
    assert.equal(preparationPath, undefined); assert.equal(approvalPath, undefined);
    const caller = json(run, ["sts", "get-caller-identity"]);
    assert.equal(caller.Account, APP_ONLY.account);
    assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${writerRole}/[^/]+$`));
    const preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run });
    source();
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-boundary-")); fs.chmodSync(directory, 0o700);
    const file = writeStageBPrivateFileExclusive({ repositoryRoot: root, filePath: path.join(directory, "preparation.json"), bytes: Buffer.from(`${JSON.stringify(preparation)}\n`) });
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `path=${file.path}\nsha256=${file.sha256}\n`);
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${JSON.stringify(preparation, null, 2)}\n`);
    return;
  }
  const preparation = readBoundStageBPrivateJson({ repositoryRoot: root, filePath: preparationPath, expectedSha256: preparationSha256 });
  const approval = readBoundStageBPrivateJson({ repositoryRoot: root, filePath: approvalPath, expectedSha256: approvalSha256 });
  assertAppOnlyBoundaryPreparation(preparation, { sourceSha });
  const authorization = createAppOnlyAuthorization({ phase: "BOUNDARY", preparation, approval, env: process.env });
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot: root, sourceSha, preparationSha256: preparation.preparationSha256 });
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `journal=${journal.directory}\n`);
  const result = await executeAppOnlyBoundaryReconciliation({ preparation, authorization, approval, env: process.env, run,
    authenticate: source, writeEvidence: journal.writeEvidence });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-boundary-result-")); fs.chmodSync(directory, 0o700);
  const file = writeStageBPrivateFileExclusive({ repositoryRoot: root, filePath: path.join(directory, "result.json"),
    bytes: Buffer.from(`${JSON.stringify({ preparation, approval, authorization, result })}\n`) });
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `path=${file.path}\n`);
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only boundary reconciliation stopped; authenticate durable journal and live IAM before any retry.\n"); process.exitCode = 1; });
