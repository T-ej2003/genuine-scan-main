import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_BOOTSTRAP_ROOT, appOnlyBootstrapTerraform, verifyAppOnlyBootstrapSource, assertAppOnlyBootstrapPlan } from "./generate-production-app-only-infrastructure.mjs";
import { createAppOnlyBootstrapPreparation, assertAppOnlyBootstrapInputs, assertAppOnlyBootstrapAbsent, appOnlyBytesSha256 } from "./production-app-only-bootstrap-contract.mjs";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { assertAppOnlyAuthorization } from "./production-app-only-authorization.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference, createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileExclusive, writeStageBPrivateFileAtomicExclusive, ensureStageBPrivateDirectory } from "./stage-b-artifact-contract.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export function parseAppOnlyBootstrapArgs(args) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["mode", "source-sha", "admin-profile", "preparation", "preparation-sha256", "plan", "plan-json", "authorization-reference"].map((name) => [name, { type: "string" }])) });
  assert.ok(["prepare", "execute"].includes(values.mode)); assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/);
  assert.match(values["admin-profile"] || "", /^[A-Za-z0-9_-]{1,80}$/);
  const files = ["preparation", "preparation-sha256", "plan", "plan-json", "authorization-reference"];
  if (values.mode === "prepare") for (const name of files) assert.equal(values[name], undefined);
  else {
    for (const name of ["preparation", "plan", "plan-json"]) assert.ok(path.isAbsolute(values[name] || ""));
    assert.match(values["preparation-sha256"] || "", /^[a-f0-9]{64}$/);
    values.reference = parseAppOnlyArtifactReference(values["authorization-reference"]);
    assert.equal(values.reference.sourceSha, values["source-sha"]);
  }
  return values;
}

export function verifyAppOnlyBootstrapReadback(run) {
  const source = appOnlyBootstrapTerraform();
  const aws = (args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
  const equalPolicy = (actual, expected) => assert.equal(canonicalJson(normalizeIamPolicyDocument(actual)), canonicalJson(JSON.parse(expected)));
  for (const policy of Object.values(source.resource.aws_iam_policy)) {
    const arn = `arn:aws:iam::${APP_ONLY.account}:policy/${policy.name}`;
    const metadata = aws(["iam", "get-policy", "--policy-arn", arn]).Policy;
    assert.equal(metadata?.Arn, arn); assert.equal(metadata.PolicyName, policy.name); assert.equal(metadata.Path, "/");
    assert.equal(metadata.DefaultVersionId, "v1"); assert.equal(metadata.AttachmentCount, 0);
    assert.equal((metadata.Tags || []).length, 0);
    const versions = aws(["iam", "list-policy-versions", "--policy-arn", arn]);
    assert.ok(!versions.IsTruncated); assert.equal(versions.Versions?.length, 1);
    assert.equal(versions.Versions[0].VersionId, "v1"); assert.equal(versions.Versions[0].IsDefaultVersion, true);
    const value = aws(["iam", "get-policy-version", "--policy-arn", arn, "--version-id", "v1"]).PolicyVersion;
    assert.equal(value?.VersionId, "v1"); assert.equal(value.IsDefaultVersion, true); equalPolicy(value.Document, policy.policy);
  }
  for (const [name, spec] of Object.entries(source.resource.aws_iam_role)) {
    const role = aws(["iam", "get-role", "--role-name", spec.name]).Role;
    assert.equal(role?.Arn, `arn:aws:iam::${APP_ONLY.account}:role/${spec.name}`); assert.equal(role.RoleName, spec.name);
    assert.equal(role.Path, "/"); assert.equal(role.MaxSessionDuration, 3600); assert.equal((role.Tags || []).length, 0);
    assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, spec.permissions_boundary);
    if (spec.permissions_boundary) assert.equal(role.PermissionsBoundary.PermissionsBoundaryType, "Policy");
    equalPolicy(role.AssumeRolePolicyDocument, spec.assume_role_policy);
    const attached = aws(["iam", "list-attached-role-policies", "--role-name", spec.name]);
    assert.ok(!attached.IsTruncated); assert.deepEqual(attached.AttachedPolicies, []);
    const inline = aws(["iam", "list-role-policies", "--role-name", spec.name]);
    const desired = source.resource.aws_iam_role_policy[name];
    assert.ok(!inline.IsTruncated); assert.deepEqual(inline.PolicyNames, [desired.name]);
    const observed = aws(["iam", "get-role-policy", "--role-name", spec.name, "--policy-name", desired.name]);
    assert.equal(observed.RoleName, spec.name); assert.equal(observed.PolicyName, desired.name); equalPolicy(observed.PolicyDocument, desired.policy);
  }
  return { verified: true, resources: 6 };
}

async function main() {
  const options = parseAppOnlyBootstrapArgs(process.argv.slice(2));
  const sourceSha = options["source-sha"], profile = options["admin-profile"];
  const githubRun = createProductionGithubCommandRunner();
  const get = (endpoint) => JSON.parse(githubRun("gh", ["api", endpoint]));
  const source = () => {
    assertProtectedCheckout({ sourceSha, repositoryRoot }); verifyAppOnlyBootstrapSource(repositoryRoot);
    const main = get("repos/T-ej2003/genuine-scan-main/branches/main");
    assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  };
  source();
  const credentialSource = PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  const run = createProductionAwsCommandRunner({ credentialSource, profile,
    exec: (command, args, opts) => execFileSync(command, args, { ...opts, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-bootstrap-")); fs.chmodSync(directory, 0o700);
  const write = (name, bytes) => writeStageBPrivateFileExclusive({ repositoryRoot, filePath: path.join(directory, name), bytes });
  for (const name of ["main.tf.json", ".terraform.lock.hcl"]) write(name, fs.readFileSync(path.join(repositoryRoot, APP_ONLY_BOOTSTRAP_ROOT, name)));
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource, profile }), TF_IN_AUTOMATION: "1", CHECKPOINT_DISABLE: "1" };
  const terraform = (args) => execFileSync("terraform", [`-chdir=${directory}`, ...args], {
    env, encoding: "utf8", timeout: 10 * 60 * 1000, maxBuffer: 16 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(JSON.parse(terraform(["version", "-json"])).terraform_version, "1.15.8");
  terraform(["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"]);
  if (options.mode === "prepare") {
    assertAppOnlyBootstrapAbsent(run);
    terraform(["plan", "-input=false", "-lock=true", "-parallelism=1", "-out=bootstrap.tfplan", "-no-color"]);
    fs.chmodSync(path.join(directory, "bootstrap.tfplan"), 0o600);
    const planBytes = readStageBPrivateFileBytes({ repositoryRoot, filePath: path.join(directory, "bootstrap.tfplan") }).bytes;
    const planJsonBytes = Buffer.from(terraform(["show", "-json", "bootstrap.tfplan"]));
    assertAppOnlyBootstrapPlan(JSON.parse(planJsonBytes)); assertAppOnlyBootstrapAbsent(run); source();
    const preparation = createAppOnlyBootstrapPreparation({ repositoryRoot, sourceSha, generatedAt: new Date().toISOString(), callerArn: caller.Arn,
      planSha256: appOnlyBytesSha256(planBytes), planJsonSha256: appOnlyBytesSha256(planJsonBytes) });
    write("bootstrap-plan.json", planJsonBytes);
    const file = write("bootstrap-preparation.json", Buffer.from(`${JSON.stringify(preparation)}\n`));
    process.stdout.write(`${JSON.stringify({ directory, preparationPath: file.path, preparationFileSha256: file.sha256, preparation })}\n`);
    return;
  }
  for (const filePath of [options.preparation, options.plan, options["plan-json"]])
    ensureStageBPrivateDirectory({ repositoryRoot, directory: path.dirname(filePath) });
  const prepared = readStageBPrivateFileBytes({ repositoryRoot, filePath: options.preparation });
  assert.equal(prepared.sha256, options["preparation-sha256"]);
  const preparation = JSON.parse(prepared.bytes);
  const planBytes = readStageBPrivateFileBytes({ repositoryRoot, filePath: options.plan }).bytes;
  const planJsonBytes = readStageBPrivateFileBytes({ repositoryRoot, filePath: options["plan-json"] }).bytes;
  assertAppOnlyBootstrapInputs({ preparation, planBytes, planJsonBytes, repositoryRoot, sourceSha });
  assert.equal(caller.Arn, preparation.callerArn);
  write("bootstrap.tfplan", planBytes);
  // Inspect the SAME authenticated binary, never trust a separately supplied JSON.
  assert.equal(appOnlyBytesSha256(Buffer.from(terraform(["show", "-json", "bootstrap.tfplan"]))), preparation.planJsonSha256);
  const artifact = downloadAppOnlyArtifact({ kind: "bootstrapAuthorization", reference: options.reference, repositoryRoot, githubRun });
  const approved = JSON.parse(artifact.bytes);
  assert.deepEqual(approved.preparation, preparation);
  const approval = approved.approval;
  const context = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: artifact.run.repository.full_name, GITHUB_SHA: artifact.run.head_sha,
    GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: artifact.run.event, GITHUB_RUN_ID: String(artifact.run.id),
    GITHUB_RUN_ATTEMPT: String(artifact.run.run_attempt), GITHUB_WORKFLOW_REF: `${artifact.run.repository.full_name}/${artifact.run.path}@refs/heads/main`, GITHUB_ACTOR: artifact.run.actor.login };
  const authenticate = () => {
    source(); assertAppOnlyAuthorization({ authorization: approved.authorization, phase: "BOOTSTRAP", preparation, approval, env: context });
    const environmentConfig = get("repos/T-ej2003/genuine-scan-main/environments/production");
    assert.deepEqual(createProductionEnvironmentApprovalEvidence({ ...approval, environmentConfig }), approval, "Production protection rules changed");
    assertAppOnlyBootstrapAbsent(run);
    assert.equal(readStageBPrivateFileBytes({ repositoryRoot, filePath: path.join(directory, "bootstrap.tfplan") }).sha256, preparation.planSha256);
  };
  authenticate();
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: preparation.preparationSha256 });
  process.stdout.write(`${JSON.stringify({ executionDirectory: directory, journalDirectory: journal.directory })}\n`);
  // An authenticated-content-derived, exclusive host claim also rejects copies
  // of the preparation at another path. Never remove/reuse a failed claim.
  // AWS's exact-name absence checks additionally reject existing/partial installs.
  const claim = path.join(os.tmpdir(), `mscqr-app-only-bootstrap-consumed-${preparation.preparationSha256}`);
  fs.mkdirSync(claim, { mode: 0o700 });
  ensureStageBPrivateDirectory({ repositoryRoot, directory: claim });
  writeStageBPrivateFileAtomicExclusive({ repositoryRoot, filePath: path.join(claim, "execution-intent.json"),
    bytes: Buffer.from(`${JSON.stringify({ preparationSha256: preparation.preparationSha256, authorizationSha256: approved.authorization.authorizationSha256, directory })}\n`) });
  await journal.writeEvidence({ status: "BOOTSTRAP_APPLY_INTENT" }); authenticate();
  let returned = false;
  try {
    terraform(["apply", "-input=false", "-lock=true", "-parallelism=1", "-no-color", "bootstrap.tfplan"]); returned = true;
    await journal.writeEvidence({ status: "BOOTSTRAP_APPLY_RETURNED" });
    const state = JSON.parse(terraform(["show", "-json"]));
    assert.equal((state.values?.root_module?.child_modules || []).length, 0);
    assert.deepEqual((state.values?.root_module?.resources || []).map((r) => r.address).sort(), preparation.exactAddresses);
    const readback = verifyAppOnlyBootstrapReadback(run);
    await journal.writeEvidence({ status: "BOOTSTRAP_VERIFIED", readback });
    process.stdout.write(`${JSON.stringify({ status: "BOOTSTRAP_VERIFIED", directory, readback })}\n`);
  } catch (cause) {
    await journal.writeEvidence({ status: returned ? "BOOTSTRAP_APPLY_COMPLETED_POSTVERIFY_FAILED" : "BOOTSTRAP_APPLY_OUTCOME_REQUIRES_READBACK" });
    throw new Error("Preserve bootstrap local state and journal; never reapply automatically", { cause });
  }
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only bootstrap stopped; preserve all printed private paths and do not retry an ambiguous apply.\n"); process.exitCode = 1; });
