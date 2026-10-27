#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createAssumedRoleSessionEnvironment, createProductionAwsCredentialEnvironment, createProductionGithubCredentialEnvironment, productionAwsExecutable, productionGithubExecutable } from "./production-credential-source-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { digest as iamDigest } from "./component-iam-installation-contract.mjs";
import { readStageBProtectedMainCheckoutFromGitHub } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const account = "368992683803";
const roleName = "mscqr-production-web-image-publisher";
const boundaryName = "MSCQRProductionWebImagePublisherBoundary";
const releaseRoleName = "mscqr-production-release-deployer";
const publisherPolicyName = "MSCQRProductionWebImagePublisher";
const activationPolicyName = "MSCQRProductionFrontendActivation";
const auditPolicyName = "MSCQRProductionStageBNativeAudit";
const registryReadPolicyName = "MSCQRProductionWebEvidenceRegistryRead";
export const PHASE3_IAM_TRANSITION = Object.freeze({
  baselineSha: "8d0aa82ebf6b5fc70447c4133ea9c9e2aeae4f44",
  reviewedPrNumber: 721,
  reviewedHeadSha: "503460a5d7eeda19bf66f7782bbefe34f5524fdf",
  reviewedMergeSha: "0237d3f24afe5e3af5efbf26e5176edc8db81fc4",
  ticketId: "CHG-20261022-001",
  account,
  region: "eu-west-2",
  roleName: releaseRoleName,
  frontendPolicyName: activationPolicyName,
  auditPolicyName,
  frontendPredecessorSha256: "a43a0e5e579f91e6dd1da3005de72984becc28e86f9d316a87b8001164dc6352",
  frontendTargetSha256: "5f594748ad6f60ec039a2c2a1ef3744cb28c857732fdd427acb7baaad5a7c93d",
  auditTargetSha256: "741f2c3e88478ad23d287f58298cc1abbd3ef6f8459cd29aa20b1f202c5a5122",
});
const PHASE3_IAM_AUTHORIZATION_MAX_AGE_MS = 2 * 60 * 60 * 1000;
export const phase3IamAuthorizationMarker = (headSha, sourceSha) => {
  assert.match(headSha || "", /^[a-f0-9]{40}$/);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  return `MSCQR_PHASE3_IAM_SOLO_AUTH_V2:${iamDigest(PHASE3_IAM_TRANSITION)}:${headSha}:${sourceSha}`;
};
export function pinPhase3IamGitPath(env = process.env, fsOps = fs) {
  const stat = fsOps.statSync("/usr/bin/git");
  assert(stat.isFile() && (stat.mode & 0o111) && !(stat.mode & 0o022), "Unsafe production Git executable");
  for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_COUNT = "2";
  env.GIT_CONFIG_KEY_0 = "core.worktree";
  env.GIT_CONFIG_VALUE_0 = root;
  env.GIT_CONFIG_KEY_1 = "core.fsmonitor";
  env.GIT_CONFIG_VALUE_1 = "false";
  env.GIT_NO_REPLACE_OBJECTS = "1";
  env.PATH = "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin";
}
export function readPhase3IamProtectedSource({ sourceSha, cwd = root, execute = execFileSync,
  executable = productionGithubExecutable(), env = process.env, gitExecute = execFileSync,
  readCheckout = readStageBProtectedMainCheckoutFromGitHub }) {
  assert.equal(env.GIT_NO_REPLACE_OBJECTS, "1", "Git replacement objects must be disabled");
  assert.equal(gitExecute("/usr/bin/git", ["for-each-ref", "--format=%(refname)", "refs/replace"],
    { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(), "", "Git replacement refs are forbidden");
  const ghEnv = { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" };
  const currentHead = readCheckout({ cwd, expectedSourceSha: sourceSha, githubRun: (_command, args) =>
    execute(executable, ["api", "--hostname", "github.com", args[1]],
      { env: ghEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }) }).currentHead;
  assert.equal(currentHead, sourceSha, "IAM checkout differs from protected main");
  gitExecute("/usr/bin/git", ["merge-base", "--is-ancestor", PHASE3_IAM_TRANSITION.reviewedMergeSha, sourceSha],
    { cwd, env, stdio: "ignore" });
  return currentHead;
}
export function productionTerraformExecutable(fsOps = fs) {
  for (const candidate of ["/usr/bin/terraform", "/opt/homebrew/bin/terraform", "/usr/local/bin/terraform"]) {
    if (!fsOps.existsSync(candidate)) continue;
    const resolved = fsOps.realpathSync(candidate);
    assert(/^(?:\/usr\/bin\/terraform|\/(?:opt\/homebrew|usr\/local)\/Cellar\/terraform\/[0-9.]+\/bin\/terraform|\/usr\/local\/bin\/terraform)$/.test(resolved),
      "Terraform executable is outside canonical safelist");
    const stat = fsOps.statSync(resolved);
    assert(stat.isFile() && (stat.mode & 0o111) && !(stat.mode & 0o022), "Unsafe Terraform executable");
    return resolved;
  }
  throw new Error("No safelisted Terraform installation found");
}
export function readPhase3IamPlan({ planFile, execute = execFileSync, executable = productionTerraformExecutable(), env = process.env }) {
  const data = env.TF_DATA_DIR && path.isAbsolute(env.TF_DATA_DIR) && fs.statSync(env.TF_DATA_DIR);
  assert.ok(data?.isDirectory() && data.uid === process.getuid() && (data.mode & 0o077) === 0,
    "An initialized operator-owned private TF_DATA_DIR is required to verify the saved plan");
  assert.ok(path.isAbsolute(planFile), "Saved Terraform plan path must be absolute");
  const bytes = fs.readFileSync(planFile);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-phase3-iam-plan-"));
  try {
    fs.chmodSync(directory, 0o700);
    const captured = path.join(directory, "saved.tfplan");
    fs.writeFileSync(captured, bytes, { mode: 0o600, flag: "wx" });
    const plan = JSON.parse(execute(executable, ["-chdir=infra/aws/terraform/production-web-release", "show", "-json", captured],
      { cwd: root, env: { HOME: env.HOME, PATH: "/usr/bin:/bin", TF_DATA_DIR: env.TF_DATA_DIR,
        TF_WORKSPACE: "default", TF_CLI_CONFIG_FILE: "/dev/null" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
    return { plan, planSha256: createHash("sha256").update(bytes).digest("hex") };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
const POLICY_NO_OPS = Object.freeze({
  "aws_iam_policy.publisher_boundary": "no-op",
  "aws_iam_role.publisher": "no-op",
  "aws_iam_role_policy.publisher": "no-op",
});
export function assertPhase3IamPlan(plan, sourceSha, checkpoint) {
  assert.ok(plan && typeof plan === "object");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(plan.variables?.phase3_iam_source_sha?.value, sourceSha,
    "Saved IAM plan is not bound to current protected main");
  const changes = plan.resource_changes || [];
  const actions = Object.fromEntries(changes.map(({ address, change }) => [address, change?.actions?.join(",")]));
  assert.equal(Object.keys(actions).length, changes.length, "IAM plan repeats a resource address");
  assert.deepEqual(Object.fromEntries(Object.keys(POLICY_NO_OPS).map(address => [address, actions[address]])), POLICY_NO_OPS,
    "IAM plan changes an unrelated resource");
  assert.deepEqual(Object.keys(actions).sort(), [...Object.keys(POLICY_NO_OPS), "aws_iam_role_policy.frontend_activation", "aws_iam_role_policy.stage_b_native_audit"].sort(),
    "IAM plan contains an unapproved resource");
  const tuple = [actions["aws_iam_role_policy.frontend_activation"], actions["aws_iam_role_policy.stage_b_native_audit"]];
  assert.ok([["update", "create"], ["update", "no-op"], ["no-op", "create"], ["no-op", "no-op"]].some(expected =>
    expected.every((action, index) => action === tuple[index])), "IAM plan does not match a safe transition checkpoint");
  if (checkpoint) {
    const expectedFrontend = checkpoint.frontend === PHASE3_IAM_TRANSITION.frontendPredecessorSha256 ? "update"
      : checkpoint.frontend === PHASE3_IAM_TRANSITION.frontendTargetSha256 && checkpoint.audit === PHASE3_IAM_TRANSITION.auditTargetSha256
        ? "no-op" : null;
    assert.equal(tuple[0], expectedFrontend, "IAM frontend plan action differs from authenticated live checkpoint");
    assert.ok(checkpoint.audit === null ? tuple[1] === "create"
      : checkpoint.audit === PHASE3_IAM_TRANSITION.auditTargetSha256 && ["create", "no-op"].includes(tuple[1]),
    "IAM audit plan action differs from authenticated live checkpoint");
  }
  const frontend = changes.find(({ address }) => address === "aws_iam_role_policy.frontend_activation").change;
  const audit = changes.find(({ address }) => address === "aws_iam_role_policy.stage_b_native_audit").change;
  assert.equal(frontend.before?.name, activationPolicyName);
  assert.equal(frontend.after?.name, activationPolicyName);
  assert.equal(frontend.before?.role, releaseRoleName);
  assert.equal(frontend.after?.role, releaseRoleName);
  assert.equal(iamDigest(normalizeIamPolicyDocument(frontend.before?.policy)),
    frontend.actions.join(",") === "update" ? PHASE3_IAM_TRANSITION.frontendPredecessorSha256 : PHASE3_IAM_TRANSITION.frontendTargetSha256);
  assert.equal(iamDigest(normalizeIamPolicyDocument(frontend.after?.policy)), PHASE3_IAM_TRANSITION.frontendTargetSha256);
  if (audit.actions.join(",") === "create") assert.equal(audit.before, null);
  else assert.equal(iamDigest(normalizeIamPolicyDocument(audit.before?.policy)), PHASE3_IAM_TRANSITION.auditTargetSha256);
  assert.equal(audit.after?.name, auditPolicyName);
  assert.equal(audit.after?.role, releaseRoleName);
  assert.equal(iamDigest(normalizeIamPolicyDocument(audit.after?.policy)), PHASE3_IAM_TRANSITION.auditTargetSha256);
  assert.ok(Object.values(plan.output_changes || {}).every(({ actions }) => actions?.join(",") === "no-op"), "IAM plan changes outputs");
}
export function assertPhase3IamAuthorization({ pull, reviewedPull, comments, operator, prNumber, sourceSha, now = Date.now() }) {
  assert.equal(reviewedPull?.number, PHASE3_IAM_TRANSITION.reviewedPrNumber);
  assert.equal(reviewedPull?.merged, true);
  assert.equal(reviewedPull?.head?.sha, PHASE3_IAM_TRANSITION.reviewedHeadSha);
  assert.equal(reviewedPull?.merge_commit_sha, PHASE3_IAM_TRANSITION.reviewedMergeSha);
  assert.equal(reviewedPull?.base?.ref, "main");
  assert.equal(reviewedPull?.base?.sha, PHASE3_IAM_TRANSITION.baselineSha);
  assert.equal(reviewedPull?.base?.repo?.full_name, "T-ej2003/genuine-scan-main");
  assert.equal(reviewedPull?.user?.id, 183396573);
  assert.equal(pull?.merged, true, "IAM correction PR is not merged");
  assert.equal(pull?.number, Number(prNumber), "IAM authorization PR identity differs");
  assert.ok(Number.isSafeInteger(pull?.number) && pull.number > PHASE3_IAM_TRANSITION.reviewedPrNumber,
    "Post-merge IAM authorization requires a distinct correction PR");
  assert.equal(pull?.base?.sha, PHASE3_IAM_TRANSITION.reviewedMergeSha,
    "IAM correction PR is not based on the reviewed PR #721 merge");
  assert.equal(pull?.merge_commit_sha, sourceSha, "IAM authorization does not bind current protected main");
  assert.equal(pull?.base?.ref, "main");
  assert.equal(pull?.base?.repo?.full_name, "T-ej2003/genuine-scan-main");
  assert.equal(pull?.user?.id, 183396573, "IAM PR author is not the accountable operator");
  assert.equal(operator?.id, 183396573, "IAM authorization requires the accountable operator");
  assert.ok(Array.isArray(comments) && comments.length < 100, "IAM authorization comment page is incomplete");
  assert.ok(Number.isFinite(Date.parse(pull.merged_at)), "IAM merge time is invalid");
  assert.ok(Number.isFinite(Date.parse(reviewedPull.merged_at)) && Date.parse(pull.merged_at) > Date.parse(reviewedPull.merged_at),
    "IAM correction did not merge after reviewed PR #721");
  const authorized = comments.filter(({ body, user, created_at, updated_at }) =>
    body === phase3IamAuthorizationMarker(pull.head?.sha, sourceSha) && user?.id === operator.id && user?.type === "User"
    && created_at === updated_at && Number.isFinite(Date.parse(created_at))
    && Date.parse(created_at) > Date.parse(pull.merged_at) && Date.parse(created_at) <= now
    && now - Date.parse(created_at) < PHASE3_IAM_AUTHORIZATION_MAX_AGE_MS);
  assert.equal(authorized.length, 1, "Exact IAM transition needs one fresh unedited post-merge operator authorization comment");
  assert.ok(Number.isSafeInteger(authorized[0].id) && authorized[0].id > 0, "IAM authorization identity is invalid");
  return authorized[0].id;
}
export function readPhase3IamAuthorization({ prNumber, sourceSha, execute = execFileSync, executable = productionGithubExecutable(), env = process.env, now = Date.now }) {
  assert.match(String(prNumber || ""), /^[1-9][0-9]*$/);
  const ghEnv = { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" };
  const gh = endpoint => JSON.parse(execute(executable, ["api", "--hostname", "github.com", endpoint],
    { env: ghEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const base = "repos/T-ej2003/genuine-scan-main";
  const pull = gh(`${base}/pulls/${prNumber}`);
  const reviewedPull = gh(`${base}/pulls/${PHASE3_IAM_TRANSITION.reviewedPrNumber}`);
  const comments = gh(`${base}/issues/${prNumber}/comments?per_page=100`);
  const operator = gh("user");
  return assertPhase3IamAuthorization({ pull, reviewedPull, comments, operator, prNumber, sourceSha, now: now() });
}
export async function verifyPhase3IamMfa({ sourceSha, authorizationId, execute = execFileSync,
  prompt = () => promptProductionMfaCode({ prompt: "Phase 3 IAM operator MFA code: " }), now = Date.now } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.ok(Number.isSafeInteger(authorizationId) && authorizationId > 0);
  const code = String(await prompt()).trim();
  assert.match(code, /^\d{6,8}$/, "Fresh operator MFA input is required");
  const aws = productionAwsExecutable();
  const serial = "arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator";
  const sourceEnv = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-production-bootstrap-operator", region: "eu-west-2" });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-phase3-iam-mfa-"));
  let issued;
  try {
    fs.chmodSync(directory, 0o700);
    const inputFile = path.join(directory, "challenge.json");
    fs.writeFileSync(inputFile, JSON.stringify({ DurationSeconds: 900, SerialNumber: serial, TokenCode: code }), { mode: 0o600, flag: "wx" });
    issued = JSON.parse(execute(aws, ["sts", "get-session-token", "--cli-input-json", `file://${inputFile}`, "--region", "eu-west-2", "--output", "json"],
      { env: sourceEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).Credentials;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  assert.ok(issued?.AccessKeyId && issued.SecretAccessKey && issued.SessionToken, "AWS did not issue an MFA-backed session");
  const expiry = Date.parse(issued.Expiration);
  assert.ok(Number.isFinite(expiry) && expiry > now() + 120000 && expiry <= now() + 901000, "MFA session is not freshly valid");
  const identity = JSON.parse(execute(aws, ["sts", "get-caller-identity", "--region", "eu-west-2", "--output", "json"],
    { env: createAssumedRoleSessionEnvironment({ credentials: issued, region: "eu-west-2" }), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  assert.equal(identity.Account, account);
  assert.equal(identity.Arn, "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator");
  return Object.freeze({ sourceSha, ticketId: PHASE3_IAM_TRANSITION.ticketId, authorizationId, operatorArn: identity.Arn,
    mfaSerial: serial, accessKeyIdSha256: createHash("sha256").update(issued.AccessKeyId).digest("hex"),
    verifiedAt: new Date(now()).toISOString(), expiresAt: new Date(expiry).toISOString() });
}
function assertPhase3IamMfaEvidence(value, sourceSha, authorizationId, now = Date.now()) {
  assert.equal(value?.sourceSha, sourceSha, "Operator MFA source binding differs");
  assert.equal(value?.ticketId, PHASE3_IAM_TRANSITION.ticketId);
  assert.equal(value?.authorizationId, authorizationId);
  assert.equal(value?.operatorArn, "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator");
  assert.equal(value?.mfaSerial, "arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator");
  assert.match(value?.accessKeyIdSha256 || "", /^[a-f0-9]{64}$/);
  assert.ok(Number.isFinite(Date.parse(value?.verifiedAt)) && Date.parse(value.verifiedAt) <= now
    && Date.parse(value.verifiedAt) >= now - 300000, "Operator MFA verification is stale");
  assert.ok(Date.parse(value?.expiresAt) > now + 120000, "Operator MFA authority expired");
}
export function claimPhase3IamOwner({ run, sourceSha, authorizationId, mfaEvidence, ownerFile, resumeOnly = false }) {
  assert.equal(typeof run, "function");
  assert.ok(path.isAbsolute(ownerFile), "IAM owner file must use a private absolute path");
  const parent = fs.realpathSync(path.dirname(ownerFile));
  assert.ok(!parent.startsWith(`${root}${path.sep}`) && parent !== root, "IAM owner file must stay outside the repository");
  assert.equal(fs.statSync(parent).mode & 0o077, 0, "IAM owner directory is not private");
  const binding = { sourceSha, ticketId: PHASE3_IAM_TRANSITION.ticketId, authorizationId,
    reviewedHeadSha: PHASE3_IAM_TRANSITION.reviewedHeadSha, reviewedMergeSha: PHASE3_IAM_TRANSITION.reviewedMergeSha,
    roleName: releaseRoleName, frontendPolicyName: activationPolicyName, auditPolicyName,
    frontendPredecessorSha256: PHASE3_IAM_TRANSITION.frontendPredecessorSha256,
    frontendTargetSha256: PHASE3_IAM_TRANSITION.frontendTargetSha256, auditTargetSha256: PHASE3_IAM_TRANSITION.auditTargetSha256 };
  assertPhase3IamMfaEvidence(mfaEvidence, sourceSha, authorizationId);
  let owner;
  try {
    const stat = fs.lstatSync(ownerFile);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0, "IAM owner file is not private");
    owner = JSON.parse(fs.readFileSync(ownerFile, "utf8"));
    assert.deepEqual(owner.binding, binding, "IAM owner file belongs to another operation");
    assert.match(owner.ownerId || "", /^[a-f0-9-]{36}$/);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    assert.equal(resumeOnly, false, "Partial IAM state lacks a durable owner");
    owner = { binding, ownerId: randomUUID(), initialMfaEvidence: mfaEvidence };
    fs.writeFileSync(ownerFile, JSON.stringify(owner), { mode: 0o600, flag: "wx" });
  }
  const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
  const operation = Object.fromEntries(Object.entries(binding).filter(([key]) => key !== "authorizationId"));
  const key = `mscqr/production/web-release/phase3-iam/${iamDigest(operation)}.json`;
  const expected = Buffer.from(JSON.stringify(owner));
  const readback = objectKey => {
    const file = path.join(path.dirname(ownerFile), `.iam-claim-read-${randomUUID()}`);
    try {
      run(["s3api", "get-object", "--bucket", bucket, "--key", objectKey, "--expected-bucket-owner", account, "--region", "eu-west-2", file]);
      return fs.readFileSync(file);
    } finally { fs.rmSync(file, { force: true }); }
  };
  if (!resumeOnly) {
    try {
      run(["s3api", "put-object", "--bucket", bucket, "--key", key, "--body", ownerFile,
        "--if-none-match", "*", "--server-side-encryption", "AES256", "--expected-bucket-owner", account, "--region", "eu-west-2"]);
    } catch (error) {
      try { if (!readback(key).equals(expected)) throw new Error("IAM operation is owned by another terminal"); }
      catch (readError) { throw new Error("IAM ownership outcome unknown or conflicting", { cause: readError }); }
    }
  }
  assert.ok(readback(key).equals(expected), "IAM ownership readback differs");
  const dispatchPayload = (policyName, inputHash, dispatchId) => ({ ownerId: owner.ownerId, binding, policyName, inputHash, dispatchId });
  const dispatchKey = policyName => `${key.slice(0, -5)}/${policyName}.json`;
  const hasDispatch = (policyName, inputHash) => {
    assert.ok([auditPolicyName, activationPolicyName].includes(policyName));
    assert.match(inputHash || "", /^[a-f0-9]{64}$/);
    try {
      const { dispatchId, ...actual } = JSON.parse(readback(dispatchKey(policyName)));
      assert.match(dispatchId || "", /^[a-f0-9-]{36}$/);
      assert.deepEqual(actual, { ownerId: owner.ownerId, binding, policyName, inputHash }, "IAM dispatch journal conflicts");
      return true;
    }
    catch (error) { if (/NoSuchKey/.test(`${error?.message || ""} ${error?.stderr || ""}`)) return false; throw error; }
  };
  const markDispatch = (policyName, inputHash) => {
    assert.ok([auditPolicyName, activationPolicyName].includes(policyName));
    assert.match(inputHash || "", /^[a-f0-9]{64}$/);
    const keyForDispatch = dispatchKey(policyName);
    const dispatchFile = path.join(path.dirname(ownerFile), `.iam-dispatch-${randomUUID()}`);
    const body = Buffer.from(JSON.stringify(dispatchPayload(policyName, inputHash, randomUUID())));
    fs.writeFileSync(dispatchFile, body, { mode: 0o600, flag: "wx" });
    let created = false;
    try {
      try {
        run(["s3api", "put-object", "--bucket", bucket, "--key", keyForDispatch, "--body", dispatchFile,
          "--if-none-match", "*", "--server-side-encryption", "AES256", "--expected-bucket-owner", account, "--region", "eu-west-2"]);
        created = true;
      } catch (error) {
        if (readback(keyForDispatch).equals(body)) created = true;
        else if (!hasDispatch(policyName, inputHash)) throw new Error("IAM dispatch journal conflicts", { cause: error });
      }
      if (created) assert.ok(readback(keyForDispatch).equals(body), "IAM dispatch journal readback differs");
      return created;
    } finally { fs.rmSync(dispatchFile, { force: true }); }
  };
  const complete = () => {
    const completionKey = `${key.slice(0, -5)}/complete.json`;
    const completionFile = path.join(path.dirname(ownerFile), `.iam-complete-${randomUUID()}`);
    const body = Buffer.from(JSON.stringify({ ownerId: owner.ownerId, binding,
      frontendPolicySha256: PHASE3_IAM_TRANSITION.frontendTargetSha256,
      auditPolicySha256: PHASE3_IAM_TRANSITION.auditTargetSha256 }));
    fs.writeFileSync(completionFile, body, { mode: 0o600, flag: "wx" });
    try {
      try { run(["s3api", "put-object", "--bucket", bucket, "--key", completionKey, "--body", completionFile,
        "--if-none-match", "*", "--server-side-encryption", "AES256", "--expected-bucket-owner", account, "--region", "eu-west-2"]); }
      catch (error) { if (!readback(completionKey).equals(body)) throw new Error("IAM completion receipt conflicts", { cause: error }); }
      assert.ok(readback(completionKey).equals(body), "IAM completion receipt readback differs");
      return iamDigest(JSON.parse(body));
    } finally { fs.rmSync(completionFile, { force: true }); }
  };
  return Object.freeze({ ownershipSha256: iamDigest(owner), hasDispatch, markDispatch, complete });
}
const publisherTags = [
  { Key: "Environment", Value: "production" },
  { Key: "ManagedBy", Value: "Terraform" },
  { Key: "Stack", Value: "production-web-release" },
];
const readJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const source = (file) => JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-web-release", file), "utf8"));
const canonical = (value) => JSON.stringify(normalizeIamPolicyDocument(value, "production web release IAM document"));
const fileValue = (file) => `file://${path.join(root, "infra/aws/terraform/production-web-release", file)}`;
function defaultPolicyVersionId(response) {
  assert.ok(response && typeof response === "object" && !Array.isArray(response), "Permissions boundary policy-version response is malformed.");
  assert.ok(response.IsTruncated === undefined || response.IsTruncated === false, "Permissions boundary policy-version response is incomplete.");
  assert.ok(!Object.hasOwn(response, "Marker") && !Object.hasOwn(response, "NextToken"), "Permissions boundary policy-version response is incomplete.");
  assert.ok(Array.isArray(response.Versions) && response.Versions.length > 0, "Permissions boundary policy-version response is malformed.");
  assert.ok(response.Versions.every((version) => version && typeof version.VersionId === "string" && /^v[1-9]\d*$/.test(version.VersionId) && typeof version.IsDefaultVersion === "boolean"), "Permissions boundary policy-version response is malformed.");
  const defaults = response.Versions.filter(({ IsDefaultVersion }) => IsDefaultVersion);
  assert.equal(defaults.length, 1, "Permissions boundary must have exactly one default policy version.");
  return defaults[0].VersionId;
}

export const WEB_RELEASE_IAM = Object.freeze({ account, roleName, boundaryName, releaseRoleName, publisherPolicyName, activationPolicyName, registryReadPolicyName });

export function bootstrapProductionWebReleaseIam({ run, sourceSha }) {
  assert.equal(typeof run, "function");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Exact protected source SHA is required.");
  const identity = readJson(run, ["sts", "get-caller-identity"]);
  assert.equal(identity.Account, account, "IAM bootstrap must use the production account.");
  assert.equal(identity.Arn, `arn:aws:iam::${account}:root`, "Exact web IAM bootstrap requires the governed root configuration profile.");

  const boundaryArn = `arn:aws:iam::${account}:policy/${boundaryName}`;
  const roleArn = `arn:aws:iam::${account}:role/${roleName}`;
  const publisher = source("publisher-permissions-policy.json");
  const trust = source("publisher-trust-policy.json");
  const activation = source("frontend-activation-policy.json");
  const registryRead = source("web-evidence-registry-read-policy.json");
  const actions = [];
  const optional = (args, select) => {
    try { return select(readJson(run, args)); }
    catch (error) { if (/NoSuchEntity/.test(`${error?.message || ""} ${error?.stderr || ""}`)) return null; throw error; }
  };

  const boundary = optional(["iam", "get-policy", "--policy-arn", boundaryArn], (value) => value.Policy);
  if (boundary) {
    assert.equal(boundary.Arn, boundaryArn, "Unexpected permissions boundary identity.");
    assert.equal(boundary.PolicyName, boundaryName, "Unexpected permissions boundary name.");
    assert.equal(boundary.Path, "/", "Unexpected permissions boundary path.");
    assert.equal(boundary.Description, "Terraform-managed production web publisher permissions boundary.", "Permissions boundary description differs from Terraform source.");
    const versions = readJson(run, ["iam", "list-policy-versions", "--policy-arn", boundaryArn]);
    const versionId = defaultPolicyVersionId(versions);
    const liveBoundary = readJson(run, ["iam", "get-policy-version", "--policy-arn", boundaryArn, "--version-id", versionId]).PolicyVersion.Document;
    assert.equal(canonical(liveBoundary), canonical(publisher), "Permissions boundary differs from reviewed source.");
  }

  const role = optional(["iam", "get-role", "--role-name", roleName], (value) => value.Role);
  if (role) {
    assert.equal(role.RoleName, roleName);
    assert.equal(role.Arn, roleArn);
    assert.equal(role.Path, "/");
    assert.equal(role.Description, "GitHub OIDC only: publish the reviewed production web image.");
    assert.equal(role.PermissionsBoundary?.PermissionsBoundaryArn, boundaryArn);
    assert.equal(role.MaxSessionDuration, 3600);
    assert.equal(canonical(role.AssumeRolePolicyDocument), canonical(trust), "Publisher trust differs from reviewed source.");
    assert.deepEqual([...(role.Tags || [])].sort((a, b) => a.Key.localeCompare(b.Key)), publisherTags, "Publisher tags differ from reviewed source.");
    const rolePolicies = readJson(run, ["iam", "list-role-policies", "--role-name", roleName]);
    assert.equal(rolePolicies.IsTruncated ?? false, false);
    assert.deepEqual(rolePolicies.PolicyNames.filter((name) => name !== publisherPolicyName), [], "Unexpected publisher inline policy exists.");
    const attached = readJson(run, ["iam", "list-attached-role-policies", "--role-name", roleName]);
    assert.equal(attached.IsTruncated ?? false, false);
    assert.deepEqual(attached.AttachedPolicies, [], "Unexpected publisher managed-policy attachment exists.");
  }
  const livePublisherPolicy = role && optional(["iam", "get-role-policy", "--role-name", roleName, "--policy-name", publisherPolicyName], (value) => value.PolicyDocument);
  if (livePublisherPolicy) assert.equal(canonical(livePublisherPolicy), canonical(publisher), "Publisher inline policy differs from reviewed source.");
  const releaseRole = readJson(run, ["iam", "get-role", "--role-name", releaseRoleName]).Role;
  assert.equal(releaseRole.Arn, `arn:aws:iam::${account}:role/${releaseRoleName}`, "Release deployer identity changed.");
  const liveActivation = optional(["iam", "get-role-policy", "--role-name", releaseRoleName, "--policy-name", activationPolicyName], (value) => value.PolicyDocument);
  if (liveActivation) assert.equal(canonical(liveActivation), canonical(activation), "Frontend activation policy differs from reviewed source.");
  const liveRegistryRead = optional(["iam", "get-role-policy", "--role-name", releaseRoleName, "--policy-name", registryReadPolicyName], (value) => value.PolicyDocument);
  if (liveRegistryRead) assert.equal(canonical(liveRegistryRead), canonical(registryRead), "Web evidence registry policy differs from reviewed source.");

  if (!boundary) {
    run(["iam", "create-policy", "--policy-name", boundaryName, "--policy-document", fileValue("publisher-permissions-policy.json"), "--description", "Terraform-managed production web publisher permissions boundary."]);
    actions.push("CREATE_BOUNDARY");
    const created = readJson(run, ["iam", "get-policy", "--policy-arn", boundaryArn]).Policy;
    assert.equal(created.Arn, boundaryArn);
    assert.equal(created.Path, "/");
    assert.equal(created.Description, "Terraform-managed production web publisher permissions boundary.");
    const versions = readJson(run, ["iam", "list-policy-versions", "--policy-arn", boundaryArn]);
    const versionId = defaultPolicyVersionId(versions);
    const live = readJson(run, ["iam", "get-policy-version", "--policy-arn", boundaryArn, "--version-id", versionId]).PolicyVersion.Document;
    assert.equal(canonical(live), canonical(publisher), "Created boundary readback differs from source.");
  }
  if (!role) {
    run(["iam", "create-role", "--role-name", roleName, "--description", "GitHub OIDC only: publish the reviewed production web image.", "--max-session-duration", "3600", "--assume-role-policy-document", fileValue("publisher-trust-policy.json"), "--permissions-boundary", boundaryArn, "--tags", "Key=ManagedBy,Value=Terraform", "Key=Environment,Value=production", "Key=Stack,Value=production-web-release"]);
    actions.push("CREATE_PUBLISHER_ROLE");
    const created = readJson(run, ["iam", "get-role", "--role-name", roleName]).Role;
    assert.equal(canonical(created.AssumeRolePolicyDocument), canonical(trust));
    assert.equal(created.PermissionsBoundary?.PermissionsBoundaryArn, boundaryArn);
    assert.equal(created.MaxSessionDuration, 3600);
    assert.deepEqual([...(created.Tags || [])].sort((a, b) => a.Key.localeCompare(b.Key)), publisherTags);
  }
  const installIfStillAbsent = (targetRole, policyName, document) => {
    const current = optional(["iam", "get-role-policy", "--role-name", targetRole, "--policy-name", policyName], (value) => value.PolicyDocument);
    if (current) { assert.equal(canonical(current), canonical(document), `${policyName} changed after preflight.`); return; }
    run(["iam", "put-role-policy", "--role-name", targetRole, "--policy-name", policyName, "--policy-document", JSON.stringify(document)]);
    actions.push(`INSTALL_${policyName}`);
    assert.equal(canonical(readJson(run, ["iam", "get-role-policy", "--role-name", targetRole, "--policy-name", policyName]).PolicyDocument), canonical(document), `${policyName} readback differs from source.`);
  };
  installIfStillAbsent(roleName, publisherPolicyName, publisher);
  installIfStillAbsent(releaseRoleName, activationPolicyName, activation);
  installIfStillAbsent(releaseRoleName, registryReadPolicyName, registryRead);
  return Object.freeze({ status: "WEB_RELEASE_IAM_SOURCE_VERIFIED", sourceSha, roleArn, boundaryArn, actions: Object.freeze(actions) });
}

// One reviewed transition for CHG-20261022-001; the ordinary bootstrap remains create-only.
export function reconcilePhase3WebIam({ run, sourceSha, ticketId, plan, authorizationId, mfaEvidence, claimOwnership, assertCurrentAuthorization,
  assertProtectedSource = () => readPhase3IamProtectedSource({ sourceSha }) }) {
  assert.equal(typeof run, "function");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(ticketId, PHASE3_IAM_TRANSITION.ticketId);
  assert.ok(Number.isSafeInteger(authorizationId) && authorizationId > 0, "Solo-operator IAM authorization is missing");
  assertPhase3IamMfaEvidence(mfaEvidence, sourceSha, authorizationId);
  assertPhase3IamPlan(plan, sourceSha);
  const frontend = source("frontend-activation-policy.json");
  const audit = source("stage-b-native-audit-policy.json");
  assert.equal(iamDigest(frontend), PHASE3_IAM_TRANSITION.frontendTargetSha256, "Frontend source fingerprint changed");
  assert.equal(iamDigest(audit), PHASE3_IAM_TRANSITION.auditTargetSha256, "Native audit source fingerprint changed");
  const caller = readJson(run, ["sts", "get-caller-identity"]);
  assert.equal(caller.Account, account);
  assert.equal(caller.Arn, `arn:aws:iam::${account}:root`, "Exact IAM bootstrap requires account root");
  const readInline = name => {
    try { return readJson(run, ["iam", "get-role-policy", "--role-name", releaseRoleName, "--policy-name", name]).PolicyDocument; }
    catch (error) { if (/NoSuchEntity/.test(`${error?.message || ""} ${error?.stderr || ""}`)) return null; throw error; }
  };
  const observed = name => {
    const value = readInline(name);
    return value === null ? null : iamDigest(normalizeIamPolicyDocument(value));
  };
  const beforeFrontend = observed(activationPolicyName), beforeAudit = observed(auditPolicyName);
  assert.ok([PHASE3_IAM_TRANSITION.frontendPredecessorSha256, PHASE3_IAM_TRANSITION.frontendTargetSha256].includes(beforeFrontend),
    "Frontend predecessor fingerprint changed");
  assert.ok(beforeAudit === null || beforeAudit === PHASE3_IAM_TRANSITION.auditTargetSha256, "Native audit policy conflicts");
  assert.ok(!(beforeAudit === null && beforeFrontend === PHASE3_IAM_TRANSITION.frontendTargetSha256),
    "Frontend transition preceded native audit installation");
  const checkpoint = { frontend: beforeFrontend, audit: beforeAudit };
  assertPhase3IamPlan(plan, sourceSha, checkpoint);
  assert.equal(assertProtectedSource(), sourceSha, "Protected main advanced before IAM ownership");
  assert.equal(typeof assertCurrentAuthorization, "function", "Fresh IAM authorization verification is required");
  assert.equal(assertCurrentAuthorization(), authorizationId, "Solo-operator IAM authorization changed before ownership");
  assert.equal(typeof claimOwnership, "function", "Durable IAM ownership claim is required");
  const resumeOnly = beforeAudit !== null || beforeFrontend === PHASE3_IAM_TRANSITION.frontendTargetSha256;
  const { ownershipSha256, hasDispatch, markDispatch, complete } = claimOwnership({ run, sourceSha, authorizationId, mfaEvidence, resumeOnly });
  assert.match(ownershipSha256 || "", /^[a-f0-9]{64}$/, "IAM ownership claim is not authenticated");
  assert.equal(typeof hasDispatch, "function", "Durable IAM dispatch inspection is required");
  assert.equal(typeof markDispatch, "function", "Durable per-policy dispatch journal is required");
  assert.equal(typeof complete, "function", "Durable IAM completion receipt is required");
  if (beforeAudit !== null) assert.equal(hasDispatch(auditPolicyName, PHASE3_IAM_TRANSITION.auditTargetSha256), true,
    "Native audit target lacks an authenticated dispatch journal");
  if (beforeFrontend === PHASE3_IAM_TRANSITION.frontendTargetSha256)
    assert.equal(hasDispatch(activationPolicyName, PHASE3_IAM_TRANSITION.frontendTargetSha256), true,
      "Frontend target lacks an authenticated dispatch journal");
  assert.equal(observed(activationPolicyName), beforeFrontend, "Frontend IAM changed after checkpoint authentication");
  assert.equal(observed(auditPolicyName), beforeAudit, "Native audit IAM changed after checkpoint authentication");
  const actions = [];
  const install = (name, document, expectedBefore, expectedAfter) => {
    const current = observed(name);
    if (current === expectedAfter) {
      assert.equal(hasDispatch(name, expectedAfter), true, `${name} target lacks an authenticated dispatch journal`);
      return;
    }
    assert.equal(current, expectedBefore, `${name} changed during IAM reconciliation`);
    assert.equal(assertProtectedSource(), sourceSha, "Protected main advanced before IAM dispatch");
    assertPhase3IamMfaEvidence(mfaEvidence, sourceSha, authorizationId);
    if (!markDispatch(name, expectedAfter)) throw new Error(`${name} dispatch outcome unknown; reconcile live IAM before another attempt`);
    assert.equal(assertProtectedSource(), sourceSha, "Protected main advanced after IAM journal");
    assert.equal(assertCurrentAuthorization(), authorizationId, "Solo-operator IAM authorization changed before IAM write");
    assertPhase3IamMfaEvidence(mfaEvidence, sourceSha, authorizationId);
    assert.equal(observed(name), expectedBefore, `${name} changed after dispatch journal and before IAM write`);
    if (name === activationPolicyName) assert.equal(observed(auditPolicyName), PHASE3_IAM_TRANSITION.auditTargetSha256,
      "Native audit policy changed before frontend IAM write");
    try { run(["iam", "put-role-policy", "--role-name", releaseRoleName, "--policy-name", name, "--policy-document", JSON.stringify(document)]); }
    catch (error) {
      if (observed(name) !== expectedAfter) throw new Error(`${name} write outcome unknown; reconcile live IAM before retry`, { cause: error });
    }
    assert.equal(observed(name), expectedAfter, `${name} readback differs from authorized target`);
    actions.push(`INSTALL_${name}`);
  };
  install(auditPolicyName, audit, null, PHASE3_IAM_TRANSITION.auditTargetSha256);
  assert.equal(observed(auditPolicyName), PHASE3_IAM_TRANSITION.auditTargetSha256);
  install(activationPolicyName, frontend, PHASE3_IAM_TRANSITION.frontendPredecessorSha256, PHASE3_IAM_TRANSITION.frontendTargetSha256);
  assert.equal(observed(auditPolicyName), PHASE3_IAM_TRANSITION.auditTargetSha256);
  assert.equal(observed(activationPolicyName), PHASE3_IAM_TRANSITION.frontendTargetSha256);
  assert.equal(hasDispatch(auditPolicyName, PHASE3_IAM_TRANSITION.auditTargetSha256), true);
  assert.equal(hasDispatch(activationPolicyName, PHASE3_IAM_TRANSITION.frontendTargetSha256), true);
  const completionSha256 = complete();
  assert.match(completionSha256 || "", /^[a-f0-9]{64}$/, "IAM completion receipt is not authenticated");
  return Object.freeze({ status: "PHASE3_WEB_IAM_RECONCILED", sourceSha, ticketId, authorizationId, ownershipSha256, completionSha256, actions: Object.freeze(actions) });
}

export function createPhase3IamAwsRunner({ profile, exec = execFileSync } = {}) {
  const mutating = new Set(["create-policy", "create-role", "put-role-policy"]);
  const aws = productionAwsExecutable();
  return createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile,
    exec: (file, command, options) => {
      assert.equal(file, "aws", "IAM bootstrap permits only the safelisted AWS CLI");
      return exec(aws, command, {
        ...options,
        env: command[0] === "iam" && mutating.has(command[1]) || command[0] === "s3api" && command[1] === "put-object"
          ? { ...options.env, AWS_MAX_ATTEMPTS: "1", AWS_RETRY_MODE: "standard" } : options.env,
      });
    } });
}

function args(argv) {
  const result = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i], value = argv[i + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || result.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    result.set(key, value);
  }
  const keys = [...result.keys()].sort();
  assert.ok(
    JSON.stringify(keys) === JSON.stringify(["--admin-profile", "--source-sha"])
    || JSON.stringify(keys) === JSON.stringify(["--admin-profile", "--authorization-pr", "--owner-file", "--plan-file", "--source-sha", "--ticket-id"]),
    "IAM bootstrap accepts only the existing bootstrap or exact Phase 3 transition arguments",
  );
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  pinPhase3IamGitPath();
  const values = args(process.argv.slice(2));
  const sourceSha = values.get("--source-sha");
  assert.equal(readPhase3IamProtectedSource({ sourceSha }), sourceSha, "IAM bootstrap source is not exact protected main.");
  const run = createPhase3IamAwsRunner({ profile: values.get("--admin-profile") });
  let result;
  if (values.has("--ticket-id")) {
    execFileSync("/usr/bin/git", ["merge-base", "--is-ancestor", PHASE3_IAM_TRANSITION.baselineSha, sourceSha], { cwd: root, stdio: "ignore" });
    const planFile = path.resolve(values.get("--plan-file"));
    const { plan, planSha256 } = readPhase3IamPlan({ planFile });
    assertPhase3IamPlan(plan, sourceSha);
    const authorizationId = readPhase3IamAuthorization({ prNumber: values.get("--authorization-pr"), sourceSha });
    assert.equal(readPhase3IamProtectedSource({ sourceSha }),
      sourceSha, "Protected main advanced before IAM installation");
    const mfaEvidence = await verifyPhase3IamMfa({ sourceSha, authorizationId });
    assert.equal(readPhase3IamAuthorization({ prNumber: values.get("--authorization-pr"), sourceSha }), authorizationId,
      "Solo-operator IAM authorization changed during MFA");
    result = { ...reconcilePhase3WebIam({ run, sourceSha, ticketId: values.get("--ticket-id"), plan, authorizationId, mfaEvidence,
      assertCurrentAuthorization: () => readPhase3IamAuthorization({ prNumber: values.get("--authorization-pr"), sourceSha }),
      claimOwnership: input => claimPhase3IamOwner({ ...input, ownerFile: path.resolve(values.get("--owner-file")) }) }),
      planSha256 };
  } else result = bootstrapProductionWebReleaseIam({ sourceSha, run });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
