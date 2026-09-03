import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner } from "../aws/production-credential-source-contract.mjs";
import { createProductionBackendFailedRecoveryEvidenceAwsRunner } from "../aws/prepare-production-backend-failed-recovery-evidence.mjs";
import { createReleaseGateImageAuthorizationRunner } from "../aws/verify-production-release-image-authorization.mjs";
import { createProductionCutoverRuntimeComposition } from "../aws/production-cutover-runtime-composition.mjs";

const hostileAwsOverrides = Object.freeze({
  AWS_PROFILE: "hostile-profile",
  AWS_DEFAULT_PROFILE: "hostile-default",
  AWS_CONFIG_FILE: "/hostile/config",
  AWS_SHARED_CREDENTIALS_FILE: "/hostile/credentials",
  AWS_SDK_LOAD_CONFIG: "1",
  AWS_ROLE_ARN: "arn:aws:iam::111111111111:role/hostile",
  AWS_WEB_IDENTITY_TOKEN_FILE: "/hostile/token",
  AWS_ROLE_SESSION_NAME: "hostile-session",
  AWS_CONTAINER_CREDENTIALS_FULL_URI: "https://hostile.invalid/credentials",
  AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/hostile",
  AWS_CONTAINER_AUTHORIZATION_TOKEN: "fixture-hostile-token",
  AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: "/hostile/container-token",
  AWS_ENDPOINT_URL: "https://hostile.invalid",
  AWS_ENDPOINT_URL_KMS: "https://hostile.invalid/kms",
  AWS_CA_BUNDLE: "/hostile/ca",
  AWS_USE_FIPS_ENDPOINT: "false",
  AWS_USE_DUALSTACK_ENDPOINT: "true",
  AWS_METADATA_SERVICE_TIMEOUT: "99",
  AWS_METADATA_SERVICE_NUM_ATTEMPTS: "99",
  AWS_EC2_METADATA_SERVICE_ENDPOINT: "https://hostile.invalid/metadata",
  AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE: "IPv6",
});
const assertAwsOverridesAbsent = (env) => {
  for (const name of Object.keys(hostileAwsOverrides)) assert.equal(env[name], undefined, name);
};
const assertLiteralIncludes = (text, literal, message = literal) => assert.ok(text.includes(literal), message);

const oidc = Object.freeze({
  AWS_ACCESS_KEY_ID: "fixture-access",
  AWS_SECRET_ACCESS_KEY: "s",
  AWS_SESSION_TOKEN: "t",
  AWS_REGION: "eu-west-2",
  ...hostileAwsOverrides,
  PATH: process.env.PATH,
});
const accessKeys = Object.freeze({
  AWS_ACCESS_KEY_ID: "fixture-access-key",
  AWS_SECRET_ACCESS_KEY: "s",
  ...hostileAwsOverrides,
  PATH: process.env.PATH,
});

test("GitHub release-gate composition preserves only the OIDC session and never selects a profile", () => {
  const calls = [];
  const run = createProductionCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return JSON.stringify({ SignatureValid: true }); },
  });
  run(["kms", "verify", "--key-id", "fixture"]);
  assert.equal(calls[0].file, "aws");
  assert.deepEqual(calls[0].args.slice(0, 2), ["kms", "verify"]);
  assert.equal(calls[0].options.env.AWS_ACCESS_KEY_ID, oidc.AWS_ACCESS_KEY_ID);
  assert.equal(calls[0].options.env.AWS_SECRET_ACCESS_KEY, oidc.AWS_SECRET_ACCESS_KEY);
  assert.equal(calls[0].options.env.AWS_SESSION_TOKEN, oidc.AWS_SESSION_TOKEN);
  assert.equal(calls[0].options.env.AWS_PROFILE, undefined);
  assert.equal(calls[0].options.env.AWS_DEFAULT_PROFILE, undefined);
  assertAwsOverridesAbsent(calls[0].options.env);
});

test("release-gate image authorization composes its verifier with the workflow OIDC session", () => {
  const calls = [];
  const run = createReleaseGateImageAuthorizationRunner({
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return JSON.stringify({ SignatureValid: true }); },
  });
  run(["kms", "verify", "--key-id", "fixture"]);
  assert.equal(calls[0].file, "aws");
  assert.deepEqual(calls[0].args.slice(0, 2), ["kms", "verify"]);
  assert.equal(calls[0].options.env.AWS_SESSION_TOKEN, oidc.AWS_SESSION_TOKEN);
  assert.equal(calls[0].options.env.AWS_PROFILE, undefined);
  assert.equal(calls[0].options.env.AWS_DEFAULT_PROFILE, undefined);
});

test("local governed composition removes ambient credentials and pins the exact named profile", () => {
  const calls = [];
  const run = createProductionCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-production-release-deployer",
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
  });
  run(["kms", "verify", "--key-id", "fixture"]);
  assert.equal(calls[0].options.env.AWS_PROFILE, "mscqr-production-release-deployer");
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) assert.equal(calls[0].options.env[name], undefined);
  assertAwsOverridesAbsent({ ...calls[0].options.env, AWS_PROFILE: undefined });
});

test("Stage A Terraform runners use the canonical sanitized named-profile environment", () => {
  for (const file of ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs"]) {
    const source = fs.readFileSync(file, "utf8");
    assert.match(source, /createProductionAwsCredentialEnvironment/);
    assert.doesNotMatch(source, /env:\s*\{\s*\.\.\.process\.env/);
  }
});

test("AWS command environments never inherit GitHub control-plane credentials", () => {
  const calls = [];
  const run = createProductionCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-production-release-deployer",
    env: { ...oidc, GH_TOKEN: "fixture-gh-token", GITHUB_TOKEN: "fixture-github-token" },
    exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
  });
  run(["secretsmanager", "describe-secret", "--secret-id", "fixture"]);
  assert.equal(calls[0].options.env.GH_TOKEN, undefined);
  assert.equal(calls[0].options.env.GITHUB_TOKEN, undefined);
});

test("GitHub authorization runner supports token and credential-store domains without AWS credentials", () => {
  for (const input of [
    { GH_TOKEN: "fixture-gh-token" },
    { GITHUB_TOKEN: "fixture-github-token" },
    { HOME: "/operator" },
    { HOME: "/operator", GH_TOKEN: "fixture-gh-token", GITHUB_TOKEN: "fixture-github-token" },
  ]) {
    let captured;
    const run = createProductionGithubCommandRunner({ env: { PATH: "/usr/bin", ...input, AWS_ACCESS_KEY_ID: "fixture-aws-key" }, exec: (file, args, options) => { captured = { file, args, options }; return "{}"; } });
    run("gh", ["api", "repos/T-ej2003/genuine-scan-main/actions/runs/123"]);
    assert.equal(captured.file, "gh");
    assert.equal(captured.options.env.AWS_ACCESS_KEY_ID, undefined);
    assert.equal(captured.options.env.GH_TOKEN, input.GH_TOKEN);
    assert.equal(captured.options.env.GITHUB_TOKEN, input.GITHUB_TOKEN);
    assert.equal(captured.options.env.HOME, input.HOME);
  }
});

test("GitHub authorization runner rejects write-shaped gh api invocations", () => {
  const run = createProductionGithubCommandRunner({ env: { GH_TOKEN: "fixture-token" }, exec: () => "{}" });
  assert.doesNotThrow(() => run("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
  for (const flag of ["--method", "-X", "--input", "--field", "-f", "--raw-field", "-F", "--method=POST", "-XPOST"]) assert.throws(() => run("gh", ["api", "repos/T-ej2003/genuine-scan-main/actions/runs/123", flag, "value"]), /reviewed read-only/);
  assert.throws(() => run("gh", ["api", "repos/example/repository"]), /reviewed read-only/);
  for (const member of ["other.json", "../authorization.json", "arbitrary.json", "recovery/authorization.json"]) assert.throws(() => run("unzip", ["-p", "/tmp/authorization.zip", member]), /reviewed local/);
});

test("GitHub authorization runner permits only the two canonical authorization archive members", () => {
  const seen = [];
  const run = createProductionGithubCommandRunner({ env: { GH_TOKEN: "fixture-token" }, exec: (file, args) => { seen.push({ file, args }); return "{}"; } });
  for (const member of ["authorization.json", "recovery-authorization.json"]) run("unzip", ["-p", "/tmp/authorization.zip", member]);
  assert.deepEqual(seen.map(({ args }) => args[2]), ["authorization.json", "recovery-authorization.json"]);
});

test("runtime preparation's real composition root pins the release profile before KMS verification", () => {
  const calls = [];
  const composition = createProductionCutoverRuntimeComposition({
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return JSON.stringify({ SignatureValid: true }); },
  });
  composition.releaseRun(["kms", "verify", "--key-id", "fixture"]);
  assert.equal(calls[0].file, "aws");
  assert.equal(calls[0].options.env.AWS_PROFILE, "mscqr-production-release-deployer");
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(calls[0].options.env[name], undefined);
});

test("credential source is explicit and OIDC fails before AWS execution when its session is absent", () => {
  let calls = 0;
  assert.throws(() => createProductionCommandRunner({ profile: "mscqr-production-release-deployer", exec: () => { calls += 1; } }), /credential source must be explicit/);
  assert.throws(() => createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env: { PATH: process.env.PATH }, exec: () => { calls += 1; } }), /AWS_ACCESS_KEY_ID/);
  assert.equal(calls, 0);
});

test("GitHub access-key composition preserves an optional session token without selecting a profile", () => {
  const calls = [];
  const run = createProductionAwsCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS,
    env: accessKeys,
    exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
  });
  run(["sts", "get-caller-identity"]);
  assert.equal(calls[0].options.env.AWS_ACCESS_KEY_ID, accessKeys.AWS_ACCESS_KEY_ID);
  assert.equal(calls[0].options.env.AWS_SECRET_ACCESS_KEY, accessKeys.AWS_SECRET_ACCESS_KEY);
  assert.equal(calls[0].options.env.AWS_SESSION_TOKEN, undefined);
  assert.equal(calls[0].options.env.AWS_PROFILE, undefined);
  assert.equal(calls[0].options.env.AWS_DEFAULT_PROFILE, undefined);
  assertAwsOverridesAbsent(calls[0].options.env);
  const withToken = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS, env: { ...accessKeys, AWS_SESSION_TOKEN: "t" }, exec: (_file, _args, options) => options.env });
  assert.equal(withToken(["sts", "get-caller-identity"]).AWS_SESSION_TOKEN, "t");
  assert.throws(() => createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS, env: { PATH: process.env.PATH }, exec: () => { throw new Error("must not execute"); } }), /AWS_ACCESS_KEY_ID/);
  assert.throws(() => createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS, env: { ...accessKeys, AWS_SECRET_ACCESS_KEY: "" }, exec: () => { throw new Error("must not execute"); } }), /AWS_SECRET_ACCESS_KEY/);
});

test("root and preflight AWS-only composition pin a named profile instead of inheriting a session", () => {
  const calls = [];
  const run = createProductionAwsCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "default",
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
  });
  run(["sts", "get-caller-identity"]);
  assert.equal(calls[0].file, "aws");
  assert.equal(calls[0].options.env.AWS_PROFILE, "default");
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) assert.equal(calls[0].options.env[name], undefined);
  assertAwsOverridesAbsent({ ...calls[0].options.env, AWS_PROFILE: undefined });
});

test("failed-recovery evidence composition pins the root profile instead of inheriting ambient credentials", () => {
  const calls = [];
  const run = createProductionBackendFailedRecoveryEvidenceAwsRunner({
    env: oidc,
    exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
  });
  run(["kms", "sign", "--key-id", "fixture"]);
  assert.equal(calls[0].file, "aws");
  assert.equal(calls[0].options.env.AWS_PROFILE, "default");
  for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) assert.equal(calls[0].options.env[name], undefined);
  assertAwsOverridesAbsent({ ...calls[0].options.env, AWS_PROFILE: undefined });
});

for (const [name, source] of [["independent checker", PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION], ["ECS verifier", PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_ECS_EXEC_VERIFIER_SESSION]]) {
  test(`${name} session composition preserves only its explicit session credentials`, () => {
    const calls = [];
    const run = createProductionAwsCommandRunner({
      credentialSource: source,
      env: oidc,
      exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; },
    });
    run(["sts", "get-caller-identity"]);
    assert.equal(calls[0].options.env.AWS_SESSION_TOKEN, oidc.AWS_SESSION_TOKEN);
    assert.equal(calls[0].options.env.AWS_PROFILE, undefined);
    assert.equal(calls[0].options.env.AWS_DEFAULT_PROFILE, undefined);
    assertAwsOverridesAbsent(calls[0].options.env);
  });
}

test("release-gate workflow explicitly selects OIDC for every AWS-capable CLI root", () => {
  const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  for (const script of ["verify-production-release-image-authorization.mjs", "production-normal-backend-activation.mjs", "recover-production-backend-health.mjs", "run-production-cutover.mjs", "apply-production-full-rls-release.mjs"]) {
    const start = workflow.indexOf(script);
    assert.ok(start >= 0, `${script} is called by Release Gate`);
    assert.match(workflow.slice(start, start + 800), /--credential-source github-oidc-release-deployer/);
  }
  assert.match(workflow, /manage-production-initial-activation-lifecycle\.mjs[\s\S]{0,600}--mode claim[\s\S]{0,160}--credential-source github-oidc-release-deployer/);
  assert.match(workflow, /aws-actions\/configure-aws-credentials@v6[\s\S]*role-to-assume: \$\{\{ env\.PRODUCTION_RELEASE_ROLE_ARN \}\}/);
});

test("workflow shell AWS calls select their authenticated credential mode before execution", () => {
  const releaseGate = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  for (const section of releaseGate.split(/^\s*- name:/m).filter((value) => /\baws\s+(?:sts|ecs)\b/.test(value))) {
    assert.match(section, /source scripts\/aws\/production-credential-source\.sh/);
    assert.match(section, /MSCQR_AWS_CREDENTIAL_SOURCE=github-oidc-release-deployer/);
    assert.match(section, /configure_production_aws_credential_source/);
  }
  const publisher = fs.readFileSync(".github/workflows/publish-ecs-images.yml", "utf8");
  assert.match(publisher, /echo "mode=oidc"[\s\S]{0,120}credential_source=github-oidc-release-deployer/);
  assert.match(publisher, /echo "mode=keys"[\s\S]{0,120}credential_source=github-access-keys/);
  assert.equal([...publisher.matchAll(/MSCQR_AWS_CREDENTIAL_SOURCE: \$\{\{ steps\.auth-mode\.outputs\.credential_source \}\}/g)].length, 3);
  assert.doesNotMatch(publisher, /MSCQR_AWS_CREDENTIAL_SOURCE=github-oidc-release-deployer/);
});

test("production image publisher workflows select explicit OIDC or the documented keys fallback and never a local profile", () => {
  for (const file of [".github/workflows/production-green-stage-b-image-build.yml", ".github/workflows/production-green-backend-image-publish.yml"]) {
    const workflow = fs.readFileSync(file, "utf8");
    assert.match(workflow, /aws-actions\/configure-aws-credentials@v6/);
    assert.doesNotMatch(workflow, /mscqr-production-release-deployer/);
  }
  const publisher = fs.readFileSync(".github/workflows/publish-ecs-images.yml", "utf8");
  assert.match(publisher, /if: steps\.auth-mode\.outputs\.mode == 'oidc'/);
  assert.match(publisher, /if: steps\.auth-mode\.outputs\.mode == 'keys'/);
  assert.doesNotMatch(publisher, /mscqr-production-release-deployer/);
});

test("every GitHub workflow credential root is classified by its authenticated mode", () => {
  const oidcWorkflows = [
    ".github/workflows/auto-failover-monitor.yml", ".github/workflows/authorize-production-stage-a-production-artifacts-continuation-rebind.yml", ".github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml", ".github/workflows/aws-dr-alb-apply.yml", ".github/workflows/aws-dr-cleanup-apply.yml", ".github/workflows/aws-dr-db-apply.yml", ".github/workflows/aws-dr-dns-apply.yml", ".github/workflows/aws-dr-hardening-apply.yml", ".github/workflows/aws-dr-object-storage-apply.yml", ".github/workflows/aws-dr-operations.yml", ".github/workflows/aws-dr-regional-readiness.yml", ".github/workflows/aws-dr-snapshot-apply.yml", ".github/workflows/production-green-backend-image-publish.yml", ".github/workflows/production-green-stage-b-image-build.yml", ".github/workflows/release-gate.yml", ".github/workflows/staging-terraform-remote-state-drift.yml",
  ];
  const configured = fs.readdirSync(".github/workflows").filter((name) => name.endsWith(".yml") && fs.readFileSync(`.github/workflows/${name}`, "utf8").includes("aws-actions/configure-aws-credentials@v6")).sort();
  assert.deepEqual(configured, [...oidcWorkflows, ".github/workflows/publish-ecs-images.yml"].map((file) => file.split("/").at(-1)).sort());
  for (const file of oidcWorkflows) {
    const workflow = fs.readFileSync(file, "utf8");
    assert.match(workflow, /aws-actions\/configure-aws-credentials@v6[\s\S]{0,360}role-to-assume:/, file);
    assert.doesNotMatch(workflow, /aws-access-key-id:/, file);
  }
  const publisher = fs.readFileSync(".github/workflows/publish-ecs-images.yml", "utf8");
  assert.match(publisher, /mode=oidc[\s\S]{0,160}credential_source=github-oidc-release-deployer/);
  assert.match(publisher, /mode=keys[\s\S]{0,160}credential_source=github-access-keys/);
  assert.match(publisher, /aws-session-token: \$\{\{ secrets\.AWS_SESSION_TOKEN \}\}/);
});

test("operator documentation declares the exact non-profile verifier and checker session sources", () => {
  const rotationRunbook = fs.readFileSync("documents/SECURITY_KEY_ROTATION_RUNBOOK.md", "utf8");
  const activationRunbook = fs.readFileSync("documents/security/rls-program/FULL_DATABASE_PRODUCTION_ACTIVATION_RUNBOOK.md", "utf8");
  assert.doesNotMatch(rotationRunbook, /AWS_PROFILE=mscqr-production-ecs-exec-verifier/);
  assert.match(rotationRunbook, /--credential-source inherited-ecs-exec-verifier-session/);
  assert.match(activationRunbook, /create-production-green-stage-b-approval\.mjs[\s\S]{0,160}--credential-source inherited-checker-session/);
});

test("every direct production AWS root declares its credential provenance before invoking AWS", () => {
  const roots = [
    ["scripts/aws/verify-production-release-image-authorization.mjs", "GITHUB_OIDC_RELEASE_DEPLOYER"],
    ["scripts/aws/create-production-green-stage-b-approval.mjs", "INHERITED_CHECKER_SESSION"],
    ["scripts/aws/publish-production-green-stage-b-approval.mjs", "INHERITED_CHECKER_SESSION"],
    ["scripts/rls/create-production-rls-approval.mjs", "INHERITED_CHECKER_SESSION"],
    ["scripts/aws/verify-production-rotation-via-ecs-exec.mjs", "INHERITED_ECS_EXEC_VERIFIER_SESSION"],
    ["scripts/aws/prepare-production-ecs-runtime-consumability.mjs", "NAMED_PROFILE"],
    ["scripts/aws/production-green-stage-b-image-evidence.mjs", "NAMED_PROFILE"],
    ["scripts/aws/create-stage-b-partial-apply-recovery-attestation.mjs", "NAMED_PROFILE"],
    ["scripts/aws/check-production-green-stage-b-approval-publication.mjs", "NAMED_PROFILE"],
    ["scripts/aws/production-normal-backend-activation.mjs", "GITHUB_OIDC_RELEASE_DEPLOYER"],
    ["scripts/aws/recover-stage-b-backend-task-definition.mjs", "NAMED_PROFILE"],
    ["scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs", "GITHUB_OIDC_RELEASE_DEPLOYER"],
    ["scripts/aws/authorize-production-stage-a-production-artifacts-continuation-rebind.mjs", "GITHUB_OIDC_RELEASE_DEPLOYER"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "NAMED_PROFILE"],
    ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "NAMED_PROFILE"],
  ];
  for (const [file, source] of roots) assertLiteralIncludes(fs.readFileSync(file, "utf8"), `PRODUCTION_AWS_CREDENTIAL_SOURCE.${source}`, file);
});

test("every production activation-lifecycle reader receives an explicit source-bound AWS client", () => {
  const checker = fs.readFileSync("scripts/check-production-activation-rotation.mjs", "utf8");
  const lifecycle = fs.readFileSync("scripts/aws/manage-production-initial-activation-lifecycle.mjs", "utf8");
  assert.match(checker, /createAws = createProductionInitialActivationAws/);
  assert.match(checker, /createAws\(\{ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE\.GITHUB_OIDC_RELEASE_DEPLOYER, env \}\)/);
  assert.match(checker, /assertCompletionAbsent\(\{ aws \}\)/);
  assert.match(checker, /readClaim\(\{ aws, expected:/);
  assert.match(lifecycle, /createProductionInitialActivationAws\(\{ credentialSource: required\(values, "--credential-source"\) \}\)/);
  for (const call of ["createInitialActivationClaim({ claim, aws })", "readInitialActivationClaim({ expected, aws })", "readInitialActivationClaim({ expected: claim, aws })", "createInitialActivationCompletion({ completion, claim, claimSha256, claimVersionId: liveClaim.versionId, aws })"]) assertLiteralIncludes(lifecycle, call);
});

test("literal source assertions treat every ECMAScript regex metacharacter as text", () => {
  const literal = "\\.*+?^${}()|[]";
  assertLiteralIncludes(`before:${literal}:after`, literal);
  assert.throws(() => assertLiteralIncludes("before:ordinary:after", literal), /\\\.\*\+\?\^/);
});

test("direct Bash production AWS roots select an explicit credential source before AWS", () => {
  for (const file of ["scripts/aws/publish-ecs-images.sh", "scripts/aws/apply-ecr-repository-controls.sh", "scripts/aws/deploy-ecs-service.sh", "scripts/aws/rollback-ecs-service.sh"]) {
    const source = fs.readFileSync(file, "utf8");
    assert.match(source, /source "\$SCRIPT_DIR\/production-credential-source\.sh"/, file);
    assert.match(source, /configure_production_aws_credential_source/, file);
  }
  const contract = fs.readFileSync("scripts/aws/production-credential-source.sh", "utf8");
  assert.match(contract, /github-oidc-release-deployer/);
  assert.match(contract, /github-access-keys/);
  assert.match(contract, /named-profile/);
  assert.match(contract, /unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN/);
  assert.match(contract, /clear_production_aws_credential_overrides/);
  for (const name of Object.keys(hostileAwsOverrides).filter((name) => name !== "AWS_ENDPOINT_URL_KMS")) assertLiteralIncludes(contract, name, name);
  assert.match(contract, /compgen -A variable AWS_ENDPOINT_URL_/);
});

test("the shell credential boundary preserves OIDC or access keys, or pins a local profile without an AWS call", () => {
  const shell = "source scripts/aws/production-credential-source.sh; configure_production_aws_credential_source; printf '%s|%s|%s|%s' \"${AWS_PROFILE:-}\" \"${AWS_ACCESS_KEY_ID:-}\" \"${AWS_SESSION_TOKEN:-}\" \"${AWS_EC2_METADATA_DISABLED:-}\"";
  const oidcResult = execFileSync("bash", ["-c", shell], { encoding: "utf8", env: { ...oidc, MSCQR_AWS_CREDENTIAL_SOURCE: "github-oidc-release-deployer" } });
  assert.equal(oidcResult, `|${oidc.AWS_ACCESS_KEY_ID}|${oidc.AWS_SESSION_TOKEN}|true`);
  const keysResult = execFileSync("bash", ["-c", shell], { encoding: "utf8", env: { ...accessKeys, MSCQR_AWS_CREDENTIAL_SOURCE: "github-access-keys" } });
  assert.equal(keysResult, `|${accessKeys.AWS_ACCESS_KEY_ID}||true`);
  const localResult = execFileSync("bash", ["-c", shell], { encoding: "utf8", env: { ...oidc, MSCQR_AWS_CREDENTIAL_SOURCE: "named-profile", MSCQR_AWS_NAMED_PROFILE: "mscqr-production-release-deployer" } });
  assert.equal(localResult, "mscqr-production-release-deployer|||true");
  const overrideState = "source scripts/aws/production-credential-source.sh; configure_production_aws_credential_source; printf '%s' \"${AWS_CONFIG_FILE+x}${AWS_SHARED_CREDENTIALS_FILE+x}${AWS_ROLE_ARN+x}${AWS_WEB_IDENTITY_TOKEN_FILE+x}${AWS_ENDPOINT_URL+x}${AWS_ENDPOINT_URL_KMS+x}${AWS_CA_BUNDLE+x}${AWS_METADATA_SERVICE_TIMEOUT+x}\"";
  for (const source of ["github-oidc-release-deployer", "github-access-keys", "named-profile"]) {
    const env = { ...(source === "github-access-keys" ? accessKeys : oidc), MSCQR_AWS_CREDENTIAL_SOURCE: source, ...(source === "named-profile" ? { MSCQR_AWS_NAMED_PROFILE: "mscqr-production-release-deployer" } : {}) };
    assert.equal(execFileSync("bash", ["-c", overrideState], { encoding: "utf8", env }), "");
  }
  const strictShell = `set -e; ${shell}`;
  const failsClosed = (env, message) => assert.throws(
    () => execFileSync("bash", ["-c", strictShell], { encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"] }),
    (error) => message.test(String(error.stderr)),
  );
  failsClosed({ ...accessKeys, MSCQR_AWS_CREDENTIAL_SOURCE: "unknown" }, /must explicitly select/);
  failsClosed({ ...accessKeys, MSCQR_AWS_CREDENTIAL_SOURCE: "github-oidc-release-deployer" }, /AWS_SESSION_TOKEN is required/);
});

test("every direct AWS source in scripts/aws has an explicit audited credential boundary", () => {
  const walk = (directory) => fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]);
  const direct = walk("scripts/aws").filter((file) => /\.(mjs|sh)$/.test(file) && /(?:execFileSync|execFile|spawnSync|spawn|run)\(["']aws["']|\baws\s+(?:sts|kms|ecr|ecs|iam|s3|secretsmanager|rds|cloudtrail)/.test(fs.readFileSync(file, "utf8"))).sort();
  const classified = [
    "scripts/aws/apply-ecr-repository-controls.sh", "scripts/aws/apply-production-full-rls-release.mjs", "scripts/aws/deploy-ecs-service.sh", "scripts/aws/discover-staging-endpoints.mjs", "scripts/aws/prepare-production-backend-failed-recovery-evidence.mjs", "scripts/aws/production-cutover-production-adapters.mjs", "scripts/aws/production-dual-slot-rebaseline-contract.mjs", "scripts/aws/production-identity-adapters.mjs", "scripts/aws/production-initial-activation-lifecycle.mjs", "scripts/aws/publish-ecs-images.sh", "scripts/aws/reconcile-production-stage-a-temporary-kms-capability.mjs", "scripts/aws/recover-production-backend-health.mjs", "scripts/aws/recover-production-green-stage-a-root-drop-orphan.mjs", "scripts/aws/rollback-ecs-service.sh", "scripts/aws/staging-database-role-credentials.mjs", "scripts/aws/verify-production-dependency-closure.mjs", "scripts/aws/verify-production-rotation-via-ecs-exec.mjs",
  ].sort();
  assert.deepEqual(direct, classified);
  const boundaries = {
    "scripts/aws/apply-ecr-repository-controls.sh": /configure_production_aws_credential_source/,
    "scripts/aws/apply-production-full-rls-release.mjs": /createProductionAwsCredentialEnvironment/,
    "scripts/aws/deploy-ecs-service.sh": /configure_production_aws_credential_source/,
    "scripts/aws/discover-staging-endpoints.mjs": /--profile", C\.profile/,
    "scripts/aws/prepare-production-backend-failed-recovery-evidence.mjs": /createProductionAwsCommandRunner/,
    "scripts/aws/production-cutover-production-adapters.mjs": /createProductionAwsCredentialEnvironment/,
    "scripts/aws/production-dual-slot-rebaseline-contract.mjs": /explicit credential-bound AWS runner/,
    "scripts/aws/production-identity-adapters.mjs": /createProductionAwsCredentialEnvironment/,
    "scripts/aws/production-initial-activation-lifecycle.mjs": /createProductionAwsCredentialEnvironment/,
    "scripts/aws/publish-ecs-images.sh": /configure_production_aws_credential_source/,
    "scripts/aws/reconcile-production-stage-a-temporary-kms-capability.mjs": /buildRecoveryAwsEnvironment/,
    "scripts/aws/recover-production-backend-health.mjs": /createProductionAwsCredentialEnvironment/,
    "scripts/aws/recover-production-green-stage-a-root-drop-orphan.mjs": /buildRecoveryAwsEnvironment/,
    "scripts/aws/rollback-ecs-service.sh": /configure_production_aws_credential_source/,
    "scripts/aws/staging-database-role-credentials.mjs": /awsCliEnvironment\(\)/,
    "scripts/aws/verify-production-dependency-closure.mjs": /requireTokens/,
    "scripts/aws/verify-production-rotation-via-ecs-exec.mjs": /createProductionAwsCredentialEnvironment/,
  };
  for (const [file, boundary] of Object.entries(boundaries)) assert.match(fs.readFileSync(file, "utf8"), boundary, file);
  assert.match(fs.readFileSync("scripts/aws/verify-production-dependency-closure.mjs", "utf8"), /requireTokens/);
});
