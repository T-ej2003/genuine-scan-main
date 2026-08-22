import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { verifyProductionReleaseImageAuthorization } from "../aws/verify-production-release-image-authorization.mjs";
import { RELEASE_POLICY_SOURCES } from "../aws/validate-production-green-stage-b-permissions.mjs";
import {
  CONFIRM_ENV,
  CONFIRM_VALUE,
  DATABASE_ENV,
  runCertification,
} from "../rls/certify-full-database.mjs";
import {
  PRODUCTION_RELEASE_ADMINISTRATOR_ARN,
  PRODUCTION_RELEASE_OIDC_AUDIENCE,
  PRODUCTION_RELEASE_OIDC_PROVIDER_ARN,
  PRODUCTION_RELEASE_ROLLOUT_ENABLED,
  PRODUCTION_RELEASE_OIDC_SUBJECT,
  PRODUCTION_RELEASE_ROLE_ARN,
  PRODUCTION_RELEASE_SOURCE_TRUST_SHA256,
  assertProductionReleaseOidcRolloutEnabled,
  assertProductionReleaseOidcSubjectConfiguration,
  assertProductionReleaseOidcSourceContract,
  assertProductionReleaseTrustPolicy,
  assertReleaseGateProductionIdentity,
  buildProductionReleaseOidcAttemptManifest,
  classifyProductionReleaseTrustPolicy,
  convergeAndEnableProductionReleaseOidc,
  readAndAssertLiveProductionReleaseTrust,
  convergeProductionReleaseOidcTrust,
  evaluateProductionReleaseOidcClaims,
  readProductionReleaseTrustPolicy,
} from "../aws/production-release-oidc-contract.mjs";

const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
const parsedWorkflow = yaml.load(workflow);
const rateLimitEnforcementTest = fs.readFileSync("backend/tests/rateLimitEnforcement.test.js", "utf8");
const permissionManifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));

test("Release Gate uses the exact production environment OIDC identity", () => {
  assert.equal(assertProductionReleaseOidcSourceContract(permissionManifest), true);
  assert.deepEqual(assertProductionReleaseOidcSubjectConfiguration(), { repository: "T-ej2003/genuine-scan-main", environment: "production", subject: PRODUCTION_RELEASE_OIDC_SUBJECT, useDefault: true, immutableSubjects: false });
  const wrongSubjectConfiguration = JSON.parse(fs.readFileSync("documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json", "utf8"));
  wrongSubjectConfiguration.repositoryOidcSubjectTemplate.use_default = false;
  assert.throws(() => assertProductionReleaseOidcSubjectConfiguration(wrongSubjectConfiguration), /subject configuration/);
  assert.equal(assertReleaseGateProductionIdentity(parsedWorkflow), true);
  const expected = { providerArn: PRODUCTION_RELEASE_OIDC_PROVIDER_ARN, audience: PRODUCTION_RELEASE_OIDC_AUDIENCE, subject: PRODUCTION_RELEASE_OIDC_SUBJECT };
  assert.equal(evaluateProductionReleaseOidcClaims(expected), true);
  for (const claims of [
    { ...expected, providerArn: "arn:aws:iam::368992683803:oidc-provider/example.invalid" },
    { ...expected, subject: "repo:other/genuine-scan-main:environment:production" },
    { ...expected, subject: "repo:T-ej2003/other:environment:production" },
    { ...expected, subject: "repo:T-ej2003/genuine-scan-main:environment:staging" },
    { ...expected, subject: "repo:T-ej2003/genuine-scan-main:ref:refs/heads/main" },
    { ...expected, subject: "repo:T-ej2003/genuine-scan-main:pull_request" },
    { ...expected, subject: "repo:T-ej2003/genuine-scan-main:ref:refs/heads/codex/merge-main-ours-test2" },
    { ...expected, audience: "other-audience" },
  ]) assert.equal(evaluateProductionReleaseOidcClaims(claims), false);

  for (const subject of ["*", "repo:T-ej2003/*", "repo:*/genuine-scan-main:environment:production"]) {
    const trust = readProductionReleaseTrustPolicy();
    trust.Statement[1].Condition.StringEquals["token.actions.githubusercontent.com:sub"] = subject;
    assert.throws(() => assertProductionReleaseTrustPolicy(trust), /exact production-environment OIDC trust/);
  }

  const liveTrust = readAndAssertLiveProductionReleaseTrust({ run: () => JSON.stringify({ Role: { Arn: PRODUCTION_RELEASE_ROLE_ARN, AssumeRolePolicyDocument: readProductionReleaseTrustPolicy() } }) });
  assert.deepEqual(liveTrust, { roleArn: PRODUCTION_RELEASE_ROLE_ARN, liveTrustCanonicalSha256: PRODUCTION_RELEASE_SOURCE_TRUST_SHA256, sourceLiveMatch: true });
  assert.throws(() => readAndAssertLiveProductionReleaseTrust(), /Governed administrator AWS runner/);
  assert.throws(() => readAndAssertLiveProductionReleaseTrust({ run: () => { throw new Error("GetRole denied"); } }), /GetRole denied/);
  assert.throws(() => readAndAssertLiveProductionReleaseTrust({ run: () => JSON.stringify({ Role: { Arn: PRODUCTION_RELEASE_ROLE_ARN, AssumeRolePolicyDocument: "%E0%A4%A" } }) }), /malformed/);
  assert.throws(() => readAndAssertLiveProductionReleaseTrust({ run: () => JSON.stringify({ Role: { Arn: "arn:aws:iam::368992683803:role/github-actions-mscqr-deploy", AssumeRolePolicyDocument: readProductionReleaseTrustPolicy() } }) }), /role ARN is not canonical/);

  for (const roleArn of ["arn:aws:iam::368992683803:role/github-actions-mscqr-deploy", "arn:aws:iam::368992683803:role/arbitrary"]) {
    const changed = structuredClone(parsedWorkflow);
    changed.jobs["deploy-production-ecs"].env.PRODUCTION_RELEASE_ROLE_ARN = roleArn;
    assert.throws(() => assertReleaseGateProductionIdentity(changed), /canonical release-deployer/);
  }
  const wrongEnvironment = structuredClone(parsedWorkflow);
  wrongEnvironment.jobs["deploy-production-ecs"].environment = "staging";
  assert.throws(() => assertReleaseGateProductionIdentity(wrongEnvironment), /environment binding/);

  const missingMfa = readProductionReleaseTrustPolicy();
  delete missingMfa.Statement[0].Condition;
  assert.throws(() => assertProductionReleaseTrustPolicy(missingMfa), /exact MFA handoff/);
  assert.doesNotMatch(workflow, /AWS_ROLE_TO_ASSUME|github-actions-mscqr-deploy|aws-access-key-id|aws-secret-access-key/);
  assert.match(fs.readFileSync("documents/ops/MSCQR_PRODUCTION_CI_CD_AND_INTEGRATION_RUNBOOK_2026-07-03.md", "utf8"), /does not accept a role variable or static AWS credentials/);
  assert.match(fs.readFileSync("documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json", "utf8"), /source-controlled exact mscqr-production-release-deployer ARN/);
});

test("governed administrator convergence requires live readback before source enables an AWS-authorized OIDC attempt", () => {
  const target = readProductionReleaseTrustPolicy();
  const mfaOnly = { Version: target.Version, Statement: [target.Statement[0]] };
  const sourceSha = "1".repeat(40);
  const now = "2026-08-22T01:00:00.000Z";
  const runner = (initial, { readback = target, callerArn = PRODUCTION_RELEASE_ADMINISTRATOR_ARN, account = "368992683803", roleArn = PRODUCTION_RELEASE_ROLE_ARN, encoded = false, updateThrows = false, readbackThrows = false } = {}) => {
    let trust = structuredClone(initial);
    const calls = [];
    return {
      calls,
      run(args) {
        calls.push(args);
        if (args[0] === "sts") return JSON.stringify({ Account: account, Arn: callerArn });
        if (args[1] === "get-role") {
          const readCount = calls.filter((entry) => entry[1] === "get-role").length;
          if (readCount > 1 && readbackThrows) throw new Error("GetRole denied");
          const document = readCount > 1 ? readback : trust;
          const represented = encoded ? { ...document, Statement: document.Statement.map((statement) => ({ ...statement, Action: [statement.Action], Principal: Object.fromEntries(Object.entries(statement.Principal).map(([key, value]) => [key, [value]])), Condition: Object.fromEntries(Object.entries(statement.Condition).map(([operator, values]) => [operator, Object.fromEntries(Object.entries(values).map(([key, value]) => [key, [value]]))])) })) } : document;
          return JSON.stringify({ Role: { Arn: roleArn, AssumeRolePolicyDocument: encoded ? encodeURIComponent(JSON.stringify(represented)) : represented } });
        }
        if (args[1] === "update-assume-role-policy") { trust = structuredClone(target); if (updateThrows) throw new Error("simulated lost update response"); return ""; }
        throw new Error(`Unexpected AWS call: ${args.join(" ")}`);
      },
    };
  };

  const migration = runner(mfaOnly, { encoded: true });
  let publishedRollout;
  const migrated = convergeAndEnableProductionReleaseOidc({ run: migration.run, sourceSha, writeRolloutManifest: (value) => { publishedRollout = value; } });
  assert.equal(migrated.status, "LIVE_TRUST_VERIFIED_BY_AWS");
  assert.equal(migrated.initialState, "MFA_ONLY");
  assert.equal(migrated.iamWrites, 1);
  assert.equal(migrated.liveTrustCanonicalSha256, PRODUCTION_RELEASE_SOURCE_TRUST_SHA256);
  assert.equal(Object.hasOwn(migrated, "evidenceSha256"), false);
  assert.equal(Object.hasOwn(migrated, "readbackVerified"), false);
  assert.equal(migration.calls.filter((args) => args[1] === "update-assume-role-policy").length, 1);
  assert.equal(migration.calls.filter((args) => args[1] === "get-role").length, 2);
  const updateCall = migration.calls.find((args) => args[1] === "update-assume-role-policy");
  const updateDocument = JSON.parse(updateCall[updateCall.indexOf("--policy-document") + 1]);
  assert.equal(updateCall.some((value) => value.startsWith?.("file://")), false);
  assert.doesNotThrow(() => assertProductionReleaseTrustPolicy(updateDocument));
  const rollout = buildProductionReleaseOidcAttemptManifest();
  assert.deepEqual(publishedRollout, rollout);
  assert.equal(assertProductionReleaseOidcRolloutEnabled(rollout).enabled, true);
  const forgedHashedEvidence = { ...rollout, schemaVersion: 1, activation: { administratorCallerArn: PRODUCTION_RELEASE_ADMINISTRATOR_ARN, sourceSha, observedAt: now, readbackVerified: true, evidenceSha256: createHash("sha256").update("attacker-controlled").digest("hex") } };
  assert.throws(() => assertProductionReleaseOidcRolloutEnabled(forgedHashedEvidence), /manifest.*reviewed role and trust|fields are not exact/);
  assert.throws(() => assertProductionReleaseOidcRolloutEnabled({ ...rollout, readbackVerified: true }), /fields are not exact/);
  assert.throws(() => assertProductionReleaseOidcRolloutEnabled({ ...rollout, sourceSha: "0".repeat(40), observedAt: "2020-01-01T00:00:00.000Z" }), /fields are not exact/);
  assert.throws(() => assertProductionReleaseOidcRolloutEnabled({ ...rollout, roleArn: "arn:aws:iam::000000000000:role/mscqr-production-release-deployer" }), /reviewed role and trust/);

  const reconciled = convergeProductionReleaseOidcTrust({ run: runner(mfaOnly, { updateThrows: true }).run, sourceSha });
  assert.equal(reconciled.iamWrites, 1);

  const publicationFailure = runner(mfaOnly);
  assert.throws(() => convergeAndEnableProductionReleaseOidc({ run: publicationFailure.run, sourceSha, writeRolloutManifest: () => { throw new Error("source publication failed"); } }), /source publication failed/);
  let retryPublished = false;
  const publicationRetry = convergeAndEnableProductionReleaseOidc({ run: publicationFailure.run, sourceSha, writeRolloutManifest: () => { retryPublished = true; } });
  assert.equal(publicationRetry.initialState, "TARGET");
  assert.equal(publicationRetry.iamWrites, 0);
  assert.equal(retryPublished, true);

  const alreadyLive = runner(target);
  const noOp = convergeProductionReleaseOidcTrust({ run: alreadyLive.run, sourceSha });
  assert.equal(noOp.initialState, "TARGET");
  assert.equal(noOp.iamWrites, 0);
  assert.equal(alreadyLive.calls.some((args) => args[1] === "update-assume-role-policy"), false);
  assert.equal(alreadyLive.calls.filter((args) => args[1] === "get-role").length, 2);

  assert.throws(() => assertProductionReleaseOidcRolloutEnabled({ ...rollout, status: "PENDING_ADMINISTRATOR_CONVERGENCE" }), /disabled until governed administrator convergence/);
  const partial = runner(mfaOnly, { readback: mfaOnly });
  let partialPublished = false;
  assert.throws(() => convergeAndEnableProductionReleaseOidc({ run: partial.run, sourceSha, writeRolloutManifest: () => { partialPublished = true; } }), (error) => error.iamWrites === 1 && /exact MFA handoff/.test(error.message));
  assert.equal(partialPublished, false);
  assert.throws(() => convergeProductionReleaseOidcTrust({ run: runner(mfaOnly, { readbackThrows: true }).run, sourceSha }), (error) => error.iamWrites === 1 && /GetRole denied/.test(error.message));
  assert.throws(() => convergeProductionReleaseOidcTrust({ run: migration.run, sourceSha: "wrong" }), /exact protected source SHA/);
  assert.throws(() => convergeProductionReleaseOidcTrust({ run: runner(mfaOnly, { account: "000000000000" }).run, sourceSha }), /exact governed root administrator/);
  assert.throws(() => convergeProductionReleaseOidcTrust({ run: runner(mfaOnly, { callerArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator" }).run, sourceSha }), /exact governed root administrator/);
  assert.throws(() => convergeProductionReleaseOidcTrust({ run: runner(mfaOnly, { roleArn: "arn:aws:iam::368992683803:role/arbitrary" }).run, sourceSha }), /wrong role/);
  const skippedConvergence = spawnSync(process.execPath, ["scripts/aws/converge-production-release-oidc-trust.mjs", "--mode", "assert-release-gate-enabled"], { encoding: "utf8" });
  assert.notEqual(skippedConvergence.status, 0);
  assert.match(skippedConvergence.stderr, /disabled until governed administrator convergence/);
  const injectedRole = spawnSync(process.execPath, ["scripts/aws/converge-production-release-oidc-trust.mjs", "--mode", "assert-release-gate-enabled", "--role", "arn:aws:iam::368992683803:role/arbitrary"], { encoding: "utf8" });
  assert.notEqual(injectedRole.status, 0);
  assert.match(injectedRole.stderr, /Unsupported argument.*--role/);
  const directActivation = spawnSync(process.execPath, ["scripts/aws/converge-production-release-oidc-trust.mjs", "--mode", "activate", "--source-sha", sourceSha], { encoding: "utf8" });
  assert.notEqual(directActivation.status, 0);
  assert.match(directActivation.stderr, /mode must be converge/);

  const broad = [
    { ...target.Statement[1], Principal: { Federated: "*" } },
    { ...target.Statement[1], Action: "*" },
    { ...target.Statement[1], Condition: { StringEquals: { ...target.Statement[1].Condition.StringEquals, "token.actions.githubusercontent.com:sub": "*" } } },
    { ...target.Statement[1], Condition: { StringEquals: { ...target.Statement[1].Condition.StringEquals, "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:ref:refs/heads/main" } } },
    { ...target.Statement[1], Condition: { StringEquals: { ...target.Statement[1].Condition.StringEquals, "token.actions.githubusercontent.com:aud": "wrong" } } },
    { ...target.Statement[1], Principal: { Federated: "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com" } },
  ];
  for (const oidc of broad) assert.throws(() => classifyProductionReleaseTrustPolicy({ Version: target.Version, Statement: [target.Statement[0], oidc] }), /neither the exact MFA-only/);
  assert.throws(() => classifyProductionReleaseTrustPolicy({ Version: target.Version, Statement: [...target.Statement, { ...target.Statement[1], Sid: "UnexpectedFederatedTrust" }] }), /neither the exact MFA-only/);
  assert.throws(() => classifyProductionReleaseTrustPolicy({ Version: target.Version, Statement: [target.Statement[1]] }), /neither the exact MFA-only/);

  const steps = parsedWorkflow.jobs["deploy-production-ecs"].steps;
  assert.ok(steps.findIndex(({ name }) => name === "Require enabled production OIDC source phase") < steps.findIndex(({ uses }) => uses === "aws-actions/configure-aws-credentials@v6"));
  assert.deepEqual(parsedWorkflow.on.workflow_dispatch.inputs.release_mode.options, ["normal", "backend-health-recovery", "rotation-overlap", "rotation-cleanup"]);
  assert.equal(rollout.status, PRODUCTION_RELEASE_ROLLOUT_ENABLED);
  assert.match(JSON.stringify(permissionManifest.principalContracts.releaseDeployer), /production:release-oidc-trust/);
  const convergenceCli = fs.readFileSync("scripts/aws/converge-production-release-oidc-trust.mjs", "utf8");
  assert.doesNotMatch(convergenceCli, /evidenceSha256|readbackVerified|--evidence|--output/);
  assert.match(convergenceCli, /convergeAndEnableProductionReleaseOidc[\s\S]*writeRolloutManifest/);
  assert.match(convergenceCli, /authority: "AWS_IAM_GET_ROLE_AND_STS"/);
});

test("release gate exposes one bounded backend health recovery mode", () => {
  assert.match(workflow, /- backend-health-recovery/);
  assert.match(workflow, /backend-health-recovery\)[\s\S]*BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN[\s\S]*BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256[\s\S]*BACKEND_RECOVERY_APPROVAL_SHA256/);
  const recoveryCase = workflow.match(/backend-health-recovery\)([\s\S]*?)\n\s*;;/u)?.[1] || "";
  assert.doesNotMatch(recoveryCase, /check:rotation-evidence-freshness/);
  assert.match(workflow, /Execute governed legacy backend health recovery[\s\S]*recover-production-backend-health\.mjs[\s\S]*--execute/);
  assert.match(workflow, /Upload backend health recovery evidence\n\s*if: \$\{\{ always\(\) && inputs\.release_mode == 'backend-health-recovery' \}\}[\s\S]*backend-health-recovery-evidence[\s\S]*if-no-files-found: ignore/);
  assert.match(workflow, /--health-url "\$\{\{ env\.PUBLIC_BASE_URL \}\}\/api\/health\/ready"/);
  assert.match(workflow, /deploy-production-ecs:[\s\S]*environment: production/);
  assert.match(workflow, /Authenticate production environment approval boundary[\s\S]*approval_dir="\$RUNNER_TEMP\/production-environment-approval"[\s\S]*! -d "\$approval_dir" \|\| -L "\$approval_dir"[\s\S]*install -d -m 700 -- "\$approval_dir"[\s\S]*stat -c '%a'[\s\S]*stat -c '%u'[\s\S]*production-github-environment-approval\.mjs[\s\S]*--environment production[\s\S]*--workflow-ref "\$GITHUB_WORKFLOW_REF"[\s\S]*--event-name "\$GITHUB_EVENT_NAME"[\s\S]*--workflow-run-id "\$GITHUB_RUN_ID"/);
  assert.doesNotMatch(workflow, /evidence_file="\$RUNNER_TEMP\/production-environment-approval\.json"/);
  assert.match(workflow, /Verify checksum-bound production RLS package[\s\S]*npm run rls:full-verify[\s\S]*stageBApprovalIdForReleaseSha/);
  assert.doesNotMatch(workflow, /secretsmanager get-secret-value|PRODUCTION_RLS_APPROVAL_SECRET_ARN|production-rls-approval\.json/);
  assert.doesNotMatch(workflow, /production-github-environment-approval\.mjs[^\n]*--github-token/);
  assert.match(workflow, /--environment-approval "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_file \}\}"[\s\S]*--environment-approval-sha256 "\$\{\{ steps\.production-environment-approval\.outputs\.evidence_sha256 \}\}"/);
  assert.ok(workflow.indexOf("Authenticate production environment approval boundary") < workflow.indexOf("Configure AWS credentials via OIDC"));
});

test("backend recovery cannot enter rotation, frontend, worker, or normal release steps", () => {
  assert.doesNotMatch(workflow, /if: \$\{\{ inputs\.release_mode != 'normal' \}\}/);
  assert.match(workflow, /Deploy rotation transition backend ECS service\n\s*if: \$\{\{ inputs\.release_mode == 'rotation-overlap' \|\| inputs\.release_mode == 'rotation-cleanup' \}\}/);
  assert.doesNotMatch(workflow, /Deploy frontend ECS service/);
  assert.doesNotMatch(workflow, /Deploy worker ECS service|PRODUCTION_WORKER_SERVICE_NAME/);
});

test("normal release consumes separated publisher and checker outputs under the deployment principal", () => {
  assert.match(workflow, /normal_image_authorization_json/);
  assert.match(workflow, /verify-production-release-image-authorization\.mjs/);
  assert.match(workflow, /PRODUCTION_RLS_CANARY_IMAGE/);
  assert.match(workflow, /PRODUCTION_FRONTEND_TASK_DEFINITION: mscqr-frontend:20/);
  assert.doesNotMatch(workflow, /amazon-ecr-login|setup-buildx|publish-ecs-images|apply-ecr-repository-controls/);
  assert.doesNotMatch(workflow, /secretsmanager get-secret-value|PRODUCTION_RLS_APPROVAL_SECRET_ARN/);
  assert.match(workflow, /role-to-assume: \$\{\{ env\.PRODUCTION_RELEASE_ROLE_ARN \}\}/);
});

test("normal release identity routing rejects both under-privilege and cross-phase privilege inheritance", () => {
  const sourceSha = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
  const fixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha });
  const refs = verifyProductionReleaseImageAuthorization({ authorization: fixture.authorization, sourceSha, now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence });
  assert.deepEqual(Object.keys(refs).sort(), ["backend", "rls-canary", "rls-executor", "worker"]);
  assert.match(refs.backend, /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:/);
  assert.throws(() => verifyProductionReleaseImageAuthorization({ authorization: fixture.authorization, sourceSha: "b".repeat(40), now: fixture.now, verifyImageEvidence: fixture.verifyImageEvidence }), /source SHA/);

  const releaseStatements = RELEASE_POLICY_SOURCES.flatMap(({ sourcePath }) => JSON.parse(fs.readFileSync(sourcePath, "utf8")).Statement || []);
  const releaseActions = releaseStatements.flatMap(({ Effect, Action }) => Effect === "Allow" ? (Array.isArray(Action) ? Action : [Action]) : []);
  for (const action of ["ecr:GetAuthorizationToken", "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"]) assert.equal(releaseActions.includes(action), false, action);
  assert.equal(releaseActions.includes("secretsmanager:GetSecretValue") && releaseStatements.some(({ Resource }) => JSON.stringify(Resource).includes("phase2/approval")), false);

  const publisher = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json", "utf8"));
  const publisherAllows = publisher.Statement.filter(({ Effect }) => Effect === "Allow").flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  assert.equal(publisherAllows.includes("ecr:PutImage"), true);
  assert.equal(publisher.Statement.some(({ Effect, Action }) => Effect === "Deny" && JSON.stringify(Action).includes("ecs:*") && JSON.stringify(Action).includes("secretsmanager:*")), true);
  assert.doesNotMatch(workflow, /AWS_ROLE_TO_ASSUME|aws-access-key-id|aws-secret-access-key/);
});

test("backend validation closes its shared Redis client before advancing", () => {
  assert.match(workflow, /REDIS_URL: redis:\/\/127\.0\.0\.1:6379\/0/);
  assert.match(rateLimitEnforcementTest, /closeRedisConnections/);
  assert.match(rateLimitEnforcementTest, /\.finally\(closeRedisConnections\)/);
});

test("release gate certifies the same disposable PostgreSQL database used by integration", () => {
  const steps = parsedWorkflow.jobs["deploy-production-ecs"].steps;
  const integration = steps.find((step) => step.name === "Disposable integration tests").run;
  const certification = steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").run;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-release-gate-rls-"));
  const bin = path.join(directory, "bin");
  const githubEnv = path.join(directory, "github-env");
  const invocations = path.join(directory, "npm-invocations");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "npm"), `#!/bin/sh\nprintf '%s\\t%s\\t%s\\t%s\\n' "$*" "\${${CONFIRM_ENV}:-}" "\${${DATABASE_ENV}:-}" "\${P2_TEST_DATABASE_ADMIN_URL:-}" >> "$INVOCATION_LOG"\n`);
  fs.chmodSync(path.join(bin, "npm"), 0o700);

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    GITHUB_ENV: githubEnv,
    INVOCATION_LOG: invocations,
    P2_TEST_DB_PROTOCOL: "postgresql",
    P2_TEST_DB_USER: "mscqr_rls_cert_admin",
    P2_TEST_DB_HOST: "127.0.0.1",
    P2_TEST_DB_PORT: "5432",
    P2_TEST_DB_NAME: "mscqr_p2_integration_test",
  };

  try {
    const integrationResult = spawnSync("bash", ["-e"], { input: integration, env, encoding: "utf8" });
    assert.equal(integrationResult.status, 0, integrationResult.stderr);
    const [name, adminUrl] = fs.readFileSync(githubEnv, "utf8").trim().split("=");
    assert.equal(name, "P2_TEST_DATABASE_ADMIN_URL");
    assert.equal(adminUrl, "postgresql://mscqr_rls_cert_admin@127.0.0.1:5432/mscqr_p2_integration_test");
    assert.equal(parsedWorkflow.jobs["deploy-production-ecs"].services.postgres.env.POSTGRES_USER, "mscqr_rls_cert_admin");
    assert.match(parsedWorkflow.jobs["deploy-production-ecs"].services.postgres.options, /pg_isready -U mscqr_rls_cert_admin/);

    const certificationResult = spawnSync("bash", ["-e"], {
      input: certification,
      env: { ...env, [name]: adminUrl },
      encoding: "utf8",
    });
    assert.equal(certificationResult.status, 0, certificationResult.stderr);
    const calls = fs.readFileSync(invocations, "utf8").trim().split("\n").map((line) => line.split("\t"));
    assert.deepEqual(calls.map(([command]) => command), ["run test:integration:ci", "run rls:full-verify", "run rls:full-certify"]);
    assert.deepEqual(calls.at(-1), ["run rls:full-certify", CONFIRM_VALUE, adminUrl, adminUrl]);
    assert.doesNotMatch(certification, /\|\|\s*true/);

    assert.throws(() => runCertification(adminUrl, {}), /Set MSCQR_FULL_RLS_CERTIFICATION_CONFIRM/);
    assert.throws(() => runCertification("", { [CONFIRM_ENV]: CONFIRM_VALUE }), /valid local PostgreSQL admin URL/);
    assert.throws(
      () => runCertification("postgresql://postgres@production.example.com/mscqr_full_rls_ci", { [CONFIRM_ENV]: CONFIRM_VALUE }),
      /loopback-local/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

const parseRedisCommand = (buffer) => {
  const headerEnd = buffer.indexOf("\r\n");
  if (headerEnd < 0 || buffer[0] !== 42) return null;
  const count = Number(buffer.subarray(1, headerEnd));
  const parts = [];
  let offset = headerEnd + 2;
  for (let index = 0; index < count; index += 1) {
    const lengthEnd = buffer.indexOf("\r\n", offset);
    if (lengthEnd < 0 || buffer[offset] !== 36) return null;
    const length = Number(buffer.subarray(offset + 1, lengthEnd));
    const valueEnd = lengthEnd + 2 + length;
    if (buffer.length < valueEnd + 2) return null;
    parts.push(buffer.subarray(lengthEnd + 2, valueEnd).toString());
    offset = valueEnd + 2;
  }
  return { parts, rest: buffer.subarray(offset) };
};

test("Redis-backed incident tests advance and exit naturally", async () => {
  const build = spawnSync("npm", ["--prefix", "backend", "run", "build"], { encoding: "utf8" });
  assert.equal(build.status, 0, build.stderr || build.stdout);

  const counters = new Map();
  const expiries = new Map();
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    let pending = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      for (let parsed; (parsed = parseRedisCommand(pending)); pending = parsed.rest) {
        const [rawCommand, key, rawValue] = parsed.parts;
        const command = rawCommand.toUpperCase();
        if (command === "INCR") {
          const value = (counters.get(key) || 0) + 1;
          counters.set(key, value);
          socket.write(`:${value}\r\n`);
        } else if (command === "PTTL") {
          socket.write(`:${expiries.has(key) ? Math.max(0, expiries.get(key) - Date.now()) : -1}\r\n`);
        } else if (command === "PEXPIRE") {
          expiries.set(key, Date.now() + Number(rawValue));
          socket.write(":1\r\n");
        } else if (command === "INFO") {
          const info = "# Server\r\nredis_version:8.0.0\r\n";
          socket.write(`$${Buffer.byteLength(info)}\r\n${info}\r\n`);
        } else if (command === "PING") {
          socket.write("+PONG\r\n");
        } else {
          socket.write("+OK\r\n");
          if (command === "QUIT") socket.end();
        }
      }
    });
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn("bash", ["-c", `"${process.execPath}" tests/incidentMvp.test.js && "${process.execPath}" tests/incidentPdfExport.test.js`], {
    cwd: "backend",
    detached: true,
    env: { ...process.env, REDIS_URL: `redis://127.0.0.1:${port}/0`, REDIS_TLS: "false" },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  let timedOut = false;
  const watchdog = setTimeout(() => {
    timedOut = true;
    process.kill(-child.pid, "SIGTERM");
  }, 15_000);

  try {
    const [code, signal] = await once(child, "close");
    assert.equal(timedOut, false, "incident test chain did not terminate naturally");
    assert.equal(signal, null, `incident test chain was terminated by ${signal}`);
    assert.equal(code, 0, stderr || stdout);
    assert.match(stdout, /incident MVP tests passed/);
    assert.match(stdout, /incident PDF export tests passed/);
  } finally {
    clearTimeout(watchdog);
    for (const socket of sockets) socket.destroy();
    server.close();
    await once(server, "close");
  }
});

test("release gate heredocs parse and backend recovery lifecycle validation executes", () => {
  const heredocSteps = Object.values(parsedWorkflow.jobs).flatMap((job) => job.steps || []).filter((step) => step.run?.includes("<<"));
  for (const step of heredocSteps) {
    const parsed = spawnSync("bash", ["-n"], { input: step.run, encoding: "utf8" });
    assert.equal(parsed.status, 0, `${step.name}: ${parsed.stderr}`);
  }

  const lifecycle = parsedWorkflow.jobs["resolve-deploy-target"].steps.find((step) => step.name === "Validate production release lifecycle mode").run;
  const image = JSON.stringify({ valid: true });
  const approval = JSON.stringify({ approvedBy: "T-ej2003" });
  const env = {
    ...process.env,
    RELEASE_MODE: "backend-health-recovery",
    BACKEND_RECOVERY_CURRENT_TASK_DEFINITION_ARN: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47",
    BACKEND_RECOVERY_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_JSON: image,
    BACKEND_RECOVERY_IMAGE_AUTHORIZATION_SHA256: createHash("sha256").update(image).digest("hex"),
    BACKEND_RECOVERY_APPROVAL_JSON: approval,
    BACKEND_RECOVERY_APPROVAL_SHA256: createHash("sha256").update(approval).digest("hex"),
  };
  assert.equal(spawnSync("bash", ["-e"], { input: lifecycle, env }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, BACKEND_RECOVERY_APPROVAL_SHA256: "0".repeat(64) } }).status, 0);
  assert.notEqual(spawnSync("bash", ["-e"], { input: lifecycle, env: { ...env, RELEASE_MODE: "unsupported" } }).status, 0);
});
