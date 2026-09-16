import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { parseAppOnlyVerifierPreparationArgs } from "../aws/prepare-production-app-only-verifier.mjs";
import { parseAppOnlyVerifierExecutionArgs } from "../aws/run-production-app-only-verifier.mjs";
import { parseAppOnlyExecutionArgs, assertAppOnlyReleaseInputs } from "../aws/run-production-app-only-deployment.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY_OIDC_WORKFLOWS, appOnlyProductionOidcTrust } from "../aws/production-app-only-policy.mjs";

test("OIDC workflow claims bind reviewed reusable code and preserve protected approval and concurrency", () => {
  for (const [role, names] of Object.entries(APP_ONLY_OIDC_WORKFLOWS)) for (const name of names) {
    const wrapper = yaml.load(fs.readFileSync(`.github/workflows/${name}.yml`, "utf8"));
    const operation = yaml.load(fs.readFileSync(`.github/workflows/${name}-operation.yml`, "utf8"));
    assert.deepEqual(Object.keys(wrapper.jobs), ["operation"]);
    assert.equal(wrapper.jobs.operation.uses, `./.github/workflows/${name}-operation.yml`);
    assert.equal(wrapper.concurrency.group, "production-deploy");
    assert.equal(wrapper.concurrency["cancel-in-progress"], false);
    assert.equal(operation.concurrency, undefined, "Reusable job cannot deadlock its caller concurrency group");
    assert.deepEqual(Object.keys(operation.on), ["workflow_call"]);
    assert.deepEqual(operation.on.workflow_call.inputs, wrapper.on.workflow_dispatch.inputs);
    const jobs = Object.values(operation.jobs).filter((job) => job.steps?.some((step) => step.with?.["role-to-assume"]?.endsWith(`/${role}`)));
    assert.ok(jobs.length > 0);
    for (const job of jobs) assert.equal(job.environment, "production");
    assert.ok(appOnlyProductionOidcTrust(role).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"]
      .includes(`T-ej2003/genuine-scan-main/.github/workflows/${name}-operation.yml@refs/heads/main`));
  }
});

test("release handoff rejects substituted permission and deployment identities even when rehashed", () => {
  const source = "a".repeat(40), preparationSha256 = "b".repeat(64), verifierArn = "authenticated-verifier";
  const seal = (body, field) => ({ ...body, [field]: canonicalSha256(body) });
  const permission = { kind: "APP_ONLY_PERMISSION_PREPARATION", sourceSha: source, phase: "DEPLOYER", eligibilitySha256: preparationSha256, verifierArn };
  const body = { schemaVersion: 1, kind: "APP_ONLY_RELEASE_INPUTS", sourceSha: source,
    deployment: { preparation: { preparationSha256 }, verifierTaskDefinitionArn: verifierArn },
    permissionPreparation: seal(permission, "preparationSha256") };
  assertAppOnlyReleaseInputs(seal(body, "resultSha256"), source);
  for (const field of ["kind", "sourceSha", "phase", "eligibilitySha256", "verifierArn"]) {
    const changed = { ...body, permissionPreparation: seal({ ...permission, [field]: "substitution" }, "preparationSha256") };
    assert.throws(() => assertAppOnlyReleaseInputs(seal(changed, "resultSha256"), source), field);
  }
  for (const field of ["schemaVersion", "kind", "sourceSha"])
    assert.throws(() => assertAppOnlyReleaseInputs(seal({ ...body, [field]: "substitution" }, "resultSha256"), source));
  assert.throws(() => assertAppOnlyReleaseInputs({ ...seal(body, "resultSha256"), resultSha256: "c".repeat(64) }, source));
  assert.throws(() => assertAppOnlyReleaseInputs(seal({ ...body, extra: true }, "resultSha256"), source));
});

test("application execution binds exact workflow, source and private or immutable artifact handoffs", () => {
  const source = "a".repeat(40), hash = "b".repeat(64);
  const reference = JSON.stringify({ sourceSha: source, runId: "12", runAttempt: "1", artifactId: "34", artifactDigest: `sha256:${hash}`, fileSha256: hash });
  for (const [mode, workflow] of [["prepare", "prepare-production-app-only-deployment"], ["provision", "provision-production-app-only-deployer"], ["deploy", "deploy-production-app-only"]]) {
    const args = ["--mode", mode, "--source-sha", source, ...(mode === "prepare" ? ["--input", "/private/input.json", "--input-sha256", hash]
      : ["--preparation-reference", reference, "--approval", "/private/approval.json", "--approval-sha256", hash]), ...(mode === "deploy" ? ["--provisioning-reference", reference] : [])];
    const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_SHA: source,
      GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: "56", GITHUB_WORKFLOW_REF: `T-ej2003/genuine-scan-main/.github/workflows/${workflow}.yml@refs/heads/main` };
    assert.equal(parseAppOnlyExecutionArgs(args, env).mode, mode);
    for (const field of Object.keys(env)) assert.throws(() => parseAppOnlyExecutionArgs(args, { ...env, [field]: "wrong" }));
    for (const option of ["--command", "--environment", "--task-definition", "--role", "--cluster", "--rollback-arn"])
      assert.throws(() => parseAppOnlyExecutionArgs([...args, option, "attacker"], env));
    assert.throws(() => parseAppOnlyExecutionArgs(args.slice(0, -2), env));
    assert.ok(JSON.stringify(args).length < 2048);
  }
});

test("application and IAM execution use separate protected approvals and isolated roles", () => {
  for (const [workflowName, mode, role] of [["provision-production-app-only-deployer", "provision", "permission-provisioner"], ["deploy-production-app-only", "deploy", "deployer"]]) {
    const source = fs.readFileSync(`.github/workflows/${workflowName}-operation.yml`, "utf8"), workflow = yaml.load(source);
    const job = workflow.jobs[mode];
    assert.equal(job.environment, "production"); assert.equal(job.needs, "review");
    assert.equal(workflow.jobs.review.environment, undefined); assert.equal(workflow.concurrency, undefined);
    assert.equal(workflow.concurrency, undefined);
    const roles = job.steps.filter((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@"));
    assert.equal(roles.length, 1); assert.equal(roles[0].with["role-to-assume"], `arn:aws:iam::368992683803:role/mscqr-production-app-only-${role}`);
    assert.equal(roles[0].with["unset-current-credentials"], true);
    assert.match(source, /--require-actual-approval/); assert.match(source, /if: always\(\).*steps\.operation\.outputs\.journal/);
    assert.doesNotMatch(source, /run-task|execute-command|terraform apply|release-gate|tfvars_base64/);
    assert.deepEqual(Object.keys(workflow.on.workflow_call.inputs).sort(), ["preparation_reference", "source_sha", ...(mode === "deploy" ? ["provisioning_reference"] : [])].sort());
    for (const phase of Object.values(workflow.jobs)) for (const step of phase.steps)
      if (step.run) assert.doesNotMatch(step.run, /\$\{\{\s*inputs\./);
  }
});

test("verifier execution rejects overrides, workflow reruns and unbound private handoffs", () => {
  const source = "a".repeat(40), hash = "b".repeat(64);
  const reference = JSON.stringify({ sourceSha: source, runId: "12", runAttempt: "1", artifactId: "34", artifactDigest: `sha256:${hash}`, fileSha256: hash });
  const args = ["--mode", "register", "--source-sha", source, "--preparation-reference", reference, "--approval", "/private/approval.json", "--approval-sha256", hash];
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_SHA: source,
    GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: "56", GITHUB_WORKFLOW_REF: "T-ej2003/genuine-scan-main/.github/workflows/verify-production-app-only-compatibility.yml@refs/heads/main" };
  assert.equal(parseAppOnlyVerifierExecutionArgs(args, env).mode, "register");
  for (const field of Object.keys(env)) assert.throws(() => parseAppOnlyVerifierExecutionArgs(args, { ...env, [field]: "wrong" }));
  for (const option of ["--sql", "--command", "--environment", "--network", "--task-definition", "--role", "--cluster"])
    assert.throws(() => parseAppOnlyVerifierExecutionArgs([...args, option, "attacker"], env));
  const verify = [...args]; verify[1] = "verify";
  assert.throws(() => parseAppOnlyVerifierExecutionArgs(verify, env));
  assert.equal(parseAppOnlyVerifierExecutionArgs([...verify, "--registration", "/private/registration.json", "--registration-sha256", hash], env).mode, "verify");
  assert.throws(() => parseAppOnlyVerifierExecutionArgs([...args, "--registration", "/private/registration.json", "--registration-sha256", hash], env));
});

test("verifier workflow previews exact preparation then separates protected provisioner and launcher credentials", () => {
  const source = fs.readFileSync(".github/workflows/verify-production-app-only-compatibility-operation.yml", "utf8");
  const workflow = yaml.load(source), job = workflow.jobs.verify;
  assert.deepEqual(Object.keys(workflow.on.workflow_call.inputs).sort(), ["preparation_reference", "source_sha"]);
  assert.equal(workflow.jobs.review.environment, undefined);
  assert.equal(job.needs, "review"); assert.equal(job.environment, "production");
  assert.equal(workflow.concurrency, undefined);
  const roles = job.steps.filter((s) => s.uses?.startsWith("aws-actions/configure-aws-credentials@"));
  assert.deepEqual(roles.map((s) => s.with["role-to-assume"].split("/").at(-1)), ["mscqr-production-app-only-permission-provisioner", "mscqr-production-app-only-verifier-launcher"]);
  assert.ok(roles.every((s) => s.with["unset-current-credentials"] === true));
  assert.match(source, /--require-actual-approval/);
  assert.match(source, /if: always\(\).*steps\.register\.outputs\.journal/);
  assert.doesNotMatch(source, /app-only-deployer|release-gate|terraform apply|update-service|execute-command/);
  for (const phase of Object.values(workflow.jobs)) for (const step of phase.steps)
    if (step.run) assert.doesNotMatch(step.run, /\$\{\{\s*inputs\./);
});

test("verifier preparation accepts compact authenticated identities only on exact protected workflow", () => {
  const source = "a".repeat(40);
  const reference = JSON.stringify({ sourceSha: source, runId: "12", runAttempt: "1", artifactId: "34", artifactDigest: `sha256:${"b".repeat(64)}`, fileSha256: "c".repeat(64) });
  const args = ["--source-sha", source, "--candidate-digest", `sha256:${"d".repeat(64)}`, "--publication-reference", reference, "--image-authorization-reference", reference, "--requirements-reference", reference];
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_SHA: source,
    GITHUB_WORKFLOW_REF: "T-ej2003/genuine-scan-main/.github/workflows/prepare-production-app-only-verifier.yml@refs/heads/main" };
  assert.equal(parseAppOnlyVerifierPreparationArgs(args, env).publicationReference.artifactId, "34");
  assert.ok(JSON.stringify(args).length < 2048);
  for (const field of Object.keys(env)) assert.throws(() => parseAppOnlyVerifierPreparationArgs(args, { ...env, [field]: "wrong" }), field);
  for (const replacement of ["x".repeat(2049), "null", "{}", JSON.stringify({ ...JSON.parse(reference), extractionRoot: "/tmp/attacker" }), reference.replace('"12"', '"0"'), reference.replace('"34"', '"$(id)"')]) {
    const changed = [...args]; changed[5] = replacement;
    assert.throws(() => parseAppOnlyVerifierPreparationArgs(changed, env));
  }
  for (const option of ["--cluster", "--role-arn", "--task-definition", "--sql", "--tfvars-base64"])
    assert.throws(() => parseAppOnlyVerifierPreparationArgs([...args, option, "attacker"], env));
});

test("verifier preparation uses protected isolated reader with step-scoped GitHub access", () => {
  const source = fs.readFileSync(".github/workflows/prepare-production-app-only-verifier-operation.yml", "utf8");
  const workflow = yaml.load(source); const job = workflow.jobs.prepare;
  assert.equal(job.environment, "production");
  assert.equal(job.if, "github.ref == 'refs/heads/main'");
  assert.deepEqual(job.permissions, { contents: "read", actions: "read", "id-token": "write" });
  assert.equal(workflow.concurrency, undefined);
  const credentials = job.steps.findIndex((step) => step.uses?.startsWith("aws-actions/configure-aws-credentials@"));
  assert.ok(credentials > job.steps.findIndex((step) => step.run?.includes("parseAppOnlyVerifierPreparationArgs")));
  assert.equal(job.steps[credentials].with["role-to-assume"], "arn:aws:iam::368992683803:role/mscqr-production-app-only-verifier-launcher");
  assert.equal(job.steps[credentials].with["unset-current-credentials"], true);
  assert.equal(job.steps.filter((step) => step.env?.GITHUB_TOKEN).length, 2);
  for (const step of job.steps) if (step.run) assert.doesNotMatch(step.run, /\$\{\{\s*inputs\./);
  assert.doesNotMatch(source, /run-task|update-service|register-task-definition|terraform apply|kms sign|release-gate/);
  assert.equal(job.steps.at(-1).with.name, "production-app-only-verifier-preparation");
  assert.equal(job.steps.at(-1).with["if-no-files-found"], "error");
});

test("requirements producer is source-only, main-bound and uses compact identities", () => {
  const source = fs.readFileSync(".github/workflows/produce-production-app-only-requirements.yml", "utf8");
  const workflow = yaml.load(source);
  assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["candidate_source_sha", "source_sha"]);
  assert.ok(JSON.stringify({ ref: "main", inputs: { source_sha: "a".repeat(40), candidate_source_sha: "b".repeat(40) } }).length < 512);
  assert.equal(workflow.jobs.requirements.if, "github.ref == 'refs/heads/main'");
  assert.equal(workflow.jobs.requirements.timeoutMinutes, undefined);
  assert.equal(workflow.jobs.requirements["timeout-minutes"], 30);
  assert.equal(workflow.jobs.requirements.environment, undefined, "No unnecessary approval for an isolated source oracle");
  assert.doesNotMatch(source, /configure-aws-credentials|role-to-assume|id-token:|release-gate|terraform apply|aws ecs|kms sign/);
  assert.match(source, /npm run test:p2:db:up/);
  assert.match(source, /produce-production-app-only-requirements\.mjs/);
  assert.match(source, /persist-credentials: false/);
  const tokenSteps = workflow.jobs.requirements.steps.filter((step) => step.env?.GITHUB_TOKEN);
  assert.equal(tokenSteps.length, 1);
  assert.match(tokenSteps[0].run, /gh api repos\/T-ej2003\/genuine-scan-main\/branches\/main/);
  const upload = workflow.jobs.requirements.steps.find((step) => step.uses?.startsWith("actions/upload-artifact@"));
  assert.equal(upload.with.name, "production-app-only-requirements");
  assert.equal(upload.with["if-no-files-found"], "error");
});

test("CI runs real PostgreSQL and full package serially without AWS identity or mock fallback", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/quality-gate.yml", "utf8"));
  const job = workflow.jobs["app-only-deployment-contract"];
  assert.equal(job["timeout-minutes"], 30);
  assert.equal(job.environment, undefined); assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.equal(job.steps[0].with["fetch-depth"], 0);
  assert.equal(job.steps[0].with["persist-credentials"], false);
  const commands = job.steps.map((step) => step.run || "");
  const focused = commands.findIndex((run) => run.includes("--test scripts/tests/production-app-only-"));
  const real = commands.findIndex((run) => run.includes("--test scripts/tests/production-full-rls-package-postgres18"));
  const staticCheck = commands.findIndex((run) => run.includes("npm run rls:full-verify"));
  assert.ok(focused > 0 && real > focused && staticCheck > real, "Generated package checks cannot race production-fixture generation");
  assert.equal(job.steps[real].env.MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST, "true");
  assert.match(job.steps[real].env.MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL, /@127\.0\.0\.1:55432\/mscqr_p2_admin_test$/);
  assert.ok(commands.some((run) => run.includes("npm run test:p2:db:up") && run.includes("node scripts/p2-test-db-tls.mjs")));
  assert.doesNotMatch(JSON.stringify(job), /configure-aws-credentials|role-to-assume|id-token|secrets\./);
  assert.match(commands[staticCheck], /init -backend=false -input=false -lockfile=readonly/);
  assert.match(commands[staticCheck], /eslint scripts\/aws\/\*app-only\*\.mjs/);
});
