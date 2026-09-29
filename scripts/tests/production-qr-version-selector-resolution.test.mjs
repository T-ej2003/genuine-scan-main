import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import os from "node:os";
import test from "node:test";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import JSZip from "jszip";
import yaml from "js-yaml";
import { assertQrVersionResolutionCurrent, assertQrVersionResolutionEvidence, assertQrVersionSelector, buildQrVersionReadSessionPolicy, createQrVersionResolutionEvidence, QR_VERSION_SELECTOR_RESOLUTION, resolveQrVersionResolutionArtifact, resolveQrVersionSelectorValue } from "../aws/production-qr-version-selector-resolution.mjs";
import { deriveLegacyRotationBaseline } from "../aws/production-legacy-rotation-baseline.mjs";

const secretArn = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-current-version-8fNOVE";
const taskDefinition = {
  taskDefinition: {
    taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:19",
    containerDefinitions: [{ name: "backend", environment: [], secrets: [
      { name: "JWT_SECRET", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk:value::" },
      { name: "QR_SIGN_PRIVATE_KEY", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO:value::" },
      { name: "QR_SIGN_PUBLIC_KEY", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex:value::" },
      { name: "QR_SIGN_ACTIVE_KEY_VERSION", valueFrom: `${secretArn}:value::` },
    ] }],
  },
};
const binding = assertQrVersionSelector({ taskDefinition, expectedSecretArn: secretArn });
const response = { ARN: secretArn, VersionId: "a".repeat(32), VersionStages: ["AWSCURRENT"], SecretString: JSON.stringify({ value: "c41ca96ab047dd25", unrelated: "never copied" }) };
const secretMetadata = { ARN: secretArn, VersionIdsToStages: { [response.VersionId]: ["AWSCURRENT"] } };

test("resolver AWS SDK dependencies resolve from a clean install of its backend dependency tree", { timeout: 180_000 }, (t) => {
  const root = path.resolve(".");
  const sourceBackend = path.join(root, "backend");
  const resolver = fs.readFileSync(path.join(root, "scripts/aws/resolve-production-qr-version-selector.mjs"), "utf8");
  assert.match(resolver, /createRequire\(path\.join\(root, "backend\/package\.json"\)\)/);
  const manifest = JSON.parse(fs.readFileSync(path.join(sourceBackend, "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(sourceBackend, "package-lock.json"), "utf8"));
  const version = "3.1055.0";
  assert.equal(manifest.dependencies["@aws-sdk/client-ecs"], version);
  assert.equal(lock.packages[""].dependencies["@aws-sdk/client-ecs"], version);
  assert.equal(lock.packages["node_modules/@aws-sdk/client-ecs"].version, version);

  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "qr-selector-backend-clean-install-"));
  t.after(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));
  const cleanBackend = path.join(temporaryRoot, "backend");
  fs.mkdirSync(cleanBackend);
  fs.copyFileSync(path.join(sourceBackend, "package.json"), path.join(cleanBackend, "package.json"));
  fs.copyFileSync(path.join(sourceBackend, "package-lock.json"), path.join(cleanBackend, "package-lock.json"));
  execFileSync("npm", ["ci", "--prefix", cleanBackend, "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: temporaryRoot, stdio: "pipe", timeout: 150_000 });

  const requireBackend = createRequire(path.join(cleanBackend, "package.json"));
  const cleanNodeModules = `${fs.realpathSync(path.join(cleanBackend, "node_modules"))}${path.sep}`;
  for (const packageName of ["@aws-sdk/client-ecs", "@aws-sdk/client-secrets-manager", "@aws-sdk/client-sts"]) {
    assert.ok(resolver.includes(`requireBackend("${packageName}")`), `resolver does not load ${packageName} from the canonical backend dependency tree`);
    const resolved = requireBackend.resolve(packageName);
    assert.ok(resolved.startsWith(cleanNodeModules), `${packageName} resolved outside the clean backend install: ${resolved}`);
  }
  assert.equal(typeof requireBackend("@aws-sdk/client-ecs").ECSClient, "function");
  assert.equal(typeof requireBackend("@aws-sdk/client-secrets-manager").SecretsManagerClient, "function");
  assert.equal(typeof requireBackend("@aws-sdk/client-sts").STSClient, "function");
});

test("canonical JWT identity and QR selected-value semantics stay distinct", () => {
  const resolved = resolveQrVersionSelectorValue({ response, binding });
  const baseline = deriveLegacyRotationBaseline(taskDefinition, { qrVersionResolution: resolved });
  assert.equal(baseline.jwtCurrent, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk");
  assert.equal(baseline.qrCurrentVersion, "c41ca96ab047dd25");
  assert.notEqual(baseline.qrCurrentVersion, secretArn);
});

test("selector requires the exact ARN, value key and unpinned current semantics", () => {
  for (const [arn, selector] of [
    [secretArn.replace("eu-west-2", "us-east-1"), `${secretArn}:value::`],
    [secretArn.replace("368992683803", "000000000000"), `${secretArn}:value::`],
    [secretArn, `${secretArn}:other::`],
    [secretArn, `${secretArn}:value:AWSPREVIOUS:`],
    [secretArn, `${secretArn}:value::${"b".repeat(32)}`],
    [secretArn.replace("qr-current-version", "qr-previous-version"), `${secretArn}:value::`],
  ]) assert.throws(() => assertQrVersionSelector({ taskDefinition: { taskDefinition: { ...taskDefinition.taskDefinition, containerDefinitions: [{ ...taskDefinition.taskDefinition.containerDefinitions[0], secrets: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", valueFrom: selector }] }] } }, expectedSecretArn: arn }));
  for (const malformed of [undefined, `${secretArn}:value:AWSCURRENT:${"b".repeat(32)}`, `${secretArn}:value::extra`]) assert.throws(() => assertQrVersionSelector({ taskDefinition: { taskDefinition: { ...taskDefinition.taskDefinition, containerDefinitions: [{ name: "backend", secrets: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", valueFrom: malformed }] }] } }, expectedSecretArn: secretArn }));
});

test("secret response must be the exact current version and only the selected identifier is carried forward", () => {
  for (const candidate of [
    { ...response, ARN: secretArn.replace("8fNOVE", "xxxxxx") },
    { ...response, VersionStages: ["AWSPREVIOUS"] },
    { ...response, VersionStages: ["AWSCURRENT", "custom-stage"] },
    { ...response, SecretString: "not-json" },
    { ...response, SecretString: JSON.stringify({ unrelated: "private" }) },
    { ...response, SecretString: JSON.stringify({ value: "" }) },
    { ...response, SecretString: JSON.stringify({ value: "bad:value" }) },
    { ...response, VersionId: "bad" },
  ]) assert.throws(() => resolveQrVersionSelectorValue({ response: candidate, binding }), (error) => !error.message.includes("private"));
  const resolved = resolveQrVersionSelectorValue({ response, binding });
  const evidence = createQrVersionResolutionEvidence({ binding, resolved, sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", workflowRunId: "12345", createdAt: "2026-09-27T12:00:00.000Z" });
  assert.equal(evidence.qrCurrentVersion, "c41ca96ab047dd25");
  assert.equal(JSON.stringify(evidence).includes("unrelated"), false);
  assert.equal(JSON.stringify(evidence).includes(response.SecretString), false);
  assert.equal(assertQrVersionResolutionEvidence(evidence, { sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, now: new Date("2026-09-27T12:01:00.000Z") }), evidence);
  assert.throws(() => assertQrVersionResolutionEvidence(evidence, { sourceSha: "b".repeat(40), changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, now: new Date("2026-09-27T12:01:00.000Z") }));
  assert.throws(() => assertQrVersionResolutionEvidence(evidence, { sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-002", expectedSecretArn: secretArn, now: new Date("2026-09-27T12:01:00.000Z") }));
  assert.throws(() => assertQrVersionResolutionEvidence(evidence, { sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn.replace("8fNOVE", "xxxxxx"), now: new Date("2026-09-27T12:01:00.000Z") }));
  assert.throws(() => assertQrVersionResolutionEvidence(evidence, { sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, now: new Date("2026-09-27T13:00:00.000Z") }));
  for (const [field, value] of Object.entries({ operation: "OTHER_OPERATION", purpose: "OTHER_PURPOSE", account: "000000000000", region: "us-east-1", secretArn: secretArn.replace("8fNOVE", "xxxxxx"), jsonKey: "other", versionSemantics: "AWSPREVIOUS", qrCurrentVersion: "arn:aws:secretsmanager:wrong" })) {
    const altered = { ...evidence, [field]: value };
    const body = { ...altered }; delete body.evidenceSha256;
    altered.evidenceSha256 = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
    assert.throws(() => assertQrVersionResolutionEvidence(altered, { sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, now: new Date("2026-09-27T12:01:00.000Z") }), undefined, field);
  }
  assert.equal(QR_VERSION_SELECTOR_RESOLUTION.operation, "READ_ONLY_QR_VERSION_SELECTOR_RESOLUTION");
});

test("resolution consumption rebinds current task revision and AWSCURRENT version", () => {
  const resolved = resolveQrVersionSelectorValue({ response, binding });
  const evidence = createQrVersionResolutionEvidence({ binding, resolved, sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", workflowRunId: "12345", createdAt: "2026-09-27T12:00:00.000Z" });
  assert.equal(assertQrVersionResolutionCurrent({ taskDefinition, resolution: evidence, secretMetadata }), true);
  assert.throws(() => assertQrVersionResolutionCurrent({ taskDefinition: { ...taskDefinition, taskDefinition: { ...taskDefinition.taskDefinition, taskDefinitionArn: `${taskDefinition.taskDefinition.taskDefinitionArn.slice(0, -2)}20` } }, resolution: evidence, secretMetadata }), /task definition and AWSCURRENT/);
  assert.throws(() => assertQrVersionResolutionCurrent({ taskDefinition, resolution: evidence, secretMetadata: { ...secretMetadata, VersionIdsToStages: { ["b".repeat(32)]: ["AWSCURRENT"] } } }), /AWSCURRENT/);
  assert.throws(() => assertQrVersionResolutionCurrent({ taskDefinition, resolution: evidence, secretMetadata: { ...secretMetadata, ARN: secretArn.replace("8fNOVE", "xxxxxx") } }), /AWSCURRENT/);
  assert.throws(() => deriveLegacyRotationBaseline(taskDefinition, { qrVersionResolution: { ...evidence, taskDefinitionSha256: "b".repeat(64) } }), /exact task definition/);
});

test("task-definition identity normalizes AWS SDK dates to CLI JSON timestamps", () => {
  const sdkTaskDefinition = structuredClone(taskDefinition);
  sdkTaskDefinition.taskDefinition.registeredAt = new Date("2026-09-27T12:00:00.000Z");
  sdkTaskDefinition.taskDefinition.deregisteredAt = new Date("2026-09-27T12:30:00.000Z");
  const cliTaskDefinition = Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(sdkTaskDefinition, (key, value) => key === "registeredAt" ? "2026-09-27T12:00:00+00:00" : key === "deregisteredAt" ? "2026-09-27T12:30:00+00:00" : value))).reverse());
  const sdkBinding = assertQrVersionSelector({ taskDefinition: sdkTaskDefinition, expectedSecretArn: secretArn });
  const resolved = resolveQrVersionSelectorValue({ response, binding: sdkBinding });
  const evidence = createQrVersionResolutionEvidence({ binding: sdkBinding, resolved, sourceSha: "a".repeat(40), changeTicket: "CHG-20260925-001", workflowRunId: "12345", createdAt: "2026-09-27T12:00:00.000Z" });
  assert.equal(assertQrVersionResolutionCurrent({ taskDefinition: cliTaskDefinition, resolution: evidence, secretMetadata }), true);
  assert.throws(() => assertQrVersionResolutionCurrent({ taskDefinition: { ...cliTaskDefinition, taskDefinition: { ...cliTaskDefinition.taskDefinition, family: "unexpected-backend" } }, resolution: evidence, secretMetadata }), /task definition and AWSCURRENT/);
});

test("artifact consumer authenticates the exact successful workflow run and single payload", async () => {
  const sourceSha = "a".repeat(40);
  const evidence = createQrVersionResolutionEvidence({ binding, resolved: resolveQrVersionSelectorValue({ response, binding }), sourceSha, changeTicket: "CHG-20260925-001", workflowRunId: "12345", createdAt: "2026-09-27T12:00:00.000Z" });
  const zip = await new JSZip().file("resolution.json", JSON.stringify(evidence)).generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
  const artifactDigest = `sha256:${crypto.createHash("sha256").update(zip).digest("hex")}`;
  const workflow = { id: 12345, path: QR_VERSION_SELECTOR_RESOLUTION.workflowPath, repository: { full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1 };
  const artifact = { name: QR_VERSION_SELECTOR_RESOLUTION.artifactName, id: 9, expired: false, digest: artifactDigest, workflow_run: { id: 12345, head_sha: sourceSha } };
  const fetchImpl = async (url) => ({ ok: true, json: async () => url.endsWith("/12345") ? workflow : { artifacts: [artifact] }, arrayBuffer: async () => zip });
  const current = { taskDefinition, secretMetadata };
  assert.equal((await resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, ...current, token: "fixture-token", fetchImpl, now: new Date("2026-09-27T12:01:00.000Z") })).qrCurrentVersion, "c41ca96ab047dd25");
  for (const alter of [
    (run) => ({ ...run, path: "attacker.yml" }),
    (run) => ({ ...run, head_repository: { full_name: "fork/repo" } }),
    (run) => ({ ...run, head_sha: "b".repeat(40) }),
    (run) => ({ ...run, conclusion: "failure" }),
    (run) => ({ ...run, run_attempt: 2 }),
  ]) {
    const badFetch = async (url, options) => { const result = await fetchImpl(url, options); return { ...result, json: async () => url.endsWith("/12345") ? alter(workflow) : { artifacts: [artifact] } }; };
    await assert.rejects(resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, ...current, token: "fixture-token", fetchImpl: badFetch, now: new Date("2026-09-27T12:01:00.000Z") }));
  }
  await assert.rejects(resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-002", expectedSecretArn: secretArn, ...current, token: "fixture-token", fetchImpl, now: new Date("2026-09-27T12:01:00.000Z") }));
  const tampered = Buffer.from(zip); tampered[tampered.length - 1] ^= 1;
  await assert.rejects(resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, ...current, token: "fixture-token", fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("/12345") ? workflow : { artifacts: [artifact] }, arrayBuffer: async () => tampered }), now: new Date("2026-09-27T12:01:00.000Z") }));
  const symlinkZip = await new JSZip().file("resolution.json", JSON.stringify(evidence), { unixPermissions: 0o120777 }).generateAsync({ type: "nodebuffer", platform: "UNIX" });
  const symlinkArtifact = { ...artifact, digest: `sha256:${crypto.createHash("sha256").update(symlinkZip).digest("hex")}` };
  await assert.rejects(resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, ...current, token: "fixture-token", fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("/12345") ? workflow : { artifacts: [symlinkArtifact] }, arrayBuffer: async () => symlinkZip }), now: new Date("2026-09-27T12:01:00.000Z") }));
  await assert.rejects(resolveQrVersionResolutionArtifact({ workflowRunId: "12345", sourceSha, changeTicket: "CHG-20260925-001", expectedSecretArn: secretArn, token: "fixture-token", fetchImpl, now: new Date("2026-09-27T12:01:00.000Z") }));
});

test("read session policy permits only exact production metadata and one secret read", () => {
  const policy = buildQrVersionReadSessionPolicy(secretArn);
  assert.deepEqual(policy.Statement.map(({ Action, Resource }) => [Action, Resource]), [
    ["sts:GetCallerIdentity", "*"],
    ["ecs:DescribeServices", "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"],
    ["ecs:DescribeTaskDefinition", "*"],
    ["secretsmanager:GetSecretValue", secretArn],
    ["secretsmanager:DescribeSecret", secretArn],
  ]);
  assert.equal(policy.Statement.some(({ Action }) => String(Action).includes("Put") || String(Action).includes("Update") || String(Action).includes("Delete") || String(Action).includes("List")), false);
  assert.equal(policy.Statement.filter(({ Resource }) => Resource === "*").map(({ Action }) => Action).join(","), "sts:GetCallerIdentity,ecs:DescribeTaskDefinition");
  assert.throws(() => buildQrVersionReadSessionPolicy(secretArn.replace("qr-current-version", "other-secret")));
});

test("workflow approval, read permissions and payload handling remain narrowly scoped", () => {
  const root = path.resolve(".");
  const workflow = yaml.load(fs.readFileSync(path.join(root, ".github/workflows/resolve-production-qr-version-selector.yml"), "utf8"));
  assert.equal(workflow.jobs.resolve.environment, QR_VERSION_SELECTOR_RESOLUTION.environment);
  assert.deepEqual(workflow.permissions, { actions: "read", contents: "read", "id-token": "write" });
  const iam = JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-initial-activation-policy-reconciler/bootstrap-operator-policy-authorizer-permissions-policy.json"), "utf8"));
  assert.deepEqual(iam.Statement.slice(0, 2).map(({ Action, Resource }) => [Action, Resource]), [
    ["ecs:DescribeServices", "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"],
    ["ecs:DescribeTaskDefinition", "*"],
  ]);
  assert.equal(iam.Statement.some(({ Action, Resource }) => String(Action).includes("secretsmanager:GetSecretValue") && (Resource === "*" || Array.isArray(Resource) && Resource.includes("*"))), false);
  assert.equal(iam.Statement.filter(({ Resource }) => Resource === "*").map(({ Action }) => Action).join(","), "ecs:DescribeTaskDefinition,sts:GetCallerIdentity");
  const resolver = fs.readFileSync(path.join(root, "scripts/aws/resolve-production-qr-version-selector.mjs"), "utf8");
  assert.match(workflow.jobs.resolve.steps.map(({ run }) => run || "").join("\n"), /npm ci --prefix backend/);
  assert.match(resolver, /process\.stdout\.write\("QR_VERSION_RESOLUTION=PASS/);
  assert.doesNotMatch(resolver, /console\.log\([^\n]*(SecretString|parsed|resolved)/);
  assert.match(resolver, /GITHUB_WORKFLOW_REF/);
  assert.match(resolver, /GITHUB_RUN_ATTEMPT !== "1"/);
});
