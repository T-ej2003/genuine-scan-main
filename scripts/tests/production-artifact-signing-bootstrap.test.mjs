import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ARTIFACT_SIGNING_BINDINGS } from "../aws/production-artifact-signing-domain.mjs";
import { ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, artifactSigningRuntimeBindingPath, bootstrapArtifactSigningBindings, loadArtifactSigningBootstrapContract } from "../aws/production-artifact-signing-bootstrap.mjs";
import { createAwsArtifactSigningAdapter, loadApprovedArtifactSigningBindings } from "../aws/production-artifact-signing-secrets-adapter.mjs";
import { parseArgs, runCli } from "../aws/bootstrap-production-artifact-signing.mjs";

const suffix = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/${name}-AbCd12`;
const names = loadArtifactSigningBootstrapContract().names;
const sourceSha = "a".repeat(40);
const runtimeBindingPath = artifactSigningRuntimeBindingPath(sourceSha);
const bootstrap = (options) => bootstrapArtifactSigningBindings({ sourceSha, ...options });

function fakeRunner({ existing = {}, createFailure = null } = {}) {
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    const operation = args[1];
    const secretIdIndex = args.indexOf("--secret-id");
    const nameIndex = args.indexOf("--name");
    const name = secretIdIndex >= 0 ? args[secretIdIndex + 1] : args[nameIndex + 1];
    if (operation === "describe-secret") {
      if (!existing[name]) {
        const error = new Error("ResourceNotFoundException");
        error.stderr = "ResourceNotFoundException";
        throw error;
      }
      const state = typeof existing[name] === "string" ? { arn: existing[name], initialized: true, value: "fixture-value" } : existing[name];
      return JSON.stringify({ Name: name, ARN: state.arn, VersionIdsToStages: state.initialized ? { fixture: ["AWSCURRENT"] } : {} });
    }
    if (operation === "create-secret") {
      if (createFailure === name) throw new Error("CreateSecret denied");
      const arn = suffix(name.split("/").at(-1));
      existing[name] = { arn, initialized: false, value: null };
      return JSON.stringify({ Name: name, ARN: arn });
    }
    if (operation === "get-secret-value") {
      const state = Object.values(existing).find((candidate) => (typeof candidate === "string" ? candidate : candidate?.arn) === name) || Object.values(existing).find((candidate) => (typeof candidate === "string" ? candidate : candidate?.arn) === name);
      const normalized = typeof state === "string" ? { initialized: true, value: "fixture-value" } : state;
      if (!normalized?.initialized) throw new Error("GetSecretValue unexpectedly called for value-less secret");
      return JSON.stringify({ SecretString: normalized.value });
    }
    if (operation === "put-secret-value") {
      const secretRef = args[args.indexOf("--secret-id") + 1];
      const state = Object.values(existing).find((candidate) => (typeof candidate === "string" ? candidate : candidate?.arn) === secretRef);
      if (!state || typeof state === "string") throw new Error("Fixture secret state is not writable.");
      const valueFile = args[args.indexOf("--secret-string") + 1].replace(/^file:\/\//, "");
      state.value = readFileSync(valueFile, "utf8");
      state.initialized = true;
      return JSON.stringify({ ARN: secretRef, VersionId: "fixture-version", VersionStages: ["AWSCURRENT"] });
    }
    throw new Error(`Unexpected operation: ${operation}`);
  };
  return { calls, run, existing };
}

function denyOperationRunner(operation) {
  const fixture = fakeRunner();
  const run = async (args) => {
    if (args[1] === operation) throw new Error(`${operation} denied`);
    return fixture.run(args);
  };
  return { ...fixture, run };
}

const cleanup = () => { if (existsSync(runtimeBindingPath)) rmSync(runtimeBindingPath, { force: true }); };

test.afterEach(cleanup);

test("protected-main bootstrap CLI exposes the existing idempotent producer", async () => {
  let written = "";
  const result = await runCli(["--source-sha", sourceSha], {
    readFresh: () => ({ headSha: sourceSha, freshRemoteMainSha: sourceSha }),
    bootstrap: async () => ({ bindingFile: "/private/tmp/bindings.json", evidenceSha256: "b".repeat(64), created: [], createSecretCount: 0 }),
    write: (value) => { written = value; },
  });
  assert.equal(result.AWS_WRITES, 0);
  assert.equal(JSON.parse(written).sourceSha, sourceSha);
  assert.throws(() => parseArgs(["--source-sha", "short"]), /full protected-main SHA/);
  await assert.rejects(() => runCli(["--source-sha", sourceSha], { readFresh: () => ({ headSha: "c".repeat(40), freshRemoteMainSha: sourceSha }) }), /exact fresh protected main/);
});

test("canonical names are stable and source-controlled", () => {
  assert.deepEqual(Object.keys(names).sort(), [...ARTIFACT_SIGNING_BINDINGS].sort());
  assert.deepEqual(Object.values(names), [
    "mscqr/production/rls-green/artifact-signing/private-key-current",
    "mscqr/production/rls-green/artifact-signing/public-key-current",
    "mscqr/production/rls-green/artifact-signing/active-key-version",
    "mscqr/production/rls-green/artifact-signing/public-keys-json",
  ]);
});

test("empty environment creates exactly four containers and emits identifiers only", async () => {
  const fixture = fakeRunner();
  const result = await bootstrap({ run: fixture.run });
  assert.equal(result.createSecretCount, 4);
  assert.equal(result.created.length, 4);
  assert.deepEqual(Object.keys(result.bindings).sort(), [...ARTIFACT_SIGNING_BINDINGS].sort());
  const bindingFile = loadApprovedArtifactSigningBindings(result.bindingFile, { expectedSourceSha: sourceSha, expectedSha256: result.evidenceSha256 });
  assert.deepEqual(bindingFile, result.bindings);
  assert.throws(() => loadApprovedArtifactSigningBindings(result.bindingFile, { expectedSourceSha: sourceSha, expectedSha256: "f".repeat(64) }), /changed after runtime preparation/);
  const bytes = readFileSync(result.bindingFile, "utf8");
  assert.doesNotMatch(bytes, /BEGIN .*PRIVATE KEY|SecretString|password|token/i);
  assert.equal(fixture.calls.some((args) => args.includes("list-secrets")), false);
  assert.equal(path.resolve(result.bindingFile).startsWith(`${path.resolve(process.cwd())}${path.sep}`), false);
  assert.equal(lstatSync(path.dirname(result.bindingFile)).mode & 0o777, 0o700);
  assert.equal(lstatSync(result.bindingFile).mode & 0o777, 0o600);
  assert.equal(JSON.parse(bytes).sourceSha, sourceSha);
});

test("runtime binding path is exact, source-bound, external, and fail-closed", async () => {
  const fixture = fakeRunner();
  await assert.rejects(() => bootstrap({ run: fixture.run, outputFile: path.join(process.cwd(), "binding.json") }), /runtime binding path must be/);
  assert.equal(fixture.calls.length, 0);
  await bootstrap({ run: fixture.run });
  assert.throws(() => loadApprovedArtifactSigningBindings(runtimeBindingPath, { expectedSourceSha: "b".repeat(40) }), /canonical external runtime path/);
  writeFileSync(runtimeBindingPath, "{}\n", { mode: 0o600 });
  assert.throws(() => loadApprovedArtifactSigningBindings(runtimeBindingPath, { expectedSourceSha: sourceSha }), /SHA-256 is required/);
  assert.throws(() => loadApprovedArtifactSigningBindings(runtimeBindingPath, { expectedSourceSha: sourceSha, expectedSha256: createHash("sha256").update("{}\n").digest("hex") }), /source identity is invalid/);
});

test("runtime binding rejects symlink traversal into a repository", () => {
  const repositoryRoot = path.join(os.tmpdir(), `artifact-binding-repository-${process.pid}`);
  const target = path.join(repositoryRoot, "binding.json");
  rmSync(runtimeBindingPath, { force: true });
  rmSync(repositoryRoot, { recursive: true, force: true });
  mkdirSync(repositoryRoot, { recursive: true, mode: 0o700 });
  mkdirSync(path.dirname(runtimeBindingPath), { recursive: true, mode: 0o700 });
  writeFileSync(target, "{}\n", { mode: 0o600 });
  symlinkSync(target, runtimeBindingPath);
  try {
    assert.throws(() => loadApprovedArtifactSigningBindings(runtimeBindingPath, { expectedSourceSha: sourceSha, expectedSha256: "0".repeat(64), repositoryRoot }), /non-symlink|must not traverse a symlink/);
  } finally {
    rmSync(runtimeBindingPath, { force: true });
    rmSync(repositoryRoot, { recursive: true, force: true });
  }
});

test("bootstrap rejects a symlinked parent before writing into a repository", async () => {
  const symlinkSourceSha = "c".repeat(40);
  const symlinkBindingPath = artifactSigningRuntimeBindingPath(symlinkSourceSha);
  const repositoryRoot = path.join(os.tmpdir(), `artifact-binding-parent-repository-${process.pid}`);
  rmSync(path.dirname(symlinkBindingPath), { recursive: true, force: true });
  rmSync(repositoryRoot, { recursive: true, force: true });
  mkdirSync(repositoryRoot, { recursive: true, mode: 0o700 });
  symlinkSync(repositoryRoot, path.dirname(symlinkBindingPath));
  try {
    const fixture = fakeRunner({ existing: Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], suffix(name.toLowerCase())])) });
    await assert.rejects(() => bootstrapArtifactSigningBindings({ run: fixture.run, sourceSha: symlinkSourceSha, repositoryRoot }), /must not traverse a symlink/);
    assert.equal(fixture.calls.length, 0);
    assert.equal(existsSync(path.join(repositoryRoot, path.basename(symlinkBindingPath))), false);
  } finally {
    unlinkSync(path.dirname(symlinkBindingPath));
    rmSync(repositoryRoot, { recursive: true, force: true });
  }
});

test("bootstrap rejects a public runtime directory before any AWS call", async () => {
  const publicSourceSha = "d".repeat(40);
  const publicBindingPath = artifactSigningRuntimeBindingPath(publicSourceSha);
  rmSync(path.dirname(publicBindingPath), { recursive: true, force: true });
  mkdirSync(path.dirname(publicBindingPath), { recursive: true, mode: 0o755 });
  const fixture = fakeRunner();
  try {
    await assert.rejects(() => bootstrapArtifactSigningBindings({ run: fixture.run, sourceSha: publicSourceSha }), /mode 0700/);
    assert.equal(fixture.calls.length, 0);
  } finally {
    rmSync(path.dirname(publicBindingPath), { recursive: true, force: true });
  }
});

test("value-less existing containers are marked uninitialized without GetSecretValue", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], { arn: suffix(name.toLowerCase()), initialized: false, value: null }]));
  const fixture = fakeRunner({ existing });
  const result = await bootstrap({ run: fixture.run });
  assert.deepEqual(new Set(result.uninitializedSecretRefs), new Set(Object.values(result.bindings)));
  assert.equal(fixture.calls.some((args) => args[1] === "get-secret-value"), false);
});

test("initialized metadata is preserved and marked ready", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], { arn: suffix(name.toLowerCase()), initialized: true, value: `preserved-${name}` }]));
  const fixture = fakeRunner({ existing });
  const result = await bootstrap({ run: fixture.run });
  assert.deepEqual(result.uninitializedSecretRefs, []);
  assert.equal(fixture.calls.filter((args) => args[1] === "create-secret").length, 0);
});

test("full environment reuses all four ARNs without CreateSecret", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], suffix(name.toLowerCase())]));
  const fixture = fakeRunner({ existing });
  const result = await bootstrap({ run: fixture.run });
  assert.equal(result.createSecretCount, 0);
  assert.equal(fixture.calls.filter((args) => args[1] === "create-secret").length, 0);
  assert.deepEqual(result.bindings, Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, existing[names[name]]] )));
});

test("bootstrap replay preserves the exact source-bound binding", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], suffix(name.toLowerCase())]));
  const fixture = fakeRunner({ existing });
  const first = await bootstrap({ run: fixture.run });
  const firstBytes = readFileSync(first.bindingFile);
  const second = await bootstrap({ run: fixture.run });
  assert.deepEqual(readFileSync(second.bindingFile), firstBytes);
  assert.equal(first.evidenceSha256, second.evidenceSha256);
  assert.equal(second.createSecretCount, 0);
});

test("partial environment creates only missing containers", async () => {
  const existing = { [names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: suffix("private-key-current") };
  const fixture = fakeRunner({ existing });
  const result = await bootstrap({ run: fixture.run });
  assert.equal(result.createSecretCount, 3);
  assert.deepEqual(result.created.sort(), ARTIFACT_SIGNING_BINDINGS.filter((name) => name !== "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT").sort());
  assert.equal(result.bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT, existing[names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]);
});

test("retry after partial failure converges without duplicate containers", async () => {
  const first = fakeRunner({ createFailure: names.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT });
  await assert.rejects(() => bootstrap({ run: first.run }), /bootstrap failed/i);
  const second = fakeRunner({ existing: first.existing });
  const result = await bootstrap({ run: second.run });
  assert.equal(result.createSecretCount, 3);
  assert.equal(second.calls.filter((args) => args[1] === "create-secret").length, 3);
});

test("invalid returned ARN is rejected before publication", async () => {
  const fixture = fakeRunner({ existing: { [names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: "arn:aws:secretsmanager:us-east-1:368992683803:secret:wrong" } });
  await assert.rejects(() => bootstrap({ run: fixture.run }), /outside the reviewed namespace/i);
});

test("wrong account, region, and namespace ARNs are rejected", async (t) => {
  for (const [label, arn] of [
    ["account", "arn:aws:secretsmanager:eu-west-2:999999999999:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12"],
    ["region", "arn:aws:secretsmanager:us-east-1:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12"],
    ["namespace", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/other/private-key-current-AbCd12"],
  ]) {
    await t.test(label, async () => {
      const fixture = fakeRunner({ existing: { [names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: arn } });
      await assert.rejects(() => bootstrap({ run: fixture.run }), /outside the reviewed namespace/i);
    });
  }
});

test("duplicate AWS ARNs are rejected", async () => {
  const arn = suffix("duplicate");
  const fixture = fakeRunner({ existing: Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.slice(0, 2).map((name) => [names[name], arn])) });
  await assert.rejects(() => bootstrap({ run: fixture.run }), /duplicate secret ARNs/i);
});

test("CreateSecret failure is fail-closed and no binding artifact is accepted", async () => {
  const fixture = fakeRunner({ createFailure: names.ARTIFACT_SIGN_ACTIVE_KEY_VERSION });
  await assert.rejects(() => bootstrap({ run: fixture.run }), /bootstrap failed/i);
  assert.equal(existsSync(runtimeBindingPath), false);
});

test("production artifact adapter invokes the bootstrap path", async () => {
  const fixture = fakeRunner();
  const adapter = createAwsArtifactSigningAdapter({ run: fixture.run, sourceSha });
  const result = await adapter.bootstrap();
  assert.equal(result.createSecretCount, 4);
  assert.deepEqual(adapter.bindings, result.bindings);
  assert.equal(fixture.calls.some((args) => args[1] === "list-secrets"), false);
});

test("value-less containers initialize through the existing artifact producer", async () => {
  const fixture = fakeRunner();
  const adapter = createAwsArtifactSigningAdapter({ run: fixture.run, sourceSha });
  await adapter.bootstrap();
  const result = await adapter.provision();
  assert.equal(result.valid, true);
  assert.equal(fixture.calls.filter((args) => args[1] === "put-secret-value").length, 4);
  assert.equal(Object.values(fixture.existing).every((state) => state.initialized === true), true);
});

test("partial initialized/value-less domains fill only missing values", async () => {
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const existing = {
    [names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: { arn: suffix("private-key-current"), initialized: true, value: pair.privateKey },
    [names.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT]: { arn: suffix("public-key-current"), initialized: false, value: null },
    [names.ARTIFACT_SIGN_ACTIVE_KEY_VERSION]: { arn: suffix("active-key-version"), initialized: true, value: "v1" },
    [names.ARTIFACT_SIGN_PUBLIC_KEYS_JSON]: { arn: suffix("public-keys-json"), initialized: false, value: null },
  };
  const fixture = fakeRunner({ existing });
  const adapter = createAwsArtifactSigningAdapter({ run: fixture.run, sourceSha });
  await adapter.bootstrap();
  const before = existing[names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].value;
  const result = await adapter.provision();
  assert.equal(result.valid, true);
  assert.equal(existing[names.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].value, before);
  assert.equal(existing[names.ARTIFACT_SIGN_ACTIVE_KEY_VERSION].value, "v1");
  assert.equal(fixture.calls.filter((args) => args[1] === "put-secret-value").length, 2);
});

test("approved adapter denies GetSecretValue and PutSecretValue failures without widening targets", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], { arn: suffix(name.toLowerCase()), initialized: true, value: "fixture" }]));
  const fixture = denyOperationRunner("get-secret-value");
  Object.assign(fixture.existing, existing);
  const adapter = createAwsArtifactSigningAdapter({ run: fixture.run, sourceSha });
  await adapter.bootstrap();
  await assert.rejects(() => adapter.readSecret(adapter.bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT), /get-secret-value denied/);

  const putFixture = denyOperationRunner("put-secret-value");
  const putAdapter = createAwsArtifactSigningAdapter({ run: putFixture.run, sourceSha });
  await putAdapter.bootstrap();
  await assert.rejects(() => putAdapter.putSecret({ secretRef: putAdapter.bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT, value: "fixture" }), /put-secret-value denied/);
  assert.equal(putFixture.calls.some((args) => args.includes("list-secrets")), false);
});

test("unknown GetSecretValue failures remain fail-closed", async () => {
  const existing = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [names[name], { arn: suffix(name.toLowerCase()), initialized: true, value: "fixture" }]));
  const fixture = fakeRunner({ existing });
  const run = async (args) => {
    if (args[1] === "get-secret-value") throw new Error("InternalServiceError");
    return fixture.run(args);
  };
  const adapter = createAwsArtifactSigningAdapter({ run, sourceSha });
  await adapter.bootstrap();
  await assert.rejects(() => adapter.readSecret(adapter.bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT), /InternalServiceError/);
});
