import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { collectAppOnlyDatabaseCatalogue } from "../aws/production-app-only-database-verifier.mjs";
import {
  FORBIDDEN_SMOKE_SECRETS, SMOKE_ENVIRONMENT, SMOKE_REPOSITORY,
  executeSmokeSecretHandoff, smokeSecretHandoffContract,
} from "../aws/handoff-production-smoke-secrets.mjs";
import {
  EXPECTED_PRINTING_ROUTINES, RLS_PROBE_CLASSIFICATIONS,
  authenticateProductionRlsProbeResult, buildProductionRlsProbeDefinition,
  classifyProductionRlsCatalogue, hashProductionRlsCatalogue,
} from "../aws/probe-production-rls-catalogue.mjs";

const handoff = smokeSecretHandoffContract();
const fakeHandoffRunner = ({ wrongArn = false, fail = "" } = {}) => {
  const calls = [];
  const run = (command, args, options = {}) => {
    calls.push({ command, args, input: options.input ? Buffer.from(options.input) : undefined });
    if (fail && args.includes(fail)) throw new Error("injected failure");
    if (command === "gh" && args[0] === "secret" && args[1] === "list") return Buffer.from(JSON.stringify(handoff.map(({ destination }) => ({ name: destination }))));
    if (command === "gh" && args[0] === "secret" && args[1] === "set") return Buffer.alloc(0);
    if (args.includes("get-caller-identity")) return Buffer.from(JSON.stringify({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" }));
    if (args.includes("describe-secret")) {
      const id = args[args.indexOf("--secret-id") + 1], entry = handoff.find(({ secretId }) => secretId === id);
      return Buffer.from(JSON.stringify({ Name: id, ARN: wrongArn ? `${entry.arn}x` : entry.arn }));
    }
    if (args.includes("get-secret-value")) return Buffer.from("dedicated-secret-value\n");
    throw new Error(`Unexpected command: ${command} ${args.join(" ")}`);
  };
  return { run, calls };
};

test("smoke handoff maps only the three source-owned canary handles to the three reviewed destinations", () => {
  assert.deepEqual(handoff.map(({ secretId }) => secretId), [
    "mscqr/production/rls-green/phase2/canary/ordinary-email",
    "mscqr/production/rls-green/phase2/canary/ordinary-password",
    "mscqr/production/rls-green/phase2/canary/ordinary-mfa-secret",
  ]);
  assert.deepEqual(handoff.map(({ destination }) => destination), ["PRODUCTION_SMOKE_LOGIN_EMAIL", "PRODUCTION_SMOKE_LOGIN_PASSWORD", "PRODUCTION_SMOKE_ADMIN_MFA_SECRET"]);
  const fake = fakeHandoffRunner(), result = executeSmokeSecretHandoff({ awsProfile: "fixture", run: fake.run, contract: handoff });
  assert.equal(result.repository, SMOKE_REPOSITORY); assert.equal(result.environment, SMOKE_ENVIRONMENT);
  const writes = fake.calls.filter(({ command, args }) => command === "gh" && args[1] === "set");
  assert.deepEqual(writes.map(({ args }) => args[2]), handoff.map(({ destination }) => destination));
  assert.ok(writes.every(({ args, input }) => args.at(-1) === "-" && input.length > 0));
  assert.ok(fake.calls.every(({ args }) => !args.includes("dedicated-secret-value")));
  assert.ok(FORBIDDEN_SMOKE_SECRETS.every((name) => !writes.some(({ args }) => args.includes(name))));
  assert.doesNotMatch(JSON.stringify(result), /dedicated-secret-value/);
});

test("smoke handoff fails closed for substituted identity or command failure", () => {
  assert.throws(() => executeSmokeSecretHandoff({ awsProfile: "fixture", run: fakeHandoffRunner({ wrongArn: true }).run, contract: handoff }));
  assert.throws(() => executeSmokeSecretHandoff({ awsProfile: "fixture", run: fakeHandoffRunner({ fail: "describe-secret" }).run, contract: handoff }));
  assert.throws(() => executeSmokeSecretHandoff({ awsProfile: "fixture", run: fakeHandoffRunner({ fail: "get-secret-value" }).run, contract: handoff }));
  assert.throws(() => executeSmokeSecretHandoff({ awsProfile: "fixture", run: fakeHandoffRunner({ fail: "set" }).run, contract: handoff }));
  const wrong = structuredClone(handoff); wrong[0].destination = "OTHER";
  assert.notDeepEqual(wrong.map(({ destination }) => destination), handoff.map(({ destination }) => destination));
});

const catalogue = () => ({
  identity: { role: APP_ONLY_VERIFIER.databaseRole },
  routines: EXPECTED_PRINTING_ROUTINES.map((name) => ({ schema: "app_rls", name, arguments: "p text", definition: `current-${name}`, grants: [] })).concat([{ schema: "app_auth", name: "login", arguments: "", definition: "current-login", grants: [] }]),
  tables: [{ name: "User", owner: "owner", rls: true, forced: true, grants: [], column_grants: [] }],
  policies: [{ table: "User", name: "tenant", command: "r", roles: ["app"], using: "false", check: null }],
  schemas: [{ name: "app_rls", owner: "owner", grants: [] }],
  roles: [{ name: APP_ONLY_VERIFIER.databaseRole, login: true, superuser: false, memberships: [], members: [] }],
});
const requirementsFor = (value) => ({ schemaVersion: 1, kind: "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS", sourceSha: "a".repeat(40), candidateSourceSha: "a".repeat(40), requirementsSha256: "b".repeat(64),
  objects: Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map((name) => [name, value[name].map((row) => ({ identity: name === "routines" ? `${row.schema}.${row.name}(${row.arguments})` : name === "policies" ? `${row.table}.${row.name}` : row.name, sha256: canonicalSha256(row) }))])) });

test("RLS classification accepts exact match and only the exact three printing routine deltas", () => {
  const expected = catalogue(), requirements = requirementsFor(expected);
  assert.deepEqual(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(expected), requirements), { classification: RLS_PROBE_CLASSIFICATIONS.MATCH, deltaObjects: [] });
  const old = structuredClone(expected); for (const row of old.routines.filter(({ name }) => EXPECTED_PRINTING_ROUTINES.includes(name))) row.definition = `old-${row.name}`;
  const result = classifyProductionRlsCatalogue(hashProductionRlsCatalogue(old), requirements);
  assert.equal(result.classification, RLS_PROBE_CLASSIFICATIONS.EXPECTED); assert.equal(result.deltaObjects.length, 3);
  for (const mutate of [
    (v) => v.routines.at(-1).owner = "wrong",
    (v) => v.policies[0].using = "true",
    (v) => v.tables[0].forced = false,
    (v) => v.tables[0].owner = "wrong",
    (v) => v.tables[0].grants.push({ role: "PUBLIC", privilege: "SELECT" }),
    (v) => v.tables[0].column_grants.push({ column: "id", role: "PUBLIC", privilege: "SELECT" }),
    (v) => v.roles[0].superuser = true,
  ]) { const bad = structuredClone(old); mutate(bad); assert.equal(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(bad), requirements).classification, RLS_PROBE_CLASSIFICATIONS.UNEXPECTED); }
});

test("RLS probe definition reuses the exact private read-only task boundary", () => {
  const value = catalogue(), requirements = requirementsFor(value), secret = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123";
  const baseDefinition = { family: APP_ONLY_VERIFIER.family, taskRoleArn: APP_ONLY_VERIFIER.taskRoleArn, executionRoleArn: APP_ONLY_VERIFIER.executionRoleArn,
    networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, containerDefinitions: [{ name: "production-green-read-only-rls-canary",
      image: `${APP_ONLY.backendRepository}@sha256:${"1".repeat(64)}`, entryPoint: ["node"], environment: [], secrets: [{ name: "RLS_CANARY_DATABASE_URL", valueFrom: secret }], readonlyRootFilesystem: true, privileged: false }] };
  const definition = buildProductionRlsProbeDefinition({ baseDefinition, requirements, identity: { sourceSha: "a".repeat(40) }, databaseSecretArn: secret });
  assert.equal(definition.family, APP_ONLY_VERIFIER.family); assert.equal(definition.taskRoleArn, APP_ONLY_VERIFIER.taskRoleArn); assert.equal(definition.executionRoleArn, APP_ONLY_VERIFIER.executionRoleArn);
  assert.deepEqual(definition.containerDefinitions[0].secrets, [{ name: "RLS_CANARY_DATABASE_URL", valueFrom: secret }]); assert.equal(definition.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.doesNotMatch(definition.containerDefinitions[0].command.join("\n"), /\$executeRawUnsafe\(["'`](?:ALTER|CREATE|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE)/i);
  assert.match(definition.containerDefinitions[0].command.join("\n"), /url\.hostname,input\.identity\.databaseHostname/);
  assert.ok(Buffer.byteLength(definition.containerDefinitions[0].command[1]) < 48000);
  const collector = collectAppOnlyDatabaseCatalogue.toString();
  assert.equal((collector.match(/\$executeRawUnsafe/g) || []).length, 1); assert.match(collector, /SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY/);
  assert.ok([...collector.matchAll(/\$queryRawUnsafe\(`([\s\S]*?)`\)/g)].every(([, sql]) => /^SELECT\b/.test(sql.trim())));
});

test("RLS execution failure or unauthenticated output can never become MATCH", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha: "a".repeat(40), requirementsSha256: "b".repeat(64), databaseRole: APP_ONLY_VERIFIER.databaseRole, catalogue: hashProductionRlsCatalogue(catalogue()) };
  const valid = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
  assert.deepEqual(authenticateProductionRlsProbeResult(valid, { sourceSha: body.sourceSha, requirementsSha256: body.requirementsSha256 }).catalogue, body.catalogue);
  assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify({ status: "PRODUCTION_RLS_CATALOGUE_PROBE_FAILED" }), { sourceSha: body.sourceSha, requirementsSha256: body.requirementsSha256 }));
  const changed = JSON.parse(valid); changed.sourceSha = "c".repeat(40); assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify(changed), { sourceSha: body.sourceSha, requirementsSha256: body.requirementsSha256 }));
});

test("operator scripts contain no secret output or database mutation surface", () => {
  const handoffSource = fs.readFileSync("scripts/aws/handoff-production-smoke-secrets.mjs", "utf8"), probeSource = fs.readFileSync("scripts/aws/probe-production-rls-catalogue.mjs", "utf8");
  assert.doesNotMatch(handoffSource, /console\.(?:log|error)|SecretString[^\n]+process\.stdout/);
  assert.doesNotMatch(probeSource, /\b(?:ALTER|CREATE|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE)\b[^\n]*\$executeRawUnsafe/i);
  assert.doesNotMatch(probeSource, /["'](?:dynamodb|lambda)["']|InvokeFunction/);
});
