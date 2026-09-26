import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { collectAppOnlyDatabaseCatalogue, collectAppOnlyDatabaseCatalogueRows } from "../aws/production-app-only-database-verifier.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import {
  FORBIDDEN_SMOKE_SECRETS, SMOKE_ENVIRONMENT, SMOKE_REPOSITORY,
  executeSmokeSecretHandoff, smokeSecretHandoffContract,
} from "../aws/handoff-production-smoke-secrets.mjs";
import {
  EXPECTED_PRINTING_ROUTINES, EXPECTED_PRINTING_ROUTINE_PREDECESSORS, RLS_PROBE_CLASSIFICATIONS,
  authenticateCanonicalProductionRequirements, authenticateCanonicalProductionRequirementsArtifact, authenticateProductionRlsProbeResult, authenticateProtectedMainProbeImage,
  bindProductionRlsProbeIdentities, buildProductionRlsProbeDefinition,
  classifyProductionRlsCatalogue, hashProductionRlsCatalogue,
} from "../aws/probe-production-rls-catalogue.mjs";

const handoff = smokeSecretHandoffContract();
const sourceSha = "a".repeat(40);
const fakeHandoffRunner = ({ wrongArn = false, fail = "", branchSha = sourceSha } = {}) => {
  const calls = [];
  const run = (command, args, options = {}) => {
    calls.push({ command, args, env: options.env, input: options.input ? Buffer.from(options.input) : undefined });
    if (fail && args.includes(fail)) throw new Error("injected failure");
    if (command === "gh" && args[0] === "api") return Buffer.from(JSON.stringify({ commit: { sha: branchSha } }));
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
  const hostileEnvironment = { PATH: process.env.PATH, HOME: process.env.HOME, GH_TOKEN: "fixture-token", GH_HOST: "attacker.invalid", GH_ENTERPRISE_TOKEN: "hostile-enterprise-token", AWS_ENDPOINT_URL: "https://attacker.invalid", AWS_ENDPOINT_URL_SECRETSMANAGER: "https://attacker.invalid/secrets", AWS_ACCESS_KEY_ID: "ambient" };
  const fake = fakeHandoffRunner(), result = executeSmokeSecretHandoff({ sourceSha, awsProfile: "fixture", run: fake.run, env: hostileEnvironment, awsExecutable: "aws", githubExecutable: "gh" });
  assert.equal(result.repository, SMOKE_REPOSITORY); assert.equal(result.environment, SMOKE_ENVIRONMENT);
  const writes = fake.calls.filter(({ command, args }) => command === "gh" && args[1] === "set");
  assert.deepEqual(writes.map(({ args }) => args[2]), handoff.map(({ destination }) => destination));
  assert.ok(writes.every(({ args, input }) => !args.includes("--body") && input.length > 0));
  assert.ok(fake.calls.filter(({ command }) => command === "gh").every(({ args, env }) => (args.includes("github.com/T-ej2003/genuine-scan-main") || args[1] === "repos/T-ej2003/genuine-scan-main/branches/main") && env?.GH_HOST === "github.com" && !env?.GH_ENTERPRISE_TOKEN && !env?.AWS_ACCESS_KEY_ID && !env?.AWS_ENDPOINT_URL));
  assert.ok(fake.calls.filter(({ command }) => command === "aws").every(({ env }) => env?.AWS_PROFILE === "fixture" && !env?.AWS_ACCESS_KEY_ID && !env?.AWS_ENDPOINT_URL && !env?.AWS_ENDPOINT_URL_SECRETSMANAGER));
  assert.ok(fake.calls.every(({ args }) => !args.includes("dedicated-secret-value")));
  assert.ok(FORBIDDEN_SMOKE_SECRETS.every((name) => !writes.some(({ args }) => args.includes(name))));
  assert.doesNotMatch(JSON.stringify(result), /dedicated-secret-value/);
});

test("smoke handoff fails closed for substituted identity or command failure", () => {
  const invoke = (options) => executeSmokeSecretHandoff({ sourceSha, awsProfile: "fixture", run: fakeHandoffRunner(options).run, awsExecutable: "aws", githubExecutable: "gh" });
  assert.throws(() => invoke({ wrongArn: true }));
  assert.throws(() => invoke({ fail: "describe-secret" }));
  assert.throws(() => invoke({ fail: "get-secret-value" }));
  assert.throws(() => invoke({ fail: "set" }));
  const first = fakeHandoffRunner({ fail: "set" });
  assert.throws(() => executeSmokeSecretHandoff({ sourceSha, awsProfile: "fixture", run: first.run, awsExecutable: "aws", githubExecutable: "gh" }));
  assert.throws(() => invoke({ branchSha: "c".repeat(40) }), /current protected main/);
  assert.doesNotThrow(() => executeSmokeSecretHandoff({ sourceSha, awsProfile: "fixture", run: fakeHandoffRunner().run, awsExecutable: "aws", githubExecutable: "gh" }));
});

const catalogue = () => ({
  identity: { role: APP_ONLY_VERIFIER.databaseRole },
  routines: Object.keys(EXPECTED_PRINTING_ROUTINE_PREDECESSORS).map((identity) => { const [, name, args] = identity.match(/^app_rls\.([^(]+)\((.*)\)$/); return { schema: "app_rls", name, arguments: args, definition: `current-${name}`, grants: [] }; })
    .concat([{ schema: "app_auth", name: "login", arguments: "", definition: "current-login", grants: [] }]),
  tables: [{ name: "User", owner: "owner", rls: true, forced: true, grants: [], column_grants: [] }],
  policies: [{ table: "User", name: "tenant", command: "r", roles: ["app"], using: "false", check: null }],
  schemas: [{ name: "app_rls", owner: "owner", grants: [] }],
  roles: [{ name: APP_ONLY_VERIFIER.databaseRole, login: true, superuser: false, memberships: [], members: [] }],
});
const requirementsFor = (value) => ({ schemaVersion: 1, kind: "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS", sourceSha: "a".repeat(40), candidateSourceSha: "a".repeat(40), requirementsSha256: "b".repeat(64),
  objects: Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map((name) => [name, value[name].map((row) => ({ identity: name === "routines" ? `${row.schema}.${row.name}(${row.arguments})` : name === "policies" ? `${row.table}.${row.name}` : row.name, sha256: canonicalSha256(row) }))])) });

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const requirementsArchive = (name, bytes) => execFileSync("python3", ["-c", `import io,sys,zipfile
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 i=zipfile.ZipInfo(sys.argv[1]);i.create_system=3;i.external_attr=33152<<16
 z.writestr(i,sys.stdin.buffer.read(),compress_type=zipfile.ZIP_DEFLATED)
sys.stdout.buffer.write(b.getvalue())`, name], { input: bytes });
const canonicalRequirementsFixture = ({ protectedSourceSha = sourceSha, candidateSourceSha = protectedSourceSha } = {}) => {
  const requirements = createAppOnlyRequirements({ repositoryRoot: process.cwd(), sourceSha: protectedSourceSha, candidateSourceSha, catalogue: catalogue(), packageChecksums: { package: "fixture" } });
  const bytes = Buffer.from(JSON.stringify(requirements)), archive = requirementsArchive("app-only-requirements.json", bytes);
  const reference = { sourceSha: protectedSourceSha, runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: `sha256:${sha256(archive)}`, fileSha256: sha256(bytes) };
  const run = { id: 123, run_attempt: 1, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_sha: protectedSourceSha, head_branch: "main", path: ".github/workflows/produce-production-app-only-requirements.yml", event: "workflow_dispatch", status: "completed", conclusion: "success" };
  const artifact = { id: 456, name: "production-app-only-requirements", expired: false, digest: reference.artifactDigest, size_in_bytes: archive.length, workflow_run: { id: 123, head_sha: protectedSourceSha, head_repository_id: 9, repository_id: 9 } };
  const githubRun = (_command, args) => args[1].endsWith("/branches/main") ? JSON.stringify({ commit: { sha: protectedSourceSha } }) : args[1].endsWith("/zip") ? archive : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1, artifacts: [artifact] }]) : JSON.stringify(run);
  return { sourceSha: protectedSourceSha, candidateSourceSha, requirements, bytes, archive, reference, run, artifact, githubRun };
};

test("production RLS requirements come only from the authenticated canonical producer artifact", () => {
  const fixture = canonicalRequirementsFixture();
  const authenticated = authenticateCanonicalProductionRequirements({ sourceSha: fixture.sourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: fixture.githubRun });
  assert.equal(authenticated.requirements.requirementsSha256, fixture.requirements.requirementsSha256);
  assert.deepEqual(authenticated.provenance, { runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: fixture.reference.artifactDigest, fileSha256: fixture.reference.fileSha256 });
  assert.throws(() => authenticateCanonicalProductionRequirements({ sourceSha: "c".repeat(40), requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: fixture.githubRun }), /source/);
  assert.throws(() => authenticateCanonicalProductionRequirements({ sourceSha: fixture.sourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: (_command, args) => args[1].endsWith("/branches/main") ? JSON.stringify({ commit: { sha: "c".repeat(40) } }) : fixture.githubRun(_command, args) }), /current protected main/);
  for (const change of [
    (value) => { value.objects.tables[0].sha256 = "0".repeat(64); },
    (value) => { value.objects.routines[0].sha256 = "0".repeat(64); },
    (value) => { value.canonicalPackageChecksumsSha256 = "0".repeat(64); },
    (value) => { value.sourceSha = value.candidateSourceSha = "d".repeat(40); },
  ]) {
    const replaced = structuredClone(fixture.requirements); change(replaced);
    const { requirementsSha256: _old, ...body } = replaced; replaced.requirementsSha256 = canonicalSha256(body);
    const replacementArchive = requirementsArchive("app-only-requirements.json", Buffer.from(JSON.stringify(replaced)));
    const substituted = (_command, args) => args[1].endsWith("/zip") ? replacementArchive : fixture.githubRun(_command, args);
    assert.throws(() => authenticateCanonicalProductionRequirements({ sourceSha: fixture.sourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: substituted }));
  }
  const wrongMember = requirementsArchive("copied-requirements.json", fixture.bytes);
  assert.throws(() => authenticateCanonicalProductionRequirements({ sourceSha: fixture.sourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: (_command, args) => args[1].endsWith("/zip") ? wrongMember : fixture.githubRun(_command, args) }));
  for (const mutate of [
    (run) => { run.path = ".github/workflows/other.yml"; },
    (run) => { run.conclusion = "failure"; },
    (run) => { run.run_attempt = 2; },
  ]) {
    const changed = structuredClone(fixture.run); mutate(changed);
    assert.throws(() => authenticateCanonicalProductionRequirements({ sourceSha: fixture.sourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: (_command, args) => args[1].includes("/runs/123") && !args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify(changed) : fixture.githubRun(_command, args) }));
  }
});

test("authenticated ancestor candidate remains distinct through workflow artifact authentication", () => {
  const protectedSourceSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const candidateSourceSha = execFileSync("git", ["rev-parse", "HEAD^"], { encoding: "utf8" }).trim();
  const fixture = canonicalRequirementsFixture({ protectedSourceSha, candidateSourceSha });
  const accepted = authenticateCanonicalProductionRequirementsArtifact({ sourceSha: protectedSourceSha, candidateSourceSha,
    requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: fixture.githubRun });
  assert.equal(accepted.requirements.sourceSha, protectedSourceSha);
  assert.equal(accepted.requirements.candidateSourceSha, candidateSourceSha);
  assert.throws(() => authenticateCanonicalProductionRequirementsArtifact({ sourceSha: protectedSourceSha,
    candidateSourceSha: protectedSourceSha, requirementsReference: fixture.reference, repositoryRoot: process.cwd(), githubRun: fixture.githubRun }));
});

test("RLS classification accepts exact match and only the exact three printing routine deltas", () => {
  const expected = catalogue(), requirements = requirementsFor(expected);
  assert.deepEqual(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(expected), requirements), { classification: RLS_PROBE_CLASSIFICATIONS.MATCH, deltaObjects: [] });
  const predecessor = hashProductionRlsCatalogue(expected);
  for (const row of predecessor.routines) if (EXPECTED_PRINTING_ROUTINE_PREDECESSORS[row.identity]) row.sha256 = EXPECTED_PRINTING_ROUTINE_PREDECESSORS[row.identity];
  const result = classifyProductionRlsCatalogue(predecessor, requirements);
  assert.equal(result.classification, RLS_PROBE_CLASSIFICATIONS.EXPECTED); assert.equal(result.deltaObjects.length, 3);
  for (const mutate of [
    (v) => v.routines.splice(v.routines.findIndex(({ identity }) => identity.includes("printing_readiness(")), 1),
    (v) => v.routines.find(({ identity }) => identity.includes("printing_create_job(")).sha256 = "0".repeat(64),
    (v) => v.routines.find(({ identity }) => identity.includes("printing_connector_identity(")).sha256 = requirements.objects.routines.find(({ identity }) => identity.includes("printing_connector_identity(")).sha256,
  ]) { const bad = structuredClone(predecessor); mutate(bad); assert.equal(classifyProductionRlsCatalogue(bad, requirements).classification, RLS_PROBE_CLASSIFICATIONS.UNEXPECTED); }
  const old = structuredClone(expected); for (const row of old.routines.filter(({ name }) => EXPECTED_PRINTING_ROUTINES.includes(name))) row.definition = `unreviewed-${row.name}`;
  assert.equal(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(old), requirements).classification, RLS_PROBE_CLASSIFICATIONS.UNEXPECTED);
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
  const value = catalogue(), requirements = requirementsFor(value);
  const identity = { sourceSha: "a".repeat(40), candidateSourceSha: "a".repeat(40), probeRuntimeSourceSha: "a".repeat(40), probeImageSourceSha: "a".repeat(40),
    probeImageDigest: `sha256:${"2".repeat(64)}`, applicationImageSourceSha: "a".repeat(40), applicationImageDigest: `sha256:${"3".repeat(64)}`, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
  const secret = ["arn:aws:secretsmanager:eu-west-2:368992683803:secret", "mscqr/production/rls-green/phase4/read-only-canary-database-url-ABC123"].join(":");
  const baseDefinition = { family: APP_ONLY_VERIFIER.family, taskRoleArn: APP_ONLY_VERIFIER.taskRoleArn, executionRoleArn: APP_ONLY_VERIFIER.executionRoleArn,
    networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, containerDefinitions: [{ name: "production-green-read-only-rls-canary",
      image: `${APP_ONLY.backendRepository}@sha256:${"1".repeat(64)}`, entryPoint: ["node"], environment: [], secrets: [{ name: "RLS_CANARY_DATABASE_URL", valueFrom: secret }], readonlyRootFilesystem: true, privileged: false }] };
  const definition = buildProductionRlsProbeDefinition({ baseDefinition, requirements, identity, databaseSecretArn: secret });
  assert.equal(definition.family, APP_ONLY_VERIFIER.family); assert.equal(definition.taskRoleArn, APP_ONLY_VERIFIER.taskRoleArn); assert.equal(definition.executionRoleArn, APP_ONLY_VERIFIER.executionRoleArn);
  assert.deepEqual(definition.containerDefinitions[0].secrets, [{ name: "RLS_CANARY_DATABASE_URL", valueFrom: secret }]); assert.equal(definition.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.deepEqual(definition.containerDefinitions[0].entryPoint, ["node", "scripts/aws/production-rls-catalogue-probe-runtime.mjs"]);
  assert.equal(definition.containerDefinitions[0].image, `${APP_ONLY.backendRepository}@${identity.probeImageDigest}`);
  assert.deepEqual(definition.containerDefinitions[0].command, []);
  assert.deepEqual(JSON.parse(definition.containerDefinitions[0].environment[0].value), { schemaVersion: 1, ...identity, requirementsSha256: requirements.requirementsSha256, securityTransportPublicKey: null });
  const wrapper = collectAppOnlyDatabaseCatalogue.toString(), collector = collectAppOnlyDatabaseCatalogueRows.toString();
  assert.equal((wrapper.match(/\$executeRawUnsafe/g) || []).length, 1); assert.match(wrapper, /SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY/);
  assert.equal((collector.match(/\$executeRawUnsafe/g) || []).length, 1); assert.match(collector, /SET LOCAL search_path = pg_catalog/);
  const queryCount = (collector.match(/\$queryRawUnsafe\(/g) || []).length;
  assert.ok(queryCount > 0);
  const queries = [...collector.matchAll(/\$queryRawUnsafe\(`([\s\S]*?)`\)/g)].map(([, sql]) => sql.trim());
  assert.equal(queries.length, queryCount);
  assert.ok(queries.every((sql) => /^(?:SELECT|WITH)\b/.test(sql)));
});

test("RLS execution failure or unauthenticated output can never become MATCH", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40), probeRuntimeSourceSha: "a".repeat(40), probeImageSourceSha: "a".repeat(40), probeImageDigest: `sha256:${"2".repeat(64)}`, applicationImageSourceSha: "b".repeat(40), applicationImageDigest: `sha256:${"3".repeat(64)}`, requirementsSha256: "b".repeat(64), databaseRole: APP_ONLY_VERIFIER.databaseRole, catalogue: hashProductionRlsCatalogue(catalogue()) };
  const expected = { sourceSha: body.sourceSha, candidateSourceSha: body.candidateSourceSha, probeImageDigest: body.probeImageDigest, applicationImageDigest: body.applicationImageDigest, requirementsSha256: body.requirementsSha256 };
  const valid = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
  assert.deepEqual(authenticateProductionRlsProbeResult(valid, expected).catalogue, body.catalogue);
  for (const field of ["candidateSourceSha", "probeImageDigest", "applicationImageDigest"]) assert.throws(() => authenticateProductionRlsProbeResult(valid, { ...expected, [field]: field.endsWith("Digest") ? `sha256:${"4".repeat(64)}` : body.sourceSha }));
  assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify({ status: "PRODUCTION_RLS_CATALOGUE_PROBE_FAILED" }), expected));
  const changed = JSON.parse(valid); changed.sourceSha = "c".repeat(40); assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify(changed), expected));
  const changedCandidate = JSON.parse(valid); changedCandidate.candidateSourceSha = "c".repeat(40); changedCandidate.evidenceSha256 = canonicalSha256(Object.fromEntries(Object.entries(changedCandidate).filter(([key]) => key !== "evidenceSha256"))); assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify(changedCandidate), expected));
  const extra = JSON.parse(valid); extra.catalogue.tables[0].unexpected = true; extra.evidenceSha256 = canonicalSha256(Object.fromEntries(Object.entries(extra).filter(([key]) => key !== "evidenceSha256"))); assert.throws(() => authenticateProductionRlsProbeResult(JSON.stringify(extra), expected));
  assert.throws(() => authenticateProductionRlsProbeResult("not-json", expected));
});

test("protected-main probe and authenticated ancestor application identities remain distinct", () => {
  const protectedMain = "a".repeat(40), candidate = "b".repeat(40), candidateDigest = `sha256:${"3".repeat(64)}`;
  const requirements = { sourceSha: protectedMain, candidateSourceSha: candidate };
  const imageBody = { kind: "APP_ONLY_AUTHENTICATED_IMAGES", sourceSha: protectedMain, candidateSourceSha: candidate, candidateDigest };
  const images = { ...imageBody, evidenceSha256: canonicalSha256(imageBody) };
  const probeImage = authenticateProtectedMainProbeImage({ sourceSha: protectedMain, response: { imageDetails: [{ registryId: APP_ONLY.account, repositoryName: "mscqr-backend", imageDigest: `sha256:${"2".repeat(64)}`, imageTags: [`${protectedMain}-backend-only`] }] } });
  const identity = bindProductionRlsProbeIdentities({ sourceSha: protectedMain, requirements, images, probeImage, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" });
  assert.equal(identity.probeImageSourceSha, protectedMain); assert.equal(identity.applicationImageSourceSha, candidate); assert.notEqual(identity.probeImageDigest, identity.applicationImageDigest);
  assert.throws(() => bindProductionRlsProbeIdentities({ sourceSha: protectedMain, requirements, images: { ...images, candidateSourceSha: protectedMain }, probeImage, databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" }));
  assert.throws(() => authenticateProtectedMainProbeImage({ sourceSha: protectedMain, response: { imageDetails: [{ registryId: APP_ONLY.account, repositoryName: "mscqr-backend", imageDigest: probeImage.digest, imageTags: [`${candidate}-backend-only`] }] } }));
});

test("operator scripts contain no secret output or database mutation surface", () => {
  const handoffSource = fs.readFileSync("scripts/aws/handoff-production-smoke-secrets.mjs", "utf8"), probeSource = fs.readFileSync("scripts/aws/probe-production-rls-catalogue.mjs", "utf8");
  assert.doesNotMatch(handoffSource, /console\.(?:log|error)|SecretString[^\n]+process\.stdout/);
  assert.doesNotMatch(probeSource, /\b(?:ALTER|CREATE|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE)\b[^\n]*\$executeRawUnsafe/i);
  assert.doesNotMatch(probeSource, /["'](?:dynamodb|lambda)["']|InvokeFunction/);
  assert.doesNotMatch(probeSource, /requirementsPath|--requirements(?:["'])/);
  assert.match(probeSource, /downloadAppOnlyArtifact\(\{ kind: "requirements"/);
  assert.match(fs.readFileSync("scripts/aws/production-app-only-artifacts.mjs", "utf8"), /execFileSync\("\/usr\/bin\/python3"/);
});
