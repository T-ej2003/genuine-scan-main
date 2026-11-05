import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { LEDGER, assertLedgerAuthorization, assertLedgerEvidence, assertLedgerReceipt, assertFixedLedgerDefinition, authenticateLedgerLogPages,
  assertProtectedToolingSource, createPinnedGitRunner, waitForLedgerLogPages } from "../aws/production-d15-ledger-readback.mjs";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "../aws/production-root-attestation-key.mjs";
import { createProductionGithubCommandRunner, productionGithubExecutable } from "../aws/production-credential-source-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const toolingSourceSha = "a".repeat(40);
const issuedAt = "2026-11-05T20:00:00.000Z";
const now = Date.parse("2026-11-05T20:01:00.000Z");
const sign = (body, key) => ({ body, [key]: canonicalSha256(body), signatureBase64: Buffer.from("signed-test-payload").toString("base64"),
  signingKeyAliasArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM });
const verify = ({ signature }) => signature.equals(Buffer.from("signed-test-payload"));
const authorization = () => sign({ kind: "D15_FIXED_MIGRATION_LEDGER_READBACK_AUTHORIZATION", sourceSha: LEDGER.sourceSha,
  toolingSourceSha, runtimeSourceSha: LEDGER.runtimeSha, database: LEDGER.database, taskDefinitionArn: LEDGER.taskDefinitionArn,
  imageDigest: LEDGER.imageDigest, commandSha256: LEDGER.commandSha256, nonce: "b".repeat(64), issuedAt,
  expiresAt: "2026-11-05T20:15:00.000Z" }, "authorizationSha256");
const evidence = () => {
  const migrations = path.join(root, "backend/prisma/migrations");
  const rows = fs.readdirSync(migrations, { withFileTypes: true }).filter((entry) => entry.isDirectory() && fs.existsSync(path.join(migrations, entry.name, "migration.sql")))
    .map((entry) => ({ migration_name: entry.name, checksum: crypto.createHash("sha256").update(fs.readFileSync(path.join(migrations, entry.name, "migration.sql"))).digest("hex"), finished: true, rolled_back: false }));
  const body = { kind: "PRODUCTION_MIGRATION_LEDGER_READ_ONLY", sourceSha: LEDGER.runtimeSha, database: LEDGER.database,
    databaseRole: "mscqr_prd_rls_phase2_migration", sessionRole: "mscqr_prod_admin", readOnly: true, rows };
  return { ...body, evidenceSha256: crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex") };
};
const receipt = (auth = authorization()) => sign({ kind: "D15_FIXED_MIGRATION_LEDGER_READBACK_RECEIPT", sourceSha: LEDGER.sourceSha,
  toolingSourceSha, runtimeSourceSha: LEDGER.runtimeSha, authorizationSha256: auth.authorizationSha256, nonce: auth.body.nonce,
  taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "c".repeat(32),
  taskDefinitionArn: LEDGER.taskDefinitionArn, createdAt: "2026-11-05T20:00:10.000Z", startedAt: "2026-11-05T20:00:20.000Z",
  stoppedAt: "2026-11-05T20:00:30.000Z", database: LEDGER.database, evidence: evidence(), logEventsSha256: "d".repeat(64) }, "receiptSha256");
const checkAuth = (a, at = now) => assertLedgerAuthorization(a, { toolingSourceSha, now: at, verify });
const checkReceipt = (r, a = authorization(), at = now) => assertLedgerReceipt(r, a, { toolingSourceSha, now: at, verify });
const changed = (value, fn, digestKey) => { const copy = structuredClone(value); fn(copy); copy[digestKey] = canonicalSha256(copy.body); return copy; };

test("D15 authorization and independently signed receipt bind the unchanged e39 task to D15", () => {
  const auth = authorization(), result = receipt(auth);
  assert.equal(checkAuth(auth).sourceSha, LEDGER.sourceSha);
  assert.equal(checkReceipt(result, auth).evidence.rows.length, 57);
  assert.equal(checkReceipt(result, auth, Date.parse("2026-11-06T00:00:00.000Z")).taskArn, result.body.taskArn,
    "Historical receipt verification remains possible after execution authorization expires");
});

test("authorization rejects forged signature, wrong source, tooling, task, database, and expiry", () => {
  const a = authorization();
  assert.throws(() => checkAuth({ ...a, signatureBase64: Buffer.from("forgery").toString("base64") }));
  for (const [field, value] of [["sourceSha", "c".repeat(40)], ["toolingSourceSha", "c".repeat(40)],
    ["runtimeSourceSha", LEDGER.sourceSha], ["database", "other"], ["taskDefinitionArn", "other"],
    ["imageDigest", "sha256:" + "c".repeat(64)], ["commandSha256", "c".repeat(64)]]) {
    assert.throws(() => checkAuth(changed(a, (x) => { x.body[field] = value; }, "authorizationSha256")), field);
  }
  assert.throws(() => checkAuth(a, Date.parse("2026-11-05T20:15:00.000Z")), "Expired authorization cannot launch");
  assert.throws(() => assertLedgerAuthorization(a, { toolingSourceSha, now: Date.parse("2026-11-05T20:09:00.000Z"),
    minimumRemainingMs: 7 * 60_000, verify }), "Launch needs enough time for the fixed task");
});

test("receipt rejects replay against a fresh request, forged signature, missing audit, and altered rows", () => {
  const a = authorization(), r = receipt(a);
  const replay = changed(a, (x) => { x.body.nonce = "e".repeat(64); }, "authorizationSha256");
  assert.throws(() => checkReceipt(r, replay), "Receipt must be bound to the exact request and nonce");
  assert.throws(() => checkReceipt({ ...r, signatureBase64: Buffer.from("forgery").toString("base64") }, a));
  assert.throws(() => checkReceipt(changed(r, (x) => { delete x.body.logEventsSha256; }, "receiptSha256"), a));
  assert.throws(() => checkReceipt(changed(r, (x) => { x.body.evidence.rows[0].checksum = "0".repeat(64); }, "receiptSha256"), a));
  assert.throws(() => checkReceipt(changed(r, (x) => { x.body.createdAt = "2026-11-05T19:59:59.000Z"; }, "receiptSha256"), a));
});

test("ledger evidence fails closed for altered migration state and incomplete output", () => {
  const e = evidence(); assert.equal(assertLedgerEvidence(e).rows.length, 57);
  for (const mutate of [(x) => { x.rows.pop(); }, (x) => { x.rows[0].finished = false; },
    (x) => { x.rows[0].checksum = "0".repeat(64); }, (x) => { x.sourceSha = LEDGER.sourceSha; }]) {
    const x = structuredClone(e); mutate(x);
    x.evidenceSha256 = crypto.createHash("sha256").update(JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k]) => k !== "evidenceSha256")))).digest("hex");
    assert.throws(() => assertLedgerEvidence(x));
  }
});

test("fixed task definition rejects an arbitrary command or execution role", () => {
  assert.throws(() => assertFixedLedgerDefinition({ taskDefinitionArn: LEDGER.taskDefinitionArn, status: "ACTIVE" }));
  assert.throws(() => assertFixedLedgerDefinition({ taskDefinitionArn: "other" }));
});

test("ledger log pagination and native execution window fail closed", () => {
  const start = "2026-11-05T20:00:10.000Z", stop = "2026-11-05T20:00:30.000Z";
  const event = { timestamp: Date.parse("2026-11-05T20:00:20.000Z"), message: JSON.stringify(evidence()) };
  const pages = [{ requestToken: undefined, nextForwardToken: "token", events: [event] },
    { requestToken: "token", nextForwardToken: "token", events: [] }];
  assert.match(authenticateLedgerLogPages(pages, start, stop).logEventsSha256, /^[a-f0-9]{64}$/);
  assert.throws(() => authenticateLedgerLogPages(pages.slice(0, 1), start, stop), "Truncated audit output");
  assert.throws(() => authenticateLedgerLogPages([{ requestToken: undefined, nextForwardToken: undefined, events: [event, event] }], start, stop));
  assert.throws(() => authenticateLedgerLogPages([{ requestToken: undefined, nextForwardToken: undefined,
    events: [{ ...event, timestamp: Date.parse("2026-11-05T19:59:59.000Z") }] }], start, stop));
});

test("protected-main gate pins GitHub host, repository, SHA, and executables", () => {
  const mainSha = "a".repeat(40);
  const gitRun = (args) => args[0] === "rev-parse" ? args[1] === "--show-toplevel" ? `${root}\n` : `${mainSha}\n` : "";
  const branch = { name: "main", _links: { self: "https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main" },
    commit: { sha: mainSha, url: `https://api.github.com/repos/T-ej2003/genuine-scan-main/commits/${mainSha}` } };
  let observed;
  const githubRun = createProductionGithubCommandRunner({ env: { ...process.env, GH_HOST: "attacker.example" },
    exec: (command, args, options) => { observed = { command, args, env: options.env }; return JSON.stringify(branch); } });
  assert.equal(assertProtectedToolingSource({ gitRun, githubRun }), mainSha);
  assert.equal(observed.env.GH_HOST, "github.com");
  assert.deepEqual(observed.args, ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]);
  assert.ok(productionGithubExecutable().startsWith("/"));
  assert.throws(() => productionGithubExecutable({ existsSync: () => true, realpathSync: () => "/tmp/attacker/gh",
    statSync: () => ({ isFile: () => true, mode: 0o755 }) }));
  assert.throws(() => createProductionGithubCommandRunner({ exec: () => "{}" })("gh", ["api", "repos/attacker/repo/branches/main"]));
  assert.throws(() => assertProtectedToolingSource({ gitRun, githubRun: () => JSON.stringify({ ...branch, commit: { ...branch.commit, sha: "b".repeat(40) } }) }));
  assert.throws(() => assertProtectedToolingSource({ gitRun, githubRun: () => JSON.stringify({ ...branch,
    _links: { self: "https://api.github.com/repos/attacker/repo/branches/main" } }) }));
  assert.throws(() => assertProtectedToolingSource({ gitRun, githubRun: () => { throw new Error("API unavailable"); } }));
  let gitCommand, gitEnvironment;
  createPinnedGitRunner({ env: { HOME: "/tmp/home", PATH: "/tmp/attacker", GIT_DIR: "/tmp/evil" },
    exec: (command, _args, options) => { gitCommand = command; gitEnvironment = options.env; return ""; } })(["rev-parse", "HEAD"]);
  assert.equal(gitCommand, "/usr/bin/git");
  assert.equal(gitEnvironment.PATH, "/usr/bin:/bin");
  assert.equal(gitEnvironment.GIT_DIR, undefined);
});

test("bounded log polling handles missing streams, empty pages, delay, and timeout without launching a task", async () => {
  const event = { timestamp: Date.parse("2026-11-05T20:00:20.000Z"), message: JSON.stringify(evidence()) };
  let reads = 0, waits = 0;
  const pages = await waitForLedgerLogPages(() => {
    reads++;
    if (reads === 1) { const error = new Error("stream absent"); error.stderr = "ResourceNotFoundException"; throw error; }
    if (reads === 2) return { nextForwardToken: "t1", events: [] };
    if (reads === 3) return { nextForwardToken: "t1", events: [] };
    if (reads === 4) return { nextForwardToken: "t2", events: [event] };
    return { nextForwardToken: "t2", events: [] };
  }, { wait: async () => { waits++; }, attempts: 4 });
  assert.equal(reads, 5); assert.equal(waits, 2);
  assert.equal(authenticateLedgerLogPages(pages, "2026-11-05T20:00:10.000Z", "2026-11-05T20:00:30.000Z").evidence.rows.length, 57);
  await assert.rejects(waitForLedgerLogPages(() => ({ nextForwardToken: "stable", events: [] }),
    { wait: async () => {}, attempts: 2 }), /absent/);
  await assert.rejects(waitForLedgerLogPages(() => { throw new Error("AccessDenied"); },
    { wait: async () => {}, attempts: 2 }), /AccessDenied/);
  assert.throws(() => authenticateLedgerLogPages([{ requestToken: undefined, nextForwardToken: "t", events: [event] }],
    "2026-11-05T20:00:10.000Z", "2026-11-05T20:00:30.000Z"));
});
