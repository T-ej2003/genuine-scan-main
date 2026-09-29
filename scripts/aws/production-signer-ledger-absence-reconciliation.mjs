#!/usr/bin/env node
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createBrokerPolicySuccessorRootMfaSession } from "./component-broker-policy-successor-root-mfa.mjs";
import { assertSignerLedgerAbsenceAuthorization, resolveSignerLedgerAbsenceAuthorization } from "./production-signer-ledger-absence-authorization.mjs";
import { classifySignerLedgerBucketPolicy, signerLedgerAbsence, signerLedgerBucketPolicySuccessor, policySha256 } from "./production-signer-ledger-absence-policy.mjs";
import { readStageBProtectedMainCheckoutFromGitHub } from "./stage-b-deployment-identity.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const expectedOwner = "368992683803";
const required = (args, index) => { const value = args[index]; if (!value) throw new Error(`Argument ${index + 1} is required`); return value; };

export function sourceShaFromProtectedMain({ githubRun = createProductionGithubCommandRunner() } = {}) {
  const value = readStageBProtectedMainCheckoutFromGitHub({ cwd: repositoryRoot, githubRun });
  return value.toolingSha || value.headSha;
}

export function classifySignerLedgerPolicyReadback(response) {
  assert.equal(typeof response?.Policy, "string", "Production state bucket policy readback is incomplete");
  return classifySignerLedgerBucketPolicy(JSON.parse(response.Policy));
}

export async function reconcileSignerLedgerAbsence({ sourceSha, authorization, s3, currentSource, now = Date.now } = {}) {
  assert.equal(typeof s3, "function"); assert.equal(typeof currentSource, "function");
  assert.equal(await currentSource(), sourceSha, "Protected main changed before signer ledger reconciliation");
  assert.equal(authorization?.sourceSha, sourceSha);
  assertSignerLedgerAbsenceAuthorization(authorization, { sourceSha, now: new Date(now()) });
  const read = () => s3("GetBucketPolicy", { Bucket: signerLedgerAbsence.bucket, ExpectedBucketOwner: expectedOwner });
  const before = classifySignerLedgerPolicyReadback(await read());
  if (before === "EXACT_SUCCESSOR") return Object.freeze({ state: "ALREADY_CONVERGED", putBucketPolicyCount: 0, policySha256: policySha256(signerLedgerBucketPolicySuccessor()) });
  assert.equal(before, "EXACT_PREDECESSOR");
  assert.equal(await currentSource(), sourceSha, "Protected main changed before signer ledger policy write");
  assertSignerLedgerAbsenceAuthorization(authorization, { sourceSha, now: new Date(now()) });
  const policy = JSON.stringify(signerLedgerBucketPolicySuccessor());
  let writeError;
  try { await s3("PutBucketPolicy", { Bucket: signerLedgerAbsence.bucket, ExpectedBucketOwner: expectedOwner, Policy: policy }); }
  catch (error) { writeError = error; }
  const after = classifySignerLedgerPolicyReadback(await read());
  if (after !== "EXACT_SUCCESSOR") throw new Error("Signer ledger bucket-policy write did not converge; do not retry without reconciliation", { cause: writeError });
  return Object.freeze({ state: "CONVERGED", putBucketPolicyCount: 1, policySha256: policySha256(signerLedgerBucketPolicySuccessor()), writeResponseAmbiguous: Boolean(writeError) });
}

function readOnlyRootPolicy() {
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-root", region: "eu-west-2" });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json"]));
  assert.deepEqual({ Account: caller.Account, Arn: caller.Arn }, { Account: expectedOwner, Arn: `arn:aws:iam::${expectedOwner}:root` });
  return classifySignerLedgerPolicyReadback(JSON.parse(run(["s3api", "get-bucket-policy", "--bucket", signerLedgerAbsence.bucket, "--expected-bucket-owner", expectedOwner, "--output", "json"])));
}

function rootS3(credentials) {
  const { S3Client, GetBucketPolicyCommand, PutBucketPolicyCommand } = sdk("@aws-sdk/client-s3");
  const client = new S3Client({ region: "eu-west-2", credentials, maxAttempts: 1 });
  return { send: (operation, input) => { const Command = { GetBucketPolicy: GetBucketPolicyCommand, PutBucketPolicy: PutBucketPolicyCommand }[operation]; assert(Command); return client.send(new Command(input)); }, close: () => client.destroy() };
}

export async function runSignerLedgerAbsenceCli(args = process.argv.slice(2), { source = sourceShaFromProtectedMain, readPolicy = readOnlyRootPolicy, resolve = resolveSignerLedgerAbsenceAuthorization, root = createBrokerPolicySuccessorRootMfaSession, transport = rootS3 } = {}) {
  const mode = required(args, 0);
  if (!["prepare", "execute"].includes(mode) || args.length !== (mode === "prepare" ? 1 : 3)) throw new Error("Usage: prepare | execute AUTHORIZATION_RUN_ID RUN_ATTEMPT");
  const sourceSha = source();
  const live = readPolicy();
  if (mode === "prepare") return { sourceSha, live, bucket: signerLedgerAbsence.bucket, principal: signerLedgerAbsence.principal,
    prefix: signerLedgerAbsence.key, desiredPolicySha256: policySha256(signerLedgerBucketPolicySuccessor()) };
  const authorization = resolve({ workflowRunId: required(args, 1), workflowRunAttempt: required(args, 2), sourceSha });
  if (live === "EXACT_SUCCESSOR") return { state: "ALREADY_CONVERGED", putBucketPolicyCount: 0 };
  let session, client;
  try {
    session = await root();
    client = transport(session.credentials);
    return await reconcileSignerLedgerAbsence({ sourceSha, authorization, s3: client.send, currentSource: source });
  } finally { client?.close(); session?.close(); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runSignerLedgerAbsenceCli().then(value => process.stdout.write(`${JSON.stringify(value)}\n`)).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
